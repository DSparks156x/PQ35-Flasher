"""PQ EPS image validation, transfer preparation and offline patching.

The flash path deliberately does not patch firmware. It accepts a complete
CPU-linear rack image, checks the dataset CRCs, selects an inclusive flash
range, and calculates the additive checksum consumed by loader routine 0xC5.
Both the stock ``Ende`` trailer and an erased ``ff ff ff ff`` trailer are
valid inputs. The only bytes it ever changes are dataset CRC words, and only
when the caller asks for correct_checksums.

Tune patches are exact-preimage manifests applied offline with
``python -m flasher.controllers.pq_eps.patches``; the flasher then sends the
patched file like any other image.
"""
import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


IMAGE_SIZE = 0x60000
FLASH_START = 0x0A000
DATASET_START = 0x5E000
DATASET_END = 0x5EFFF
DATASET_SIZE = DATASET_END - DATASET_START + 1
DEFAULT_START = 0x5D000
DEFAULT_END = 0x5DFFF
END_MARKER_OFFSET = 0x5FFFC

# The resident loader in the user's full TT 3001 rack dump requires exact
# partition bounds for CPU-flash RequestDownload (0x9A10, flag bit 0). This
# fingerprint limits the extra check to images retaining that loader bank;
# SGO-derived application images do not identify the target's resident loader.
TT3001_LOADER_SHA256 = "432B7F6C46DCED5A19A63D22C26E6B8987184996033404B586DB54D9714E1D93"
TT3001_PARTITIONS = frozenset({
    (0x0A000, 0x5FFFF),
    (0x0A000, 0x5BFFF),
    (0x0A000, 0x5DFFF),
    (0x5F000, 0x5FFFF),
    (0x5C000, 0x5DFFF),
    (0x5C000, 0x5CFFF),
    (0x5D000, 0x5DFFF),
    (0x5E000, 0x5EFFF),
    (0x57000, 0x5FFFF),
})


# Dataset CRCs are CRC-16/XMODEM (poly 0x1021, init 0), stored big-endian.
# Layouts come from the original pq-flasher patcher and were re-checked against
# 41 stock and tuned rack images (2301..3501). Each layout is recognised by the
# 0x12345678 (little-endian) marker that sits just before its CRC words.
# The odd 0x5CFFF boundary is real: that byte counts toward the 0x5D CRC. It
# is 0xFF in every image seen, so a 0x5D-only flash may still correct that CRC
# as long as the byte is still 0xFF.
CRC_MARKER = bytes.fromhex("78563412")
ERASED_GAP = 0x5CFFF
# (name, CRC word address, data start, data end exclusive)
GEN3_CRCS = (
    ("0x5C dataset", 0x5DFFC, 0x5C000, 0x5CFFF),
    ("0x5D configuration", 0x5DFFE, 0x5CFFF, 0x5DFFC),
    ("0x5E steer dataset", 0x5EFFE, 0x5E000, 0x5EFFE),
)
GEN2_CRCS = (
    ("0x5E dataset", 0x5EFFC, 0x5E000, 0x5EFFC),
)
# A standalone 4 KiB 0x5E dataset carries its CRC in its last word.
DATASET_CRCS = (
    ("0x5E steer dataset", DATASET_SIZE - 2, 0, DATASET_SIZE - 2),
)


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def checksum_layout(data: bytes):
    """Return (layout name, CRC sites) for a full image or a 4 KiB dataset."""
    if len(data) == DATASET_SIZE:
        if data[-8:-4] == CRC_MARKER:
            raise ValueError("This 4 KiB file looks like a 0x5D configuration block, not a "
                             "0x5E steer dataset; flash it from a full 384 KiB image")
        return "0x5E dataset file", DATASET_CRCS
    if data[0x5DFF8:0x5DFFC] == CRC_MARKER:
        return "gen3 (firmware 3000+)", GEN3_CRCS
    if data[0x5EFF8:0x5EFFC] == CRC_MARKER:
        return "gen2 (firmware below 3000)", GEN2_CRCS
    raise ValueError("No dataset CRC marker (78 56 34 12) at 0x5DFF8 or 0x5EFF8; "
                     "not a recognised PQ EPS image")


def check_checksums(data: bytes, base: int = 0, start: int = None, end: int = None,
                    correct: bool = False):
    """Verify the dataset CRCs and optionally rewrite wrong ones.

    ``base`` is the CPU address of data[0]. A wrong CRC is only rewritten when
    its word and all of the data it covers lie inside the inclusive start..end
    flash range. Otherwise the rack would end up with a CRC that does not match
    the bytes it actually holds. Returns (data, rows).
    """
    layout, sites = checksum_layout(data)
    out = bytearray(data)
    rows, errors = [], []
    for name, word, low, high in sites:
        stored = int.from_bytes(out[word:word + 2], "big")
        computed = crc16_xmodem(out[low:high])
        row = {"name": name, "address": base + word, "stored": stored,
               "computed": computed, "valid": stored == computed, "corrected": False}
        if stored != computed:
            detail = (f"{name} CRC at 0x{base + word:05X} stored 0x{stored:04X} "
                      f"computed 0x{computed:04X}")
            if not correct:
                errors.append(detail)
            elif start is not None and not _covered(out, base, low, high, word, start, end):
                errors.append(detail + " (its data or CRC word is not all in the flash "
                              f"range 0x{start:05X}..0x{end:05X}, cannot correct)")
            else:
                out[word:word + 2] = computed.to_bytes(2, "big")
                row["corrected"] = True
        rows.append(row)
    if errors:
        hint = "" if correct else " (use --correct-checksum if these edits are intentional)"
        raise ValueError(f"EPS {layout} dataset CRC mismatch: " + "; ".join(errors) + hint)
    return bytes(out), rows


def _covered(data, base, low, high, word, start, end):
    if base + low == ERASED_GAP and data[low] == 0xFF:
        low += 1
    return start <= base + low and base + max(high - 1, word + 1) <= end


def _changes(before: bytes, after: bytes, base: int):
    return [{"address": base + i, "before": before[i:i + 2].hex(), "after": after[i:i + 2].hex()}
            for i in range(0, len(before), 2) if before[i:i + 2] != after[i:i + 2]]


def _load(source) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    return Path(source).read_bytes()


def validate_image(data: bytes) -> None:
    if len(data) != IMAGE_SIZE:
        raise ValueError(
            f"Expected exactly 384 KiB ({IMAGE_SIZE} bytes), got {len(data)} bytes")


def validate_selection(start: int, end: int) -> None:
    if not FLASH_START <= start <= end < IMAGE_SIZE:
        raise ValueError("PQ EPS OBD flash range must be within 0x00A000..0x05FFFF")


def prepare_image(source, start=DEFAULT_START, end=DEFAULT_END, file_off=None,
                  simulator_mode=False, correct_checksums=False) -> dict:
    """Prepare an inclusive range for the common PQ flash engine.

    The range is sent unmodified unless correct_checksums rewrites dataset CRCs.
    """
    if simulator_mode:
        raise ValueError("PQ EPS has no simulator-mode firmware patch set")
    data = _load(source)
    if len(data) == DATASET_SIZE:
        if (start, end) != (DATASET_START, DATASET_END):
            raise ValueError(
                "A 4 KiB EPS block image can only be flashed as the 0x5E steer dataset")
        if file_off not in (None, 0):
            raise ValueError("A 4 KiB EPS steer dataset starts at file offset zero")
        original = data
        data, crcs = check_checksums(original, DATASET_START, start, end, correct_checksums)
        return {
            "image": data,
            "region": data,
            "metadata": {
                "image_size": len(data),
                "image_sha256": hashlib.sha256(original).hexdigest().upper(),
                "prepared_sha256": hashlib.sha256(data).hexdigest().upper(),
                "source_kind": "4 KiB steer dataset block (0x5E)",
                "start_addr": start,
                "end_addr": end,
                "size": len(data),
                "checksum": sum(data) & 0xFFFF,
                "patches": _changes(original, data, DATASET_START),
                "dataset_crcs": crcs,
                "correct_checksums": correct_checksums,
                "end_marker": None,
                "selection_policy": "exact 0x5E steer-dataset block",
            },
        }
    if file_off is not None and file_off != start:
        raise ValueError("PQ EPS images are CPU-linear; file offset must equal start address")
    validate_image(data)
    validate_selection(start, end)
    original = data
    data, crcs = check_checksums(original, 0, start, end, correct_checksums)
    tt3001_loader = hashlib.sha256(data[:FLASH_START]).hexdigest().upper() == TT3001_LOADER_SHA256
    if tt3001_loader and (start, end) not in TT3001_PARTITIONS:
        raise ValueError(
            "TT 3001 resident loader requires exact partition bounds; "
            f"0x{start:05X}..0x{end:05X} is not in its RequestDownload table")
    region = data[start:end + 1]
    trailer = data[END_MARKER_OFFSET:END_MARKER_OFFSET + 4]
    marker = ("Ende" if trailer == b"Ende" else
              "erased" if trailer == b"\xFF" * 4 else trailer.hex())
    return {
        "image": data,
        "region": region,
        "metadata": {
            "image_size": len(data),
            "image_sha256": hashlib.sha256(original).hexdigest().upper(),
            "prepared_sha256": hashlib.sha256(data).hexdigest().upper(),
            "source_kind": "384 KiB CPU-linear EPS firmware",
            "start_addr": start,
            "end_addr": end,
            "size": len(region),
            "checksum": sum(region) & 0xFFFF,
            "patches": _changes(original, data, 0),
            "dataset_crcs": crcs,
            "correct_checksums": correct_checksums,
            "end_marker": marker,
            "known_patches": known_patches(data),
            "selection_policy": (
                "exact TT 3001 resident-loader partition" if tt3001_loader else
                "local PQ EPS range only; target loader partition unverified"),
        },
    }


class UnsupportedFirmwarePatch(ValueError):
    pass


def update_checksums(data: bytes) -> bytes:
    """Rewrite every dataset CRC word of a full image or 4 KiB dataset."""
    _, sites = checksum_layout(data)
    out = bytearray(data)
    for _, word, low, high in sites:
        out[word:word + 2] = crc16_xmodem(out[low:high]).to_bytes(2, "big")
    return bytes(out)


@dataclass(frozen=True)
class PatchSite:
    address: int
    expected: bytes
    replacement: Optional[bytes]  # None: identity check only, never written
    description: str

    def state(self, image: bytes) -> str:
        actual = image[self.address:self.address + len(self.expected)]
        if actual == self.expected:
            return "stock" if self.replacement is not None else "match"
        if self.replacement is not None and actual == self.replacement:
            return "applied"
        return "mismatch"


@dataclass(frozen=True)
class PatchManifest:
    """One patch (feature) for one firmware build, as exact preimages.

    The identity sites (replacement None) must match before anything is
    written, and every other site must hold either its stock or its patched
    bytes, so a manifest never lands on a firmware it was not made for.
    """
    feature: str
    firmware: str
    sites: tuple

    @property
    def name(self) -> str:
        return f"{self.feature} ({self.firmware})"

    def status(self, image: bytes) -> Optional[str]:
        """None if the image is another firmware, else stock/applied/partial/mismatch."""
        if len(image) != IMAGE_SIZE or any(
                site.state(image) == "mismatch" for site in self.sites if site.replacement is None):
            return None
        states = {site.state(image) for site in self.sites if site.replacement is not None}
        if "mismatch" in states:
            return "mismatch"
        return states.pop() if len(states) == 1 else "partial"

    def apply(self, image: bytes, correct_checksums: bool = False) -> bytes:
        validate_image(image)
        bad = [site for site in self.sites if site.state(image) == "mismatch"]
        if bad:
            raise UnsupportedFirmwarePatch(
                f"{self.name} does not match this image at "
                + ", ".join(f"0x{site.address:05X} ({site.description})" for site in bad)
                + "; image was not modified")
        check_checksums(image, correct=correct_checksums)
        out = bytearray(image)
        for site in self.sites:
            if site.replacement is not None:
                out[site.address:site.address + len(site.replacement)] = site.replacement
        return update_checksums(bytes(out))


# Ported from pq-flasher 02_patcher.py ("3001_v2_hca" and "3501" there).
# hca-timeout-minspeed zeroes the HCA disengage countdown (so HCA no longer
# times out) and the HCA minimum speed. The bytes live in the 0x5D
# configuration block, so the default 0x5D flash sends them with their CRCs.
# The end marker sits outside the datasets and only matters for a full flash.
# Add a feature or firmware by adding a manifest here.
HCA_TIMEOUT_MINSPEED = "hca-timeout-minspeed"
END_MARKER_SITE = PatchSite(END_MARKER_OFFSET, b"Ende", b"\xff" * 4, "End of firmware marker")
PATCH_MANIFESTS = (
    PatchManifest(HCA_TIMEOUT_MINSPEED, "8J0909144J 3001", (
        PatchSite(0x5D7A0, b"8J0909144J \x003001", None, "Software number and version"),
        PatchSite(0x5D249, b"\x64", b"\x00", "HCA disengage countdown"),
        PatchSite(0x5D2AE, b"\x14", b"\x00", "HCA minimum speed"),
        END_MARKER_SITE,
    )),
    PatchManifest(HCA_TIMEOUT_MINSPEED, "1K0909144R 3501", (
        PatchSite(0x5D828, b"1K0909144R \x003501", None, "Software number and version"),
        PatchSite(0x5D289, b"\x64", b"\x00", "HCA disengage countdown"),
        PatchSite(0x5D2FA, b"\x14", b"\x00", "HCA minimum speed"),
        END_MARKER_SITE,
    )),
)
FEATURES = tuple(dict.fromkeys(manifest.feature for manifest in PATCH_MANIFESTS))


def known_patches(image: bytes) -> dict:
    """Status of every manifest made for this image's firmware."""
    return {manifest.name: status for manifest in PATCH_MANIFESTS
            if (status := manifest.status(image)) is not None}


def require_patch_manifest(image: bytes, feature: str) -> PatchManifest:
    """The manifest of ``feature`` made for this image's firmware."""
    for manifest in PATCH_MANIFESTS:
        if manifest.feature == feature and manifest.status(image) not in (None, "mismatch"):
            return manifest
    firmwares = ", ".join(m.firmware for m in PATCH_MANIFESTS if m.feature == feature)
    raise UnsupportedFirmwarePatch(
        f"No exact PQ EPS firmware manifest supports {feature} on this image "
        f"(known firmware: {firmwares or 'none'}); image was not modified")


def report(image: bytes) -> bool:
    layout, sites = checksum_layout(image)
    print(f"layout: {layout}")
    print("CRC        stored   computed  state")
    valid = True
    for name, word, low, high in sites:
        stored = int.from_bytes(image[word:word + 2], "big")
        computed = crc16_xmodem(image[low:high])
        valid = valid and stored == computed
        state = "OK" if stored == computed else "*** MISMATCH ***"
        print(f"  0x{word:05X}  0x{stored:04X}   0x{computed:04X}    {state}  ({name})")
    patches = known_patches(image)
    for name, status in patches.items():
        print(f"patch {name}: {status}")
    if not patches:
        print("no known patch manifest for this firmware")
    return valid


def main(argv=None):
    parser = argparse.ArgumentParser(description="PQ EPS rack image checker and patcher (offline).")
    parser.add_argument("input_bin", help="384 KiB CPU-linear rack image (or 4 KiB 0x5E dataset)")
    parser.add_argument("output_bin", nargs="?", help="Output for --patch (default: INPUT_<patch>.bin)")
    parser.add_argument("--patch", choices=FEATURES,
                        help="Apply this patch (the manifest is picked from the image's firmware); "
                             "without it, only report CRCs and known patches")
    parser.add_argument("--correct-checksum", action="store_true",
                        help="Accept an input whose dataset CRCs are wrong")
    args = parser.parse_args(argv)
    image = Path(args.input_bin).read_bytes()
    if not args.patch:
        if args.output_bin or args.correct_checksum:
            parser.error("an output file and --correct-checksum need --patch")
        return 0 if report(image) else 1
    try:
        validate_image(image)
        manifest = require_patch_manifest(image, args.patch)
        patched = manifest.apply(image, args.correct_checksum)
    except ValueError as exc:
        parser.exit(1, f"Not patched: {exc}\n")
    source = Path(args.input_bin)
    output = Path(args.output_bin or source.with_name(f"{source.stem}_{args.patch}{source.suffix}"))
    output.write_bytes(patched)
    print(f"applied {manifest.name}")
    for change in _changes(image, patched, 0):
        print(f"  0x{change['address']:05X}: {change['before']} -> {change['after']}")
    print(f"wrote {output}")
    print("Flash the 0x5D block (the default), or the full firmware to also send the end marker.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
