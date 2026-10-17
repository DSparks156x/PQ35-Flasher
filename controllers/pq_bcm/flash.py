"""PQ BCM (8P0907063E/0575) resident-loader flash support for the PQ engine.

STATUS: wired from a full static trace of the resident CAN bootloader contained
in the page-FF boot image (global 0x7FC000..0x7FFFFF). See
`CentElecRE/artifacts/bcm_pageff_loader_trace.md` for the disassembly evidence.
It has NOT yet been exercised on hardware -- running a live flash remains the
sole hardware owner's decision.

Protocol recovered from the loader (all high-confidence unless flagged):
  * Transport: VWTP2.0, logical module 0x20 (same as the application).
  * Entry: the application's `10 85` writes an AA55 EEPROM marker and resets;
    the resident loader's reset path sees AA55 and stays resident.
  * Programming security: `27 01` request seed / `27 02` send key (NOT the
    application's `27 03/04 +A41D`). key = T(T(seed)) with the 32-bit Galois
    step below (mask 0x1D825439). A wrong key only yields NRC 0x35 -- it stops
    the flow before any erase, so it is non-destructive to get wrong.
  * `34` RequestDownload (7-byte form `34 AAA 00 SSS`), range-validated against
    the loader's own region table (NRC 0x42 out of range).
  * `31 C4` erase (payload start+end), `36` TransferData (8-byte phrase
    programming), `37` RequestTransferExit.
  * `31 C5` checksum = 16-bit additive byte sum over the range (NOT a CRC),
    big-endian; mismatch -> NRC 0x22.
  * Flashable regions: see BCM_FLASH_REGIONS. The boot block 0x7FC000..0x7FFFFF
    is deliberately NOT flashable (the loader protects its own recovery path);
    this module refuses it explicitly as well.

The BCM's only anti-brick protection is that boot-block self-protection. A wrong
image checksum or a bad CRC32 descriptor table can still leave the application
failing its own runtime integrity check (bootloop); keep every changed byte CRC
consistent (see artifacts/comma_headlight_integration_plan.md).
"""
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

from ...engine import PQFlashProfile, PQFlasher, SecurityAccess
from ...vag_protocols.kwp import KWPClient
from ...vag_protocols.tp2 import TP2Transport

from . import codec


BCM_MODULE_ADDR = 0x20
SESSION_APP_DIAGNOSTIC = 0x89       # application session held before the handoff
SESSION_PROGRAMMING = 0x85          # application 10 85 -> AA55 marker + reset
COMMIT_SERVICES = (0x82,)

# Loader programming security: 27 01 (request seed) / 27 02 (send key).
PROGRAMMING_SEED_SUBFN = 0x01
PROGRAMMING_KEY_SUBFN = 0x02
# Galois seed->key transform traced from the loader (FUN_00F7AB): two rounds.
PROGRAMMING_KEY_MASK = 0x1D825439
PROGRAMMING_KEY_ROUNDS = 2

# Flashable regions permitted by the loader's own table at page-FF 0xC219
# (global addresses, inclusive). The boot block 0x7FC000..0x7FFFFF is absent on
# purpose -- the loader will not erase/program its own recovery code.
PFLASH_REGION = (0x780000, 0x7FBFFF)        # 31 x 16 KiB application sectors
BCM_FLASH_REGIONS: Tuple[Tuple[int, int], ...] = (
    (0x003800, 0x003FFB),                   # D-Flash/EEPROM driver staging
    PFLASH_REGION,
    (0x13F070, 0x13FFFB),                   # EEPROM region
)
BOOT_BLOCK = (0x7FC000, 0x7FFFFF)           # resident loader + vectors (protected)
PFLASH_SECTOR = 0x4000                      # 16 KiB erase/program sector
FLASH_PHRASE = 0x08                         # loader programs 8-byte phrases

# Flasher image contract: a full-span 1 MiB image, byte 0 = global 0x700000,
# running through 0x7FFFFF. The 0x700000..0x77FFFF head and the 0x7A0000..0x7BFFFF
# gap are all-0xFF, the application starts at 0x780000, and the boot-block tail
# 0x7FC000..0x7FFFFF is padding we never touch. Only the 31 P-Flash sectors below
# the boot block are ever programmed. (The old 512 KiB byte-0 = 0x780000 layout
# is retired; such images must be re-exported in this 1 MiB 0x700000 layout.)
BCM_IMAGE_BASE = 0x700000
BCM_IMAGE_SIZE = 0x100000                   # 0x700000..0x7FFFFF inclusive

# RAM-driver download stage (loader programming session download #1). Before any
# application P-Flash page the loader requires one RAM-driver download into the
# D-Flash/EEPROM staging window (region-table row 0, 0x003800..0x003FFB). The
# driver is a SEPARATE .bin the operator supplies; its bytes are never embedded
# here and never spliced into the application image. These constants pin the one
# known-good driver so a supplied file is verified against them and a mismatch is
# refused. The transfer is a RAM byte-copy, so neither the P-Flash 16 KiB sector
# rule nor the 8-byte phrase rule applies (918 is not a multiple of 8). The
# erase/checksum payloads use the ACTUAL data end 0x3B95, not the row capacity.
DRIVER_LOAD_ADDR = 0x003800
DRIVER_LEN = 918                            # 0x396, exact, NO padding
DRIVER_END_INCLUSIVE = 0x003B95             # 0x3800 + 918 - 1
DRIVER_SHA256 = "2DABA2AA4A2C9A84245137AFAB93A67576C65FE66404CC9B6D3B7AC8C86439AB"
DRIVER_SUM16 = 0x5B2D                       # byte sum mod 65536, big-endian
DRIVER_FLASH_REGION = (0x003800, 0x003FFB)  # loader row 0 (range check, not exact)

# First-application-erase metadata: exactly six bytes appended to the 31 C4 of
# download #2 only (the first application page after the RAM driver). See
# make_bcm_flash_profile.erase_payload and bcm_first_erase_metadata_findings.md.
FIRST_ERASE_METADATA_LEN = 6

# DID 22 F184 (ISO 14229 applicationSoftwareFingerprint) returns the six NVM
# bytes the loader stored on the last first-application erase. Re-sending the
# module's own current fingerprint keeps the stored identity unchanged and avoids
# inventing a format.
APPLICATION_FINGERPRINT_DID = b"\xF1\x84"


class BCMFlashNotConfigured(RuntimeError):
    """A live BCM flash was requested without the data needed to run it safely."""


def bcm_loader_key(seed: bytes) -> Optional[bytes]:
    """Derive the loader programming key from a 4-byte seed (big-endian).

    Traced from FUN_00F7AB: key = T(T(seed)) where each round T left-shifts the
    32-bit value and, when a 1 falls out of bit 31, sets bit 0 and XORs the mask.
    A zero seed conventionally means the level is already unlocked.
    """
    if len(seed) != 4:
        raise RuntimeError(f"Expected four-byte loader seed, got {len(seed)}")
    if not any(seed):
        return None
    value = int.from_bytes(seed, "big")
    for _ in range(PROGRAMMING_KEY_ROUNDS):
        carry = value & 0x80000000
        value = (value << 1) & 0xFFFFFFFF
        if carry:
            value = (value | 1) ^ PROGRAMMING_KEY_MASK
    return value.to_bytes(4, "big")


def loader_security() -> SecurityAccess:
    return SecurityAccess(PROGRAMMING_SEED_SUBFN, PROGRAMMING_KEY_SUBFN,
                          bcm_loader_key, "pq-bcm-programming")


@dataclass(frozen=True)
class LoaderConfig:
    """Resident-loader programming parameters.

    Defaults are the values traced from the page-FF boot image; override only
    from a verified bench capture. `loader_identity_marker` is the one field with
    no fixed default -- an empty string accepts any BCM part-number reply on the
    programming channel (the security step is the real gate), while a bench
    capture can set a stricter substring.
    """
    flash_start: int = PFLASH_REGION[0]
    flash_end: int = PFLASH_REGION[1]        # inclusive
    image_size: int = PFLASH_REGION[1] - PFLASH_REGION[0] + 1
    loader_identity_marker: str = ""
    erase_routine: int = 0xC4
    checksum_routine: int = 0xC5
    erase_response: bytes = b"\x71\xC4\x01"
    checksum_response: bytes = b"\x71\xC5"
    chunk_size: int = 0x40                    # phrase-aligned; <= loader block limit
    regions: Tuple[Tuple[int, int], ...] = BCM_FLASH_REGIONS

    @classmethod
    def from_file(cls, path) -> "LoaderConfig":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))

        def num(key, default):
            if key not in raw:
                return default
            value = raw[key]
            return int(value, 0) if isinstance(value, str) else value

        def bts(key, default):
            if key not in raw:
                return default
            value = raw[key]
            return bytes.fromhex(value) if isinstance(value, str) else bytes(value)

        return cls(
            flash_start=num("flash_start", PFLASH_REGION[0]),
            flash_end=num("flash_end", PFLASH_REGION[1]),
            image_size=num("image_size", PFLASH_REGION[1] - PFLASH_REGION[0] + 1),
            loader_identity_marker=str(raw.get("loader_identity_marker", "")),
            erase_routine=num("erase_routine", 0xC4),
            checksum_routine=num("checksum_routine", 0xC5),
            erase_response=bts("erase_response", b"\x71\xC4\x01"),
            checksum_response=bts("checksum_response", b"\x71\xC5"),
            chunk_size=num("chunk_size", 0x40),
        )


def default_loader_config() -> LoaderConfig:
    """The evidence-grounded loader profile; no bench capture required to run."""
    return LoaderConfig()


# Items still worth confirming on the bench (all non-destructive, before erase):
REQUIRED_CAPTURE = [
    "27 02 key acceptance (confirm 67 02 ... with the traced Galois key)",
    "loader 10 <session> byte and a stable identity DID for the loader marker",
]


def _a3(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def sum16(data: bytes) -> int:
    """Loader 31 C5 transport checksum: 16-bit additive byte sum (FUN_00DCA9)."""
    return sum(data) & 0xFFFF


def _region_for(start: int, end: int, regions) -> Tuple[int, int]:
    for lo, hi in regions:
        if lo <= start and end <= hi:
            return (lo, hi)
    raise ValueError(
        f"Range 0x{start:06X}..0x{end:06X} is not inside any loader-permitted "
        f"region {['0x%06X..0x%06X' % r for r in regions]}")


def require_full_span(data: bytes, what: str = "image") -> bytes:
    """Reject anything but a whole 1 MiB, 0x700000-based BCM image.

    Sector planning and change detection both map linearly from BCM_IMAGE_BASE,
    so a mis-sized buffer would silently read the wrong bytes. Refuse early with
    a message that points at the retired 512 KiB layout.
    """
    if len(data) != BCM_IMAGE_SIZE:
        raise ValueError(
            f"BCM {what} is {len(data)} bytes; it must be exactly "
            f"{BCM_IMAGE_SIZE} bytes (1 MiB, global 0x{BCM_IMAGE_BASE:06X}.."
            f"0x{BCM_IMAGE_BASE + BCM_IMAGE_SIZE - 1:06X}). An old 512 KiB "
            f"0x780000-based image must be re-exported in the 1 MiB "
            f"0x700000-based layout.")
    return data


def prepare_image(source, start_addr, end_addr, file_off=None, simulator_mode=False,
                  regions=BCM_FLASH_REGIONS):
    """Load a CPU-linear image slice and compute the loader checksum.

    Enforces the loader's own safety rules offline, before any hardware access:
      * the range must lie inside one permitted region and never touch the
        boot block 0x7FC000..0x7FFFFF,
      * P-Flash ranges must be whole 16 KiB sectors (erase granularity),
      * the length must be a whole number of 8-byte program phrases.
    The 16-bit additive checksum the loader's 31 C5 expects is computed here and
    placed in metadata["checksum"]. This function never patches firmware.
    """
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else bytes(source)
    if start_addr is None or end_addr is None:
        raise BCMFlashNotConfigured("BCM flash requires explicit --start/--end (loader range)")
    if end_addr < start_addr:
        raise ValueError("BCM flash range end precedes start")
    # Refuse the boot block explicitly, independent of the region list.
    if not (end_addr < BOOT_BLOCK[0] or start_addr > BOOT_BLOCK[1]):
        raise ValueError(
            "Refusing to flash the boot block 0x7FC000..0x7FFFFF: the resident "
            "loader lives there and will not program it; this is the only "
            "recovery path.")
    region = _region_for(start_addr, end_addr, regions)
    size = end_addr - start_addr + 1
    if region == PFLASH_REGION:
        if start_addr % PFLASH_SECTOR or (end_addr + 1) % PFLASH_SECTOR:
            raise ValueError(
                f"P-Flash range 0x{start_addr:06X}..0x{end_addr:06X} is not aligned "
                f"to whole 16 KiB sectors (erase granularity)")
    if size % FLASH_PHRASE:
        raise ValueError(f"Flash length {size} is not a multiple of the 8-byte phrase")
    base = start_addr if file_off is None else file_off
    payload = data[start_addr - base:end_addr - base + 1] if file_off is not None else data
    if len(payload) != size:
        raise ValueError(f"Image slice is {len(payload)} bytes, expected {size}")
    return {"region": payload,
            "metadata": {"start_addr": start_addr, "end_addr": end_addr, "size": size,
                         "controller": "pq-bcm", "flash_region": list(region),
                         "checksum": sum16(payload), "checksum_kind": "sum16"}}


def pflash_sector_starts() -> Tuple[int, ...]:
    """The 31 erasable 16 KiB application P-Flash sectors (0x780000..0x7FBFFF)."""
    lo, hi = PFLASH_REGION
    return tuple(range(lo, hi, PFLASH_SECTOR))


def sector_index(address: int) -> int:
    """Index (0-based) of the P-Flash sector containing `address`."""
    lo, hi = PFLASH_REGION
    if not (lo <= address <= hi):
        raise ValueError(f"0x{address:06X} is not in the application P-Flash window")
    return (address - lo) // PFLASH_SECTOR


def changed_sectors(image: bytes, reference: bytes, *, base: int = BCM_IMAGE_BASE) -> Tuple[int, ...]:
    """P-Flash sector starts whose bytes differ between image and reference.

    Both buffers map linearly from `base` (default BCM_IMAGE_BASE 0x700000, the
    1 MiB full-span layout) and must each be a whole BCM_IMAGE_SIZE image. Only
    the 31 application sectors are compared; this is how "flash only what the
    patch changed" is planned.
    """
    require_full_span(image, "image")
    require_full_span(reference, "reference image")
    starts = []
    for start in pflash_sector_starts():
        off = start - base
        end = off + PFLASH_SECTOR
        if end > len(image) or end > len(reference):
            continue
        if image[off:end] != reference[off:end]:
            starts.append(start)
    return tuple(starts)


def plan_sectors(source, sector_starts, *, base: int = BCM_IMAGE_BASE,
                 regions=BCM_FLASH_REGIONS):
    """Build one flash segment per selected 16 KiB P-Flash sector.

    `source` maps linearly from `base` (default BCM_IMAGE_BASE 0x700000, the
    1 MiB full-span layout) and must be a whole BCM_IMAGE_SIZE image. Each sector
    becomes its OWN download/erase/transfer/checksum cycle; the loader's
    RequestDownload validator (FUN_00E1B9/E0BE) requires every download to exactly
    match one 16 KiB region-table entry, so contiguous sectors are NOT coalesced
    -- a multi-sector download is rejected with NRC 0x42. The segments still flash
    in a single programming session (34 has no state gate, so cycles repeat).
    Every segment is validated and checksummed by prepare_image.
    """
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else bytes(source)
    require_full_span(data, "image")
    if not sector_starts:
        raise ValueError("No sectors selected to flash")
    lo, hi = PFLASH_REGION
    segments = []
    for start in sorted(set(sector_starts)):
        if start % PFLASH_SECTOR or not (lo <= start <= hi):
            raise ValueError(f"0x{start:06X} is not a valid 16 KiB P-Flash sector start")
        if (start - base) < 0 or (start - base + PFLASH_SECTOR) > len(data):
            raise ValueError(
                f"Sector 0x{start:06X} is not fully present in the image "
                f"(base 0x{base:06X}, {len(data)} bytes)")
        segments.append(prepare_image(data, start, start + PFLASH_SECTOR - 1,
                                      file_off=base, regions=regions))
    return segments


def prepare_driver(source) -> dict:
    """Load and verify the RAM-driver .bin, returning a prepared segment dict.

    The driver is download #1 of every programming session. This is a RAM-stage
    preparation path that deliberately BYPASSES the P-Flash 16 KiB sector rule and
    the 8-byte phrase rule enforced by prepare_image (918 is not a multiple of 8,
    and 0x3800 is not a 16 KiB boundary) -- the loader copies these bytes into RAM.
    The supplied file is verified byte-for-byte against the known-good driver
    (length + SHA-256); a mismatch is refused so a wrong or padded driver can never
    be staged. The returned metadata is shaped like prepare_image's output; the
    erase/checksum payloads use the data end 0x3B95, not the row-0 capacity 0x3FFB.
    """
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else bytes(source)
    if len(data) != DRIVER_LEN:
        raise BCMFlashNotConfigured(
            f"RAM driver is {len(data)} bytes; the known-good BCM driver is exactly "
            f"{DRIVER_LEN} bytes (0x{DRIVER_LEN:X}, no padding to 0x3FFB or a 16 KiB page)")
    digest = hashlib.sha256(data).hexdigest().upper()
    if digest != DRIVER_SHA256:
        raise BCMFlashNotConfigured(
            f"RAM driver SHA-256 {digest} does not match the known-good BCM driver "
            f"{DRIVER_SHA256}; refusing to stage an unverified RAM driver")
    checksum = sum16(data)
    if checksum != DRIVER_SUM16:  # unreachable once the hash matches; defensive only
        raise BCMFlashNotConfigured(
            f"RAM driver sum16 0x{checksum:04X} does not match 0x{DRIVER_SUM16:04X}")
    return {"region": data,
            "metadata": {"start_addr": DRIVER_LOAD_ADDR, "end_addr": DRIVER_END_INCLUSIVE,
                         "size": DRIVER_LEN, "controller": "pq-bcm",
                         "flash_region": list(DRIVER_FLASH_REGION),
                         "checksum": checksum, "checksum_kind": "sum16",
                         "stage": "ram_driver"}}


def validate_first_erase_metadata(value) -> bytes:
    """Return exactly six non-zero metadata bytes, or raise.

    The loader's first-application-erase branch (26B2 == 2) reads six bytes after
    start/end and rejects the field (NRC 0x22) only when all six are zero. We also
    refuse a missing value or a wrong length: the firmware reads six real bytes, so
    guessing or padding is not a valid implementation.
    """
    if value is None:
        raise BCMFlashNotConfigured(
            "First-application-erase metadata is required but was not available "
            "(read 22 F184 before the handoff, or pass an explicit 6-byte override)")
    value = bytes(value)
    if len(value) != FIRST_ERASE_METADATA_LEN:
        raise BCMFlashNotConfigured(
            f"First-application-erase metadata must be exactly {FIRST_ERASE_METADATA_LEN} "
            f"bytes, got {len(value)}")
    if not any(value):
        raise BCMFlashNotConfigured(
            "First-application-erase metadata is all-zero; the loader rejects this "
            "with NRC 0x22. Refusing before any erase")
    return value


def read_application_fingerprint(kwp) -> Optional[bytes]:
    """Read DID 22 F184 on the application channel; return 6 bytes or None.

    Non-destructive. Returns None on any negative/short/malformed reply so the
    caller can decide whether to refuse (the authoritative refusal happens in
    validate_first_erase_metadata)."""
    try:
        response = bytes(kwp.request(b"\x22" + APPLICATION_FINGERPRINT_DID))
    except Exception:
        return None
    if (len(response) == 3 + FIRST_ERASE_METADATA_LEN
            and response[:1] == b"\x62" and response[1:3] == APPLICATION_FINGERPRINT_DID):
        return response[3:]
    return None


def build_segment_plan(driver_segment: dict, application_segments) -> list:
    """Assemble the full programming-session segment list: driver first, apps after.

    The RAM driver is always download #1; the application pages are #2, #3, ...
    The first application page (download #2) is marked so the BCM erase_payload
    closure appends the six-byte first-erase metadata to its 31 C4 only. A
    flash-first application list (no driver) is not a valid plan.
    """
    if not application_segments:
        raise ValueError("No application segments to flash after the RAM driver")
    if driver_segment.get("metadata", {}).get("stage") != "ram_driver":
        raise ValueError("build_segment_plan requires a prepared RAM-driver segment first")
    apps = []
    for index, segment in enumerate(application_segments):
        prepared = dict(segment)
        metadata = dict(segment["metadata"])
        if index == 0:
            metadata["first_app_erase"] = True   # download #2 carries metadata
        prepared["metadata"] = metadata
        apps.append(prepared)
    return [driver_segment] + apps


def make_bcm_flash_profile(loader: LoaderConfig, *, kwp_factory, device_factory,
                           transport_factory, identify, first_erase=None):
    # Shared mutable holder for the six-byte first-application-erase metadata,
    # kept inside the pq_bcm layer (never added to the controller-neutral engine).
    # "override" is an explicit operator value; "captured" is filled by the BCM
    # identify step from 22 F184; erase_payload reads whichever is available.
    holder = first_erase if first_erase is not None else {}

    def validate_controller(info, metadata):
        part = str(info.get("software_part_number", info.get("part_number", ""))).upper()
        if not part.startswith("8P0907063E"):
            raise RuntimeError(f"Identification {part or '<empty>'} is not the PQ BCM 8P0907063E")

    def verify_programming_channel(tp):
        # Non-destructive confirmation that the programming channel is live and
        # still the BCM. Do NOT probe 27 01 here: a seed request advances the
        # loader security state machine and would break the real unlock. The
        # security step (loader_security) is the authoritative in-loader gate --
        # 27 01/02 succeed only in the resident loader (the app uses 27 03/04).
        kwp = kwp_factory(tp, lambda *_: None, False)
        try:
            text = bytes(kwp.request(codec.part_number_request())).decode("latin-1", "ignore")
        except Exception as exc:
            raise RuntimeError(f"BCM programming channel did not answer identity: {exc}")
        if "8P0907063E" not in text.upper().replace(" ", ""):
            raise RuntimeError(f"Programming channel identity is not the BCM: {text!r}")
        if loader.loader_identity_marker and loader.loader_identity_marker not in text:
            raise RuntimeError(
                "BCM did not present the expected resident-loader marker "
                f"{loader.loader_identity_marker!r}; got {text!r}")

    def erase_payload(start, end, metadata):
        # Loader 31 C4: start+end, each 24-bit (FUN_00E8AE), must equal the 34 range.
        payload = _a3(start) + _a3(end)
        # ONLY the first application page (download #2, 26B2 == 2) carries six extra
        # metadata bytes after start/end. The RAM driver (download #1) and later
        # application pages keep the plain start+end form. The six bytes are the
        # module's own re-sent fingerprint (or an explicit operator override); an
        # all-zero/missing/short value is refused here before any erase.
        if metadata.get("first_app_erase"):
            meta = (metadata.get("first_erase_metadata")
                    or holder.get("override")
                    or holder.get("captured"))
            payload += validate_first_erase_metadata(meta)
        return payload

    def checksum_payload(start, end, metadata):
        if "checksum" not in metadata:
            raise BCMFlashNotConfigured("Image checksum not computed in metadata")
        # Loader 31 C5: start+end+16-bit additive byte sum, big-endian (FUN_00E994).
        return _a3(start) + _a3(end) + struct.pack(">H", metadata["checksum"])

    def validate_fresh_application(info):
        if not str(info.get("part_number", "")).upper().startswith("8P0907063E"):
            raise RuntimeError("Fresh BCM application boot not confirmed after flash")

    return PQFlashProfile(
        name="pq-bcm",
        module=BCM_MODULE_ADDR,
        kwp_factory=kwp_factory,
        prepare_image=lambda *a, **k: prepare_image(*a, regions=loader.regions, **k),
        device_factory=device_factory,
        transport_factory=transport_factory,
        identify=identify,
        validate_controller=validate_controller,
        is_application_channel=lambda tp: True,
        initial_session=SESSION_APP_DIAGNOSTIC,
        programming_session=SESSION_PROGRAMMING,
        pre_programming_security=None,
        programming_security=loader_security(),
        verify_programming_channel=verify_programming_channel,
        chunk_size=loader.chunk_size,
        erase_routine=loader.erase_routine,
        checksum_routine=loader.checksum_routine,
        erase_payload=erase_payload,
        checksum_payload=checksum_payload,
        validate_fresh_application=validate_fresh_application,
        commit_services=COMMIT_SERVICES,
        programming_reconnect_delay=1.0,
    )


class PQBCMFlasher(PQFlasher):
    def __init__(self, loader: Optional[LoaderConfig] = None, *, channel=None,
                 module=BCM_MODULE_ADDR, device=None, device_factory=None,
                 progress_cb=None, log_cb=None, debug=False, interface="socketcan",
                 first_erase_override=None, first_erase_required=True):
        from ...socketcan_device import SocketCANDevice
        loader = loader or default_loader_config()
        # Holder shared between the identify step (which captures 22 F184) and the
        # profile's erase_payload closure (which appends the six bytes to the first
        # application 31 C4). "require" makes a live flash refuse BEFORE any erase
        # when neither an override nor a valid captured fingerprint is available.
        holder = {"override": (validate_first_erase_metadata(first_erase_override)
                               if first_erase_override is not None else None),
                  "captured": None, "require": bool(first_erase_required)}
        self._first_erase = holder

        def bcm_identify(kwp, tp):
            part = codec.parse_part_number_response(kwp.request(codec.part_number_request()))
            info = {"part_number": part, "software_part_number": part, "connected": True}
            fingerprint = read_application_fingerprint(kwp)
            if fingerprint is not None:
                holder["captured"] = fingerprint
                info["application_fingerprint"] = fingerprint.hex().upper()
            # Pre-flight refusal before any erase (including the RAM driver): if a
            # first-application page will be flashed and no override was supplied,
            # the 22 F184 read must have produced a valid six non-zero bytes.
            if holder.get("require") and holder.get("override") is None:
                validate_first_erase_metadata(holder.get("captured"))
            return info

        profile = make_bcm_flash_profile(
            loader,
            kwp_factory=lambda tp, log, dbg: KWPClient(tp, log_fn=log, debug=dbg),
            device_factory=lambda ch: SocketCANDevice(channel=ch, interface=interface),
            transport_factory=lambda *a, **k: TP2Transport(*a, **k),
            identify=bcm_identify,
            first_erase=holder,
        )
        super().__init__(profile, channel=channel, module=module, device=device,
                         device_factory=device_factory, progress_cb=progress_cb,
                         log_cb=log_cb, debug=debug)
