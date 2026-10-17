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


def make_bcm_flash_profile(loader: LoaderConfig, *, kwp_factory, device_factory,
                           transport_factory, identify):
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
        return _a3(start) + _a3(end)

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
                 progress_cb=None, log_cb=None, debug=False, interface="socketcan"):
        from ...socketcan_device import SocketCANDevice
        loader = loader or default_loader_config()
        profile = make_bcm_flash_profile(
            loader,
            kwp_factory=lambda tp, log, dbg: KWPClient(tp, log_fn=log, debug=dbg),
            device_factory=lambda ch: SocketCANDevice(channel=ch, interface=interface),
            transport_factory=lambda *a, **k: TP2Transport(*a, **k),
            identify=lambda kwp, tp: {"part_number": codec.parse_part_number_response(
                kwp.request(codec.part_number_request())), "connected": True},
        )
        super().__init__(profile, channel=channel, module=module, device=device,
                         device_factory=device_factory, progress_cb=progress_cb,
                         log_cb=log_cb, debug=debug)
