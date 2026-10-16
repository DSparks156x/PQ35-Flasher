"""PQ BCM (8P0907063E/0575) flash scaffold for the shared PQ engine.

STATUS: scaffold, never exercised on hardware. It wires the parts of the BCM
programming path that are established from the application firmware onto the
controller-neutral PQFlasher lifecycle, and refuses to run a live flash until
the resident-loader parameters it cannot know are supplied.

What is established (from the application image, SGO 8P0907063E__0575):
  * TP2 logical module 0x20.
  * Application identity is service 22 (F187/F189), not 1A.
  * Service 10 85 sets an EEPROM marker and schedules a reset (observed
    response 50 85 32) -- the programming/bootloader handoff, same shape as the
    PQ EPS/Haldex "enter programming session" step.
  * Application read security is 27 03/04 with additive key +0x0000A41D.

What the RESIDENT BOOTLOADER owns and is NOT in our dump (top 16 KiB
7FC000..7FFFFF is absent from every SGO), so it must be supplied by the caller
after capturing a real BCM flash (e.g. an ODIS/VCDS session) -- see
LoaderConfig and run_flash's checklist:
  1. erase + checksum routine IDs and their payload/response formats,
  2. the programming (loader) security algorithm -- the hypothesis here is that
     it is the same elevated 27 03/04 +0xA41D as flash-read, UNCONFIRMED,
  3. the loader's identification/"in bootloader" marker,
  4. the flashable address range + image checksum policy,
  5. whether RequestDownload uses the standard or the app's 7-byte form.

The BCM has NO anti-brick net (unlike the Haldex). A wrong checksum or routine
can brick it with only BSL recovery. Running this live is the hardware owner's
decision; the scaffold will not guess.
"""
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from ...engine import PQFlashProfile, PQFlasher, SecurityAccess, add32
from ...vag_protocols.kwp import KWPClient
from ...vag_protocols.tp2 import TP2Transport

from . import codec


BCM_MODULE_ADDR = 0x20
SESSION_PROGRAMMING = 0x85
PROGRAMMING_KEY_ADD_HYPOTHESIS = 0xA41D  # same as flash-read; UNCONFIRMED for loader
COMMIT_SERVICES = (0x82,)


class BCMFlashNotConfigured(RuntimeError):
    """A live BCM flash was requested without confirmed resident-loader data."""


@dataclass(frozen=True)
class LoaderConfig:
    """The resident-loader parameters that cannot be derived from our dump.

    Capture these from a real BCM programming session before any live flash.
    Addresses/lengths are integers; payload builders take (start, end, metadata).
    """
    flash_start: int
    flash_end: int                       # inclusive
    image_size: int
    loader_identity_marker: str          # substring proving we are in the loader
    # Erase/checksum routine IDs and responses default to the common PQ/VAG
    # loader convention -- identical on both Haldex Gen4 and PQ EPS (31 C4 ->
    # 71 C4 01, 31 C5 -> 71 C5). Very likely the same on the BCM, but override
    # from a capture if it differs.
    erase_routine: int = 0xC4
    checksum_routine: int = 0xC5
    erase_response: bytes = b"\x71\xC4\x01"
    checksum_response: bytes = b"\x71\xC5"
    programming_key_add: int = PROGRAMMING_KEY_ADD_HYPOTHESIS
    chunk_size: int = 0x40               # <= app TransferData max 0x43
    # Checksum payload start+end+crc16 is shared by Haldex and EPS. Erase payload
    # DIFFERS per family (EPS: start+end; Haldex: start+end+flashdate+toolID), so
    # it is the module-specific piece to confirm.
    erase_is_start_end: bool = True
    checksum_is_start_end_crc16: bool = True

    @classmethod
    def from_file(cls, path) -> "LoaderConfig":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))

        def num(key, default=None):
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
            flash_start=num("flash_start"),
            flash_end=num("flash_end"),
            image_size=num("image_size"),
            loader_identity_marker=str(raw["loader_identity_marker"]),
            erase_routine=num("erase_routine", 0xC4),
            checksum_routine=num("checksum_routine", 0xC5),
            erase_response=bts("erase_response", b"\x71\xC4\x01"),
            checksum_response=bts("checksum_response", b"\x71\xC5"),
            programming_key_add=num("programming_key_add", PROGRAMMING_KEY_ADD_HYPOTHESIS),
            chunk_size=num("chunk_size", 0x40),
        )


# Routine IDs/responses and the checksum payload default to the shared PQ/VAG
# loader convention (same on Haldex and EPS), so they are NOT in this list. What
# is genuinely module-specific and must be captured from a real BCM flash:
REQUIRED_CAPTURE = [
    "loader_identity_marker (how the resident loader identifies itself)",
    "flash_start / flash_end / image_size (flashable range)",
    "programming security (confirm +0xA41D, or capture the loader's 27 algorithm)",
    "erase payload variant (EPS start+end vs Haldex start+end+date+toolID)",
    "image checksum policy (algorithm the loader's 31 C5 expects)",
]


def _a3(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def prepare_image(source, start_addr, end_addr, file_off=None, simulator_mode=False):
    """Load a CPU-linear image slice. Checksum policy is loader-defined.

    The caller supplies the checksum in metadata (from LoaderConfig-driven
    computation) because the BCM loader's expected checksum algorithm is not
    proven here. This function never patches firmware.
    """
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else bytes(source)
    if start_addr is None or end_addr is None:
        raise BCMFlashNotConfigured("BCM flash requires explicit --start/--end (loader range)")
    base = start_addr if file_off is None else file_off
    region = data[start_addr - base:end_addr - base + 1] if file_off is not None else data
    size = end_addr - start_addr + 1
    if len(region) != size:
        raise ValueError(f"Image slice is {len(region)} bytes, expected {size}")
    return {"region": region,
            "metadata": {"start_addr": start_addr, "end_addr": end_addr, "size": size,
                         "controller": "pq-bcm"}}


def make_bcm_flash_profile(loader: LoaderConfig, *, kwp_factory, device_factory,
                           transport_factory, identify):
    def validate_controller(info, metadata):
        part = str(info.get("software_part_number", info.get("part_number", ""))).upper()
        if not part.startswith("8P0907063E"):
            raise RuntimeError(f"Identification {part or '<empty>'} is not the PQ BCM 8P0907063E")

    def verify_programming_channel(tp):
        kwp = kwp_factory(tp, lambda *_: None, False)
        # The loader's identity service is unknown; try the app's F187 first,
        # then fall back to 1A 9B which many PQ loaders answer.
        text = ""
        for probe in (lambda: kwp.request(codec.part_number_request()),
                      lambda: kwp.read_ecu_ident(0x9B)):
            try:
                text += bytes(probe()).decode("latin-1", "ignore")
            except Exception:
                continue
        if loader.loader_identity_marker not in text:
            raise RuntimeError(
                "BCM did not present the expected resident-loader marker "
                f"{loader.loader_identity_marker!r}; got {text!r}")

    def erase_payload(start, end, metadata):
        if loader.erase_is_start_end:
            return _a3(start) + _a3(end)
        raise BCMFlashNotConfigured("Non start/end erase payload must be captured")

    def checksum_payload(start, end, metadata):
        if "checksum" not in metadata:
            raise BCMFlashNotConfigured("Image checksum (loader policy) not supplied in metadata")
        if loader.checksum_is_start_end_crc16:
            return _a3(start) + _a3(end) + struct.pack(">H", metadata["checksum"])
        raise BCMFlashNotConfigured("Non start/end/crc16 checksum payload must be captured")

    def validate_fresh_application(info):
        if not str(info.get("part_number", "")).upper().startswith("8P0907063E"):
            raise RuntimeError("Fresh BCM application boot not confirmed after flash")

    return PQFlashProfile(
        name="pq-bcm",
        module=BCM_MODULE_ADDR,
        kwp_factory=kwp_factory,
        prepare_image=prepare_image,
        device_factory=device_factory,
        transport_factory=transport_factory,
        identify=identify,
        validate_controller=validate_controller,
        is_application_channel=lambda tp: True,
        initial_session=0x89,
        programming_session=SESSION_PROGRAMMING,
        pre_programming_security=None,
        programming_security=SecurityAccess(0x03, 0x04, add32(loader.programming_key_add), "pq-bcm-programming"),
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
    def __init__(self, loader: LoaderConfig, *, channel=None, module=BCM_MODULE_ADDR,
                 device=None, device_factory=None, progress_cb=None, log_cb=None, debug=False,
                 interface="socketcan"):
        from ...socketcan_device import SocketCANDevice
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
