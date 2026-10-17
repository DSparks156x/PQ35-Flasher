"""Offline codec for named bounded application-upload reads in BCM 0575.

Static evidence: artifacts/rls/ram_and_fixed_rom_upload_trace.json and
artifacts/rls/bounded_eeprom_upload_trace.json, from SGO
SHA256 B8EF9A8963FECF8E4E4D4181CB5A8E943189EDF12430253419A88089CB6D4362.
The packet format and interpretation have not been confirmed on hardware.

The traced handler requires an active connection, internal session value 3,
and RAM 0x2368 mask 0x20. Service 0x27 subfunctions 0x03/0x04 are associated
with that authorization flag. Session establishment, authorization, keys,
transport framing, device identity checks, and hardware access are deliberately
outside this codec. It contains no client and emits no writes.

Inputs/outputs are diagnostic payloads INCLUDING the SID, without transport or
firmware diagnostic-length prefixes. The prefix's continuation bit must be
passed separately as `more`; it must never be inferred from payload data.
The selected lengths need only one final upload response. Upload 0x36 has no
sequence counter in this firmware branch. No arbitrary addresses or lengths
are accepted. RAM bytes are copied individually, so a four-byte sensor read
is not guaranteed to be an atomic snapshot.

The identity helpers accept only service 22 identifiers F187/F189 and the
known part/version 8P0907063E/0575. Firmware fallback strings were verified
against original SGO bytes at 7F7EE0 (11 bytes) and 7F7EEC (4 bytes), but NVM
can override them. A future live reader must call validate_known_identity on
actual replies before upload. Creating offline request bytes does not prove
the connected module's identity or establish a live session.

Six separate subsystem service-22 reads are backed by
artifacts/rls/subsystem_identity_read_trace.json. They return raw bytes only;
no coding display order, version text, RLS NAD assignment, or reply freshness
is assumed. Firmware may serve these replies from its existing LIN cache.
EEPROM upload targets return raw triplicates, not voted effective RAM values.

Additional RAM capture targets are explicit selections only. Their sources are
artifacts/rls/native_can_receive_cache_trace.json and
artifacts/rls/front_wiper_architecture_trace.json. Cache receipt, freshness,
recipient identity, field polarity and physical units require separate
evidence; these targets return raw bytes. DEFAULT_TARGETS preserves the
original eight-target capture selection. Multi-byte cache captures and
separate target reads are not guaranteed to form one coherent snapshot.
"""

from dataclasses import dataclass
from types import MappingProxyType


class ProtocolError(ValueError):
    """A payload or metadata does not match the bounded static protocol."""


class NegativeResponseError(ProtocolError):
    """A complete negative response, including response-pending, was rejected."""

    def __init__(self, service: int, code: int):
        self.service = service
        self.code = code
        super().__init__(f"Negative response: service 0x{service:02X}, NRC 0x{code:02X}")


@dataclass(frozen=True)
class KnownIdentity:
    part_number: str
    software_version: str


@dataclass(frozen=True)
class ReadTarget:
    encoded_address: int
    length: int
    interpretation: str


TARGETS = MappingProxyType({
    "sensor": ReadTarget(0x8034B1, 4, "BCM LIN receive bytes, CPU-local 0x34B1..0x34B4"),
    "frontparams": ReadTarget(0x80269C, 2, "Effective stored BCM wiper threshold/hysteresis, CPU-local 0x269C/0x269D; algorithm requires runtime 0x1097 bit7, inactive under supplied coding byte21=0x20"),
    "light_hold": ReadTarget(0x802589, 1, "Automatic low-beam hold parameter, CPU-local 0x2589"),
    "light_threshold": ReadTarget(0x802586, 1, "Separate discrete light-level threshold parameter, CPU-local 0x2586"),
    "resident_prefix": ReadTarget(0x80C000, 4, "Four resident fixed-ROM bytes, CPU-local 0xC000..0xC003; contents unknown"),
    "hold_eeprom": ReadTarget(0x000586, 3, "Raw logical EEPROM triplicate for low-beam hold, offsets 0x586..0x588"),
    "frontparams_eeprom": ReadTarget(0x000FA0, 6, "Raw logical EEPROM threshold/hysteresis triplicates, offsets 0xFA0..0xFA5"),
    "light_threshold_eeprom": ReadTarget(0x00057D, 3, "Raw logical EEPROM light threshold triplicate, offsets 0x57D..0x57F"),
    "runtime_coding20_21": ReadTarget(0x801096, 2, "Runtime coding bytes20/21, CPU-local 0x1096/0x1097; raw bytes, including architecture gates"),
    "retained_coding36": ReadTarget(0x8010A6, 1, "Retained runtime coding byte36, CPU-local 0x10A6; raw byte"),
    "cluster621_cache": ReadTarget(0x802C93, 7, "Native CAN0x621 received-prefix cache, CPU-local 0x2C93..0x2C99; receipt and optical meaning unverified live"),
    "sunload3e3_cache": ReadTarget(0x802C52, 5, "Native CAN0x3E3 first-five-byte receive cache, CPU-local 0x2C52..0x2C56; physical units and live receipt unverified"),
    "cluster_freshness": ReadTarget(0x8010C0, 1, "CPU-local 0x10C0; native CAN0x621 receipt clears mask0x20 and timeout sets it, timer units unverified"),
    "receive_state": ReadTarget(0x802DC8, 1, "CPU-local 0x2DC8 receive-group state; native CAN0x621/0x3E3 copying requires mask0x0C nonzero"),
    "lin_f0_commands": ReadTarget(0x80349F, 5, "LIN PID0xF0 command payload cache, CPU-local 0x349F..0x34A3; active schedule depends on coding, recipient identity unproved"),
    "lin_b1_reply": ReadTarget(0x8034AC, 5, "LIN PID0xB1 receive cache, CPU-local 0x34AC..0x34B0; reply freshness and slave identity unproved"),
})

# Page FF (global 0x7FC000..0x7FFFFF, the S12X boot/vector page) is absent
# from the firmware dump. The upload helper 7F42E0 treats encoded high byte
# 0x80 as a CPU-local read, and CPU-local 0xC000..0xFFFF is the fixed alias of
# page FF (CentElecRE comma_headlight_integration_plan.md §2.3 item 3). This is
# the only window outside the named TARGETS, bounded to 64-byte uploads so each
# needs one final 76 response under MAX_UPLOAD 0x43. Read-only; unproven live.
PAGE_FF_TARGET = "page_ff"
PAGE_FF_START = 0x80C000
PAGE_FF_END = 0x810000  # exclusive
PAGE_FF_GLOBAL_START = 0x7FC000
PAGE_FF_SIZE = PAGE_FF_END - PAGE_FF_START
PAGE_FF_CHUNK = 0x40


def in_page_ff_window(address: int, length: int) -> bool:
    return (type(address) is int and type(length) is int
            and 1 <= length <= PAGE_FF_CHUNK
            and PAGE_FF_START <= address and address + length <= PAGE_FF_END)


def upload_target(address: int, length: int) -> str:
    """Return the named target, or PAGE_FF_TARGET, covering exactly this read."""
    for name, target in TARGETS.items():
        if (address, length) == (target.encoded_address, target.length):
            return name
    if in_page_ff_window(address, length):
        return PAGE_FF_TARGET
    raise ProtocolError("Only exact reviewed named BCM read targets or 1..64-byte "
                        "page FF alias reads (0x80C000..0x80FFFF) are enabled")


DEFAULT_TARGETS = (
    "sensor", "frontparams", "light_hold", "light_threshold", "resident_prefix",
    "hold_eeprom", "frontparams_eeprom", "light_threshold_eeprom",
)


@dataclass(frozen=True)
class SubsystemField:
    identifier: int
    width: int


SUBSYSTEM_FIELDS = MappingProxyType({
    "part_nad1": SubsystemField(0x0640, 11),
    "part_nad2": SubsystemField(0x0641, 11),
    "version_nad1": SubsystemField(0x0670, 4),
    "version_nad2": SubsystemField(0x0671, 4),
    "coding_nad1": SubsystemField(0x0610, 3),
    "coding_nad2": SubsystemField(0x0611, 3),
})


def _subsystem_field(name: str) -> SubsystemField:
    if type(name) is not str or name not in SUBSYSTEM_FIELDS:
        raise ProtocolError("Unknown subsystem field; select an exact name from SUBSYSTEM_FIELDS")
    return SUBSYSTEM_FIELDS[name]


def subsystem_request(name: str) -> bytes:
    """Encode one bounded service-22 subsystem read; no hardware access."""
    return b"\x22" + _subsystem_field(name).identifier.to_bytes(2, "big")


# Writable LIN sub-bus coding. The BCM proxies a 3-byte coding write to its
# channel-0 slaves (RLS rain/light sensor and wiper motor) through outer
# service 2E on identifiers 0610 (NAD 1) / 0611 (NAD 2). Firmware route:
# 799AE8 service jump -> 2E handler -> 0x79F019 write-identifier dispatch ->
# 0x79F137, which copies the three incoming bytes unchanged into 236C..236E and
# submits LIN "3B 9A d0 d1 d2" to the selected NAD (subsystem_coding_transport
# .json). Wire byte order is preserved end to end; the VCDS display order is not
# proven, so compare a read-back before trusting a correction.
CODING_WRITE_FIELDS = ("coding_nad1", "coding_nad2")


def subsystem_coding_write_request(name: str, data) -> bytes:
    """Encode 2E + DID(0610/0611) + exactly three coding bytes. Encoder only."""
    if name not in CODING_WRITE_FIELDS:
        raise ProtocolError("Coding write is defined only for coding_nad1/coding_nad2")
    field = _subsystem_field(name)
    payload = _bytes(data)
    if len(payload) != field.width:  # width == 3 for coding
        raise ProtocolError(f"Subsystem coding write needs exactly {field.width} bytes")
    return b"\x2e" + field.identifier.to_bytes(2, "big") + payload


def parse_subsystem_coding_write_response(name: str, reply, *, more: bool = False) -> None:
    """Accept 6E + echoed DID for a positive WriteDataByIdentifier."""
    field = _subsystem_field(name)
    data = _positive(reply, 0x6E, 2, more)
    if data != field.identifier.to_bytes(2, "big"):
        raise ProtocolError("Unexpected coding-write identifier echo")


# --- Service 18 ReadDTCByStatus (sub-function 02, filter FF 00) -------------
# Firmware handler 0x798D86 requires sub-function 02/03 and the filter bytes
# FF 00, else NRC 12. Positive reply: 58, count, then `count` 3-byte records of
# [DTC high, DTC low, status]. See the service-router analysis (FUN_799A28).

def dtc_read_request() -> bytes:
    """Encode 18 02 FF 00 (ReadDTCByStatus, all groups)."""
    return b"\x18\x02\xff\x00"


def parse_dtc_response(reply, *, more: bool = False):
    """Return a list of {code, status} from a 58 response; [] when none."""
    payload = _bytes(reply)
    if payload[:1] == b"\x7f":
        if len(payload) != 3:
            raise ProtocolError("Malformed negative response")
        raise NegativeResponseError(payload[1], payload[2])
    if len(payload) < 2 or payload[0] != 0x58:
        raise ProtocolError("Expected positive DTC SID 0x58")
    count = payload[1]
    body = payload[2:]
    if len(body) < count * 3:
        raise ProtocolError(f"DTC body too short: {len(body)} bytes for {count} codes")
    dtcs = []
    for i in range(count):
        hi, lo, status = body[i * 3:i * 3 + 3]
        dtcs.append({"code": (hi << 8) | lo, "status": status})
    return dtcs


# --- Service 21 ReadDataByLocalIdentifier (measuring blocks) ----------------
# Firmware handler 0x798E5A -> group dispatch 0x79C000 (147 entries). Positive
# reply: 61, group, then the raw measuring body (triples decoded by the worker).

def measuring_request(group: int) -> bytes:
    """Encode 21 <group> for a single measuring group (1..0xFF)."""
    if type(group) is not int or not 1 <= group <= 0xFF:
        raise ProtocolError("Measuring group must be 1..255")
    return b"\x21" + bytes([group])


def parse_measuring_response(group: int, reply, *, more: bool = False) -> bytes:
    """Return the raw measuring body (after 61 + group echo)."""
    payload = _bytes(reply)
    if payload[:1] == b"\x7f":
        if len(payload) != 3:
            raise ProtocolError("Malformed negative response")
        raise NegativeResponseError(payload[1], payload[2])
    if len(payload) < 2 or payload[0] != 0x61:
        raise ProtocolError("Expected positive measuring SID 0x61")
    if payload[1] != (group & 0xFF):
        raise ProtocolError("Measuring group echo mismatch")
    return payload[2:]


def _target(name: str) -> ReadTarget:
    if type(name) is not str or name not in TARGETS:
        raise ProtocolError("Unknown target; select an exact name from TARGETS")
    return TARGETS[name]


def _bytes(data) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ProtocolError("Payload must be bytes, bytearray, or memoryview")
    return bytes(data)


def setup_request(target: str) -> bytes:
    """Encode 35 + BE24 selector/address + 00 + BE24 length."""
    selected = _target(target)
    return window_setup_request(selected.encoded_address, selected.length)


def window_setup_request(address: int, length: int) -> bytes:
    """Encode 35 for a named target's exact range or a bounded page FF chunk."""
    upload_target(address, length)
    return b"\x35" + address.to_bytes(3, "big") + b"\x00" + length.to_bytes(3, "big")


def transfer_request() -> bytes:
    """Encode SID-only 36; no block-sequence counter."""
    return b"\x36"


def exit_request() -> bytes:
    """Encode SID-only 37."""
    return b"\x37"


def part_number_request() -> bytes:
    """Read identifier F187; no guessed service-1A variant."""
    return b"\x22\xf1\x87"


def software_version_request() -> bytes:
    """Read identifier F189."""
    return b"\x22\xf1\x89"


def _positive(reply, sid: int, data_length: int, more: bool) -> bytes:
    if type(more) is not bool:
        raise ProtocolError("Continuation metadata must be a bool")
    if more:
        raise ProtocolError("Continuation response is forbidden for these tiny reads")
    payload = _bytes(reply)
    if payload[:1] == b"\x7f":
        if len(payload) != 3:
            raise ProtocolError("Malformed negative response")
        raise NegativeResponseError(payload[1], payload[2])
    if len(payload) != data_length + 1:
        raise ProtocolError(f"Expected exactly {data_length + 1} response bytes")
    if payload[0] != sid:
        raise ProtocolError(f"Expected positive SID 0x{sid:02X}")
    return payload[1:]


def parse_subsystem_response(name: str, payload, *, more: bool = False) -> bytes:
    """Require 62 + exact DID + exact raw field width.

    No text, numeric coding order, sensor assignment, or freshness is inferred.
    Firmware may return cached LIN diagnostic bytes.
    """
    selected = _subsystem_field(name)
    data = _positive(payload, 0x62, selected.width + 2, more)
    if data[:2] != selected.identifier.to_bytes(2, "big"):
        raise ProtocolError("Unexpected subsystem identifier")
    return data[2:]


def parse_setup_response(reply, *, more: bool = False) -> None:
    """Accept only 75 43, with no continuation metadata."""
    data = _positive(reply, 0x75, 1, more)
    if data != b"\x43":
        raise ProtocolError("Expected upload setup format byte 0x43")


def parse_transfer_response(target: str, reply, *, more: bool = False) -> bytes:
    """Accept 76 followed by exactly the selected raw byte count."""
    return _positive(reply, 0x76, _target(target).length, more)


def parse_window_transfer_response(address: int, length: int, reply, *, more: bool = False) -> bytes:
    """Accept 76 followed by exactly `length` bytes for a permitted window."""
    upload_target(address, length)
    return _positive(reply, 0x76, length, more)


def parse_exit_response(reply, *, more: bool = False) -> None:
    """Accept only 77, with no response data."""
    _positive(reply, 0x77, 0, more)


def _identity(reply, identifier: bytes, width: int, expected: str, more: bool) -> str:
    data = _positive(reply, 0x62, width + 2, more)
    if data[:2] != identifier:
        raise ProtocolError("Unexpected identity identifier")
    raw = data[2:]
    if any(value < 0x20 or value > 0x7E for value in raw):
        raise ProtocolError("Identity must contain printable ASCII only")
    value = raw.decode("ascii").strip(" ")
    if value != expected:
        raise ProtocolError(f"Identity mismatch: expected {expected!r}, received {value!r}")
    return value


def parse_part_number_response(reply, *, more: bool = False) -> str:
    """Require 62 F1 87 + 11 printable ASCII bytes matching 8P0907063E."""
    return _identity(reply, b"\xf1\x87", 11, "8P0907063E", more)


def parse_software_version_response(reply, *, more: bool = False) -> str:
    """Require 62 F1 89 + 4 printable ASCII bytes matching 0575."""
    return _identity(reply, b"\xf1\x89", 4, "0575", more)


def validate_known_identity(part_number_reply, software_version_reply, *,
                            part_number_more: bool = False,
                            software_version_more: bool = False) -> KnownIdentity:
    """Strict identity gate: both supplied actual replies must match.

    No identity is returned for missing, malformed, negative, unknown, or
    mismatched data. This pure function cannot authenticate a device or prove
    that input bytes came from hardware.
    """
    part = parse_part_number_response(part_number_reply, more=part_number_more)
    version = parse_software_version_response(software_version_reply, more=software_version_more)
    return KnownIdentity(part, version)


def decode_sensor_data(data) -> dict:
    """Decode four raw receive bytes into assembly-backed discrete BCM fields.

    These are not optical units or internal sensor calibration curves.
    `light_dark_flag` names the extracted bit without asserting its polarity.
    `front_class` differs from the measuring-group-15 rain value.
    """
    raw = _bytes(data)
    if len(raw) != 4:
        raise ProtocolError("Sensor data must contain exactly four raw bytes")
    return {
        "raw_hex": raw.hex().upper(),
        "front_class": (raw[0] >> 4) & 7,
        "brightness": raw[3] & 7,
        "light_dark_flag": (raw[1] >> 5) & 1,
        "automatic_light_request": raw[1] & 1,
        "group15_rain": (raw[3] >> 3) & 7,
    }


def decode_front_parameter_data(data) -> dict:
    """Decode effective RAM threshold/hysteresis, with unsigned byte boundary.

    The automatic high-stage return boundary is (threshold - hysteresis) & FF;
    additional firmware gates apply. This BCM algorithm requires runtime
    coding 0x1097 bit7; it is inactive under supplied coding byte21=0x20.
    Reading these bytes does not establish an active front-wiper calibration.
    No rain-onset meaning or recommended value is implied. Effective RAM bytes
    can differ from firmware defaults.
    """
    raw = _bytes(data)
    if len(raw) != 2:
        raise ProtocolError("Front parameter data must contain exactly two raw bytes")
    return {
        "raw_hex": raw.hex().upper(),
        "effective_threshold": raw[0],
        "effective_hysteresis": raw[1],
        "unsigned_return_boundary": (raw[0] - raw[1]) & 0xFF,
    }
