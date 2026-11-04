"""KWP2000 diagnostic-trouble-code read/clear for VAG application sessions.

Ported from RNS-E-Hudiy ``tp2/tp2_worker.py`` (request order and fallbacks)
and ``tp2/tp2_coding.py`` (status and freeze-frame decoding). The caller owns
the transport and the diagnostic session; these helpers only exchange KWP.

Read order: ``18 02 FF 00`` (VCDS-style ReadDTCByStatus), then ``18 00 FF 00``,
then ``13`` (ReadDiagnosticTroubleCodes), then OBD mode ``03``. Each fallback
is tried only after a negative response to the previous request.
"""
from typing import List, Optional

from .kwp import KWP_NRC


READ_REQUESTS = (
    ("18 02 FF 00", b"\x18\x02\xFF\x00"),
    ("18 00 FF 00", b"\x18\x00\xFF\x00"),
    ("13", b"\x13"),
    ("03", b"\x03"),
)
CLEAR_REQUEST = b"\x14\xFF\x00"

_STATUS_BITS = (
    (0x01, "Test Failed"),
    (0x02, "Failed This Cycle"),
    (0x04, "Pending"),
    (0x08, "Confirmed"),
    (0x10, "Not Completed Since Clear"),
    (0x20, "Failed Since Clear"),
    (0x40, "Not Completed This Cycle"),
    (0x80, "Warning Requested"),
)


def decode_dtc_status(status_byte: int) -> List[str]:
    """Hudiy's status-bit names (ISO 14229 layout); ``["No Status"]`` when zero."""
    active = [text for bit, text in _STATUS_BITS if status_byte & bit]
    return active if active else ["No Status"]


def vag_code_text(code: int) -> str:
    """VAG five-digit decimal code, for example ``00573``."""
    return f"{code:05d}"


def vag_p_code(code: int) -> Optional[str]:
    """SAE P-code equivalent of a VAG engine code (16384 + 1024*k + nnn), else None."""
    offset = code - 16384
    if not 0 <= offset < 4 * 1024:
        return None
    block, number = divmod(offset, 1024)
    if number > 999:
        return None
    return f"P{block}{number:03d}"


def obd_code_text(code: int) -> str:
    """SAE J2012 text for a two-byte OBD-II mode 03 code, for example ``P0301``."""
    letter = "PCBU"[(code >> 14) & 0x03]
    return f"{letter}{(code >> 12) & 0x03}{(code >> 8) & 0x0F:X}{(code >> 4) & 0x0F:X}{code & 0x0F:X}"


def _nrc_text(response: bytes) -> str:
    if len(response) >= 3:
        return f"Request rejected (NRC 0x{response[2]:02X} {KWP_NRC.get(response[2], 'Unknown')})"
    return "Request rejected"


def _code_entry(code: int, status: Optional[int]) -> dict:
    entry = {
        "code": code,
        "code_text": vag_code_text(code),
        "p_code": vag_p_code(code),
        "status": status if status is not None else 0,
        # The raw byte only: decode_dtc_status uses UDS (ISO 14229) bit names, which
        # aren't confirmed for KWP/VAG status bytes.
        "status_text": f"status 0x{status:02X}" if status is not None else "",
    }
    return entry


def parse_dtc_response(response: bytes) -> dict:
    """Parse a positive 58/53/43 response into ``{"count", "codes", "error"}``."""
    response = bytes(response)
    if not response:
        return {"count": 0, "codes": [], "error": "No response for DTC request"}
    sid = response[0]
    if sid in (0x58, 0x53):
        if len(response) < 2:
            return {"count": 0, "codes": [], "error": "Truncated DTC response"}
        count = response[1]
        data = response[2:]
        width = 3 if sid == 0x58 else 2
        available = len(data) // width
        codes = []
        for index in range(min(count, available)):
            item = data[index * width:(index + 1) * width]
            code = (item[0] << 8) | item[1]
            codes.append(_code_entry(code, item[2] if width == 3 else None))
        error = None
        if available < count:
            error = (f"DTC response length mismatch: expected {count * width} bytes, "
                     f"got {len(data)}")
        return {"count": count, "codes": codes, "error": error}
    if sid == 0x43:
        data = response[1:]
        if len(data) % 2:
            # CAN OBD responses carry a leading count byte.
            data = data[1:]
        codes = []
        for index in range(0, len(data) - 1, 2):
            code = (data[index] << 8) | data[index + 1]
            if code:
                codes.append({"code": code, "code_text": obd_code_text(code), "p_code": None,
                              "status": 0, "status_text": ""})
        return {"count": len(codes), "codes": codes, "error": None}
    return {"count": 0, "codes": [], "error": f"Unexpected DTC response: 0x{sid:02X}"}


def read_dtcs(kwp, *, freeze_frames: bool = False) -> dict:
    """Read stored DTCs with Hudiy's fallback order.

    Returns ``{"method", "codes", "raw", "count", "error"}``. ``error`` is None
    on a parsed positive response. Transport errors propagate.
    """
    method = ""
    response = b""
    for method, request in READ_REQUESTS:
        response = kwp.request(request, raise_negative=False, validate_positive=False)
        if not (response and response[0] == 0x7F):
            break
    if response and response[0] == 0x7F:
        result = {"count": 0, "codes": [], "error": _nrc_text(response)}
    else:
        result = parse_dtc_response(response)
    if freeze_frames and result["error"] is None and method != "03":
        for entry in result["codes"]:
            try:
                entry["freeze_frame"] = read_freeze_frame(kwp, entry["code"])
            except Exception as error:  # Optional detail; never fails the read.
                entry["freeze_frame_error"] = str(error)
    result.update(method=method, raw=bytes(response).hex())
    return result


def clear_dtcs(kwp) -> dict:
    """Send ``14 FF 00``; ``cleared`` only on a positive 0x54 response."""
    response = kwp.request(CLEAR_REQUEST, raise_negative=False, validate_positive=False)
    response = bytes(response)
    cleared = bool(response) and response[0] == 0x54
    error = None
    if not cleared:
        error = _nrc_text(response) if response[:1] == b"\x7f" else (
            f"Unexpected clear response: {response.hex() or '<empty>'}")
    return {"cleared": cleared, "raw": response.hex(), "error": error}


def read_freeze_frame(kwp, code: int) -> Optional[dict]:
    """VCDS-style ``12 00 04 hi lo``; None when the module rejects it."""
    response = kwp.request(bytes([0x12, 0x00, 0x04, (code >> 8) & 0xFF, code & 0xFF]),
                           raise_negative=False, validate_positive=False)
    if not response or response[0] != 0x52:
        return None
    return {"raw": bytes(response[1:]).hex(), "fields": decode_freeze_frame(response)}


def decode_freeze_frame(raw_data) -> List[dict]:
    """Decode VAG environment data ``[52, DTC_H, DTC_L, PID, value, ...]``."""
    if not raw_data or len(raw_data) < 4:
        return []
    data = list(raw_data)[3:]
    results = []
    i = 0
    while i < len(data):
        pid = data[i]
        if i + 1 >= len(data):
            break
        if pid == 0x6C:
            results.append({"label": "Priority", "value": data[i + 1], "known": True})
            i += 2
        elif pid == 0x2B:
            results.append({"label": "Frequency", "value": data[i + 1], "known": True})
            i += 2
        elif pid == 0x02:
            results.append({"label": "Reset Counter", "value": data[i + 1], "known": True})
            i += 2
        elif pid == 0x03:
            if i + 3 < len(data):
                value = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
                results.append({"label": "Mileage", "value": value, "unit": "km", "known": True})
                i += 4
            else:
                i += 2
        elif pid == 0x58:
            results.append({"label": "Speed", "value": data[i + 1], "unit": "km/h", "known": True})
            i += 2
        elif pid == 0x2E:
            results.append({"label": "Voltage", "value": round(data[i + 1] * 0.1, 1),
                            "unit": "V", "known": True})
            i += 2
        elif pid == 0x24:
            if i + 3 < len(data):
                value = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
                results.append({"label": "Distance", "value": value, "unit": "km", "known": True})
                i += 4
            else:
                i += 2
        elif pid == 0x5B:
            results.append({"label": "Engine Load", "value": data[i + 1], "unit": "%", "known": True})
            i += 2
        elif pid == 0x4E:
            if i + 2 < len(data):
                value = (data[i + 1] << 8) | data[i + 2]
                results.append({"label": "Engine Speed", "value": value, "unit": "rpm", "known": True})
                i += 3
            else:
                i += 2
        else:
            results.append({"label": f"PID_0x{pid:02X}", "value": data[i + 1], "known": False})
            i += 2
    return results
