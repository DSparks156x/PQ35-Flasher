"""Gateway installation list (KWP 1A 9F on the gateway, TP2 0x1F).

Maps each module's workshop (VCDS) address to the TP2 logical ID it answers
on, e.g. AWD 22 -> TP2 0x0A. It reflects the gateway's coding (what should
be installed), not a live presence check.

Reply body after 5A 9F: one header byte, then 4-byte records
[workshop address, TP2 logical ID, bus, status] until 0xFF. Status bit 0 is
"coded"; other bits are not understood and are passed through raw.
Ported from RNS-E-Hudiy tp2/installation_list.py.
"""
from typing import List

GATEWAY_ID = 0x1F

# Workshop (VCDS) address names. Unlisted addresses fall back to "Address XX".
WORKSHOP_NAMES = {
    0x01: "Engine",
    0x02: "Auto Trans",
    0x03: "ABS Brakes",
    0x04: "Steering Angle",
    0x06: "Seat Mem. Pass.",
    0x08: "Auto HVAC",
    0x09: "Central Elect.",
    0x0F: "Digital Radio",
    0x10: "Park/Steer Assist",
    0x11: "Engine II",
    0x13: "Auto Dist. Reg.",
    0x14: "Susp. Elect.",
    0x15: "Airbags",
    0x16: "Steering wheel",
    0x17: "Instruments",
    0x18: "Aux. Heat",
    0x19: "CAN Gateway",
    0x22: "AWD",
    0x25: "Immobilizer",
    0x26: "Auto Roof",
    0x36: "Seat Mem. Drvr",
    0x37: "Navigation",
    0x3C: "Lane Change",
    0x42: "Door Elect, Driver",
    0x44: "Steering Assist",
    0x46: "Central Conv.",
    0x47: "Sound System",
    0x52: "Door Elect, Pass.",
    0x53: "Parking Brake",
    0x55: "Headlight Range",
    0x56: "Radio",
    0x57: "TV Tuner",
    0x61: "Battery Regul.",
    0x65: "Tire Pressure",
    0x69: "Trailer",
    0x75: "Telematics",
    0x76: "Park Assist",
    0x77: "Telephone",
}


def parse_installation_list(body: bytes) -> List[dict]:
    """Records from the reply body after ``5A 9F`` (header byte first)."""
    entries = []
    for i in range(1, len(body) - 3, 4):
        address, tp2_id, bus, status = body[i:i + 4]
        if address == 0xFF:
            break
        entries.append({
            "address": address,
            "address_text": f"{address:02X}",
            "tp2": tp2_id,
            "bus": bus,
            "status": status,
            "coded": bool(status & 0x01),
            "name": WORKSHOP_NAMES.get(address, f"Address {address:02X}"),
        })
    return entries


def read_installation_list(kwp) -> List[dict]:
    """Ask the gateway (a KWPClient on TP2 0x1F) for its installation list."""
    response = bytes(kwp.read_ecu_ident(0x9F))
    if len(response) < 2 or response[:2] != b"\x5A\x9F":
        raise ValueError(f"Unexpected installation-list reply: {response.hex(' ')}")
    return parse_installation_list(response[2:])
