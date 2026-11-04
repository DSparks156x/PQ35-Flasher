"""Named measuring-block values for the logger (stdlib data only).

Labels, units and (group, field) locations were ported from RNS-E-Hudiy
``vehicle_data``, which transcribed the owner's measuring-group reference PDFs
for one car (engine 01, transmission 02, AWD/Haldex). They may not match every
ECU or software version: the decoded unit reported by the ECU is authoritative.

Fields are ONE-BASED. A value documented in several groups is offered at its
first (primary) location; ``locations`` lists every documented location.
"""
from ._data import VALUES


MODULE_ENGINE = 0x01
MODULE_TRANSMISSION = 0x02
MODULE_HALDEX = 0x0A

# First matching rule wins; the order is from most to least specific.
_CATEGORY_RULES = (
    ("awd.", "Haldex"),
    ("transmission.", "Transmission"),
    ("engine.transmission.", "Transmission"),
    ("engine.selected_gear", "Transmission"),
    ("engine.torque_converter_clutch", "Transmission"),
    ("engine.boost.", "Boost"),
    ("engine.n75_duty", "Boost"),
    ("engine.atmospheric_pressure", "Boost"),
    ("engine.altitude_correction_factor", "Boost"),
    ("engine.ignition_timing", "Timing"),
    ("engine.timing_retard.", "Timing"),
    ("engine.knock.", "Timing"),
    ("engine.camshaft.", "Timing"),
    ("engine.misfire.", "Misfire"),
    ("engine.lambda.", "Lambda"),
    ("engine.catalyst.", "Lambda"),
    ("engine.fuel", "Fuel"),
    ("engine.injection_time", "Fuel"),
    ("engine.correction_factor.", "Fuel"),
    ("engine.adaptation.", "Fuel"),
    ("engine.evap.", "Fuel"),
    ("engine.maf", "Air"),
    ("engine.load", "Air"),
    ("engine.thermostat.integral_air_mass", "Air"),
    ("engine.thermostat.mean_air_mass", "Air"),
    ("engine.runner_flap.", "Air"),
    ("engine.throttle", "Throttle"),
    ("engine.pedal", "Throttle"),
    ("engine.idle.", "Throttle"),
    ("engine.cruise.", "Cruise"),
    ("engine.torque.", "Torque"),
    ("engine.traction_control.", "Torque"),
    ("engine.obd.", "OBD"),
    ("engine.identification.", "Identification"),
    ("engine.vehicle_mileage", "Identification"),
    ("engine.module_communication.", "Communication"),
    ("engine.ac.", "Climate"),
    ("engine.window_heater.", "Climate"),
    ("engine.cooling.", "Temperatures"),
    ("engine.thermostat.", "Temperatures"),
    ("ambient.", "Temperatures"),
    ("vehicle.", "Vehicle"),
    ("engine.terminal30_voltage", "Electrical"),
    ("engine.generator_duty", "Electrical"),
)


def category_for(value_id: str, unit: str = "") -> str:
    for prefix, category in _CATEGORY_RULES:
        if value_id.startswith(prefix):
            return category
    if "temperature" in value_id or unit == "C":
        return "Temperatures"
    return "Engine"


# The source catalog writes units plainly; show them as the decoder reports them.
DISPLAY_UNITS = {"C": "°C", "deg": "°"}


def _entry(row) -> dict:
    value_id, name, unit, kind, module, locations = row
    group, field = locations[0]
    return {
        "id": value_id,
        "name": name,
        "unit": DISPLAY_UNITS.get(unit, unit),
        "group": group,
        "field": field,
        "category": category_for(value_id, unit),
        "module": module,
        "kind": kind,
        "locations": [list(location) for location in locations],
    }


def all_values() -> list:
    return [_entry(row) for row in VALUES]


def values_for_module(module: int) -> list:
    """Every named value for one TP2 module (fresh dicts, safe to modify)."""
    return [_entry(row) for row in VALUES if row[4] == module]


def value_by_id(value_id: str, module: int):
    for row in VALUES:
        if row[0] == value_id and row[4] == module:
            return _entry(row)
    return None


def groups_for(value_ids, module: int) -> list:
    """Sorted unique primary groups needed for ``value_ids`` on ``module``.

    Unknown IDs raise ValueError.
    """
    wanted = list(value_ids)
    primary = {row[0]: row[5][0][0] for row in VALUES if row[4] == module}
    unknown = [value_id for value_id in wanted if value_id not in primary]
    if unknown:
        raise ValueError(f"Unknown measuring values for module 0x{module:02X}: {', '.join(unknown)}")
    return sorted({primary[value_id] for value_id in wanted})


__all__ = ["MODULE_ENGINE", "MODULE_HALDEX", "MODULE_TRANSMISSION", "all_values",
           "category_for", "groups_for", "value_by_id", "values_for_module"]
