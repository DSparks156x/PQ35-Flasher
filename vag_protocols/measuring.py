"""KWP2000 measuring-block (21 <group>) decoding, scheduling and polling.

Ported from RNS-E-Hudiy ``tp2/tp2_coding.py`` (formula table),
``tp2/group_scheduler.py`` and the poll loop of ``tp2/tp2_worker.py``
(session handling, keepalive, group cooldown and reconnect policy). The
transport and KWP client are the canonical ones in this package.

Measuring-block fields are ONE-BASED. Wall timestamps describe host receipt,
not an ECU-generated time. No field-count limit is imposed on responses.
"""
from collections import deque
import logging
import math
import time
from typing import Callable, Dict, List, Optional

from .kwp import KWPClient, KWPNegativeResponse


logger = logging.getLogger(__name__)

READ_GROUP_SID = 0x21
READ_GROUP_POSITIVE = 0x61
DEFAULT_SESSION = 0x89

# Error policy from Hudiy's TP2Service.
GROUP_FAILURE_LIMIT = 3          # consecutive failures before a group cools down
GROUP_COOLDOWN_SECONDS = 30.0
SESSION_ERROR_LIMIT = 10         # consecutive transport errors before reconnect
RECONNECT_DELAY_SECONDS = 5.0    # minimum gap between connection attempts
TESTER_PRESENT_IDLE_SECONDS = 2.0
IDLE_SLEEP_SECONDS = 0.01


class MeasuringError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Formula table
# ---------------------------------------------------------------------------

UNIT_MAP = {
    "unit_amper": "A",
    "unit_bar": "bar",
    "unit_barpersecon": "bar/s",
    "unit_centinewtometer": "cNm",
    "unit_degrecelsi": "°C",
    "unit_degreofarc": "deg",
    "unit_degreofarcpersecon": "deg/s",
    "unit_forceofgravi": "g",
    "unit_gramperliter": "g/L",
    "unit_hertz": "Hz",
    "unit_hours": "h",
    "unit_kilogram": "kg",
    "unit_kilogrammetersquar": "kg m2",
    "unit_kilometer": "km",
    "unit_kilometerperhour": "km/h",
    "unit_kilonewto": "kN",
    "unit_kilowatt": "kW",
    "unit_liter": "L",
    "unit_meter": "m",
    "unit_meterpercubicsecon": "m3/s",
    "unit_meterperseconsquar": "m/s2",
    "unit_microliter": "uL",
    "unit_millibar": "mbar",
    "unit_milliliter": "mL",
    "unit_millimeter": "mm",
    "unit_millisecon": "ms",
    "unit_minut": "min",
    "unit_minutinver": "rpm",
    "unit_newtometer": "Nm",
    "unit_newtometerpersecon": "Nm/s",
    "unit_ohm": "ohm",
    "unit_percent": "%",
    "unit_percentofforceofgravi": "% g",
    "unit_percentpersecon": "%/s",
    "unit_secon": "s",
    "unit_volt": "V",
    "unit_watt": "W",
    "unit_year": "yr",
}


def normalize_unit(unit: str) -> str:
    if not unit:
        return ""
    key = unit.strip().lower()
    return UNIT_MAP.get(key, unit.strip())


def _bitvalue(a: int, b: int) -> str:
    bits = []
    for mask in (128, 64, 32, 16, 8, 4, 2, 1):
        if a & mask:
            bits.append("1" if b & mask else "0")
        else:
            bits.append("X")
    return "".join(bits)


def _signed16(a: int, b: int) -> int:
    raw = (a << 8) | b
    return raw - 0x10000 if raw & 0x8000 else raw


# formula -> (function(a, b) -> value, unit). Results match TP2Coding.decode_value.
_FORMULAS = {
    1: (lambda a, b: (a * b) / 5.0, "rpm"),
    2: (lambda a, b: a * 0.002 * b, "%"),
    3: (lambda a, b: 0.002 * a * b, "°"),
    5: (lambda a, b: a * (b - 100) * 0.1, "°C"),
    6: (lambda a, b: 0.001 * a * b, "V"),
    7: (lambda a, b: (a * b) / 100.0, "km/h"),
    8: (lambda a, b: 0.1 * a * b, ""),
    9: (lambda a, b: (b - 127) * 0.02 * a, "°"),
    10: (lambda a, b: "COLD" if b == 0 else "WARM", ""),
    11: (lambda a, b: 0.0001 * a * (b - 128.0) + 1.0, ""),
    12: (lambda a, b: 0.001 * a * b, "ohm"),
    13: (lambda a, b: (b - 127) * 0.001 * a, "mm"),
    14: (lambda a, b: 0.01 * a * (b - 100), "bar"),
    15: (lambda a, b: 0.01 * a * b, "ms"),
    16: (_bitvalue, "bitval"),
    17: (lambda a, b: f"{chr(a)}{chr(b)}", ""),
    18: (lambda a, b: 0.04 * a * b, "mbar"),
    19: (lambda a, b: a * b * 0.01, "L"),
    20: (lambda a, b: a * (b - 128) / 128.0, "%"),
    21: (lambda a, b: 0.001 * a * b, "V"),
    22: (lambda a, b: a * b * 0.001, "ms"),
    23: (lambda a, b: (b / 256.0) * a, "%"),
    24: (lambda a, b: 0.001 * a * b, "A"),
    25: (lambda a, b: (a / 182.0) + (1.421 * b), "g/s"),
    26: (lambda a, b: b - a, "°C"),
    27: (lambda a, b: abs(b - 128) * 0.01 * a, "°"),
    28: (lambda a, b: b - a, "°C"),
    30: (lambda a, b: (b / 12.0) * a, "°"),
    31: (lambda a, b: (b / 2560.0) * a, "°C"),
    33: (lambda a, b: 0.01 * a * b, "%"),
    34: (lambda a, b: (b - 128) * 0.01 * a, "kW"),
    35: (lambda a, b: 0.01 * a * b, "L/h"),
    36: (lambda a, b: a * 256 + b, "°"),
    37: (lambda a, b: a * 256 + b, "s"),
    38: (lambda a, b: (b - 128) * 0.001 * a, "°"),
    39: (lambda a, b: (b / 256.0) * a, "mg/h"),
    40: (lambda a, b: 0.001 * a * b, "A"),
    41: (lambda a, b: 0.1 * a * b, "Ah"),
    42: (lambda a, b: (b - 128) * 0.01 * a, "kW"),
    43: (lambda a, b: (b * 0.1) + (25.5 * a), "V"),
    44: (lambda a, b: f"{a}:{b:02d}", "h:m"),
    45: (lambda a, b: (a * b) / 1000.0, ""),
    46: (lambda a, b: (a * b - 3200.0) * 0.0027, "°"),
    47: (lambda a, b: (b - 128) * a, "ms"),
    48: (lambda a, b: a * 256 + b, ""),
    49: (lambda a, b: (b / 4.0) * a * 0.1, "mg/h"),
    50: (lambda a, b: (b - 128.0) / 0.01 / a if a != 0 else (b - 128.0) / 0.01, "mbar"),
    51: (lambda a, b: ((b - 128.0) / 255.0) * a, "mg/h"),
    52: (lambda a, b: (b * 0.02 * a) - a, "Nm"),
    53: (lambda a, b: (b - 128.0) * 1.4222 + 0.006 * a, "g/s"),
    54: (lambda a, b: a * 256 + b, "count"),
    55: (lambda a, b: (a * b) / 200.0, "s"),
    56: (lambda a, b: a * 256 + b, "WSC"),
    57: (lambda a, b: a * 256 + b, "WSC"),
    59: (lambda a, b: (a * 256 + b) / 32768.0, ""),
    60: (lambda a, b: (a * 256 + b) * 0.01, "s"),
    61: (lambda a, b: (b - 128.0) / a if a != 0 else (b - 128.0), ""),
    62: (lambda a, b: 0.256 * a * b, "S"),
    63: (lambda a, b: f"{chr(a)}{chr(b)}?", ""),
    64: (lambda a, b: a + b, "ohm"),
    65: (lambda a, b: 0.01 * a * (b - 127.0), "mm"),
    66: (lambda a, b: (a * b) / 511.12, "V"),
    67: (lambda a, b: (640.0 * a) + b * 2.5, "°"),
    68: (lambda a, b: (256.0 * a + b) / 7.365, "°/s"),
    69: (lambda a, b: (256.0 * a + b) * 0.3254, "bar"),
    70: (lambda a, b: (256.0 * a + b) * 0.192, "m/s2"),
    71: (lambda a, b: 0.1 * a * b, "%"),
    72: (lambda a, b: 0.1 * a * b, "L"),
    81: (lambda a, b: _signed16(a, b) * 0.04375, ""),
    83: (lambda a, b: (a * 256 + b) * 0.01, "bar"),
    94: (lambda a, b: 0.1 * a * (b - 128), "Nm"),
}

KNOWN_FORMULAS = frozenset(_FORMULAS) | {4}


def decode_value(formula: int, a: int, b: int):
    """Return ``(value, unit)`` for one measuring-block triple.

    An unrecognised formula returns ``("0xAABB", "Type_N")``.
    """
    if formula == 4:
        if a == 1:
            return 0.75 * b - 48.0, "°C"
        return abs(b - 127) * 0.01 * a, "°"
    entry = _FORMULAS.get(formula)
    if entry is None:
        return f"0x{a:02X}{b:02X}", f"Type_{formula}"
    function, unit = entry
    return function(a, b), normalize_unit(unit)


def format_value(value) -> str:
    """Short display form of a decoded value (no unit)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        return str(value)
    if float(value).is_integer() and abs(value) < 1e15:
        return str(int(value))
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return "0" if text == "-0" else text


def _group_body(payload) -> bytes:
    payload = bytes(payload)
    # A complete response is 61 gg + 3n bytes (length 2 mod 3); a body is 3n.
    if len(payload) >= 2 and payload[0] == READ_GROUP_POSITIVE and len(payload) % 3 == 2:
        return payload[2:]
    return payload


def decode_group(payload) -> List[dict]:
    """Decode a measuring-group payload into one dict per complete field.

    ``payload`` is normally the KWP positive-response body after ``61 <grp>``.
    A full ``61 gg ...`` response is also accepted: it is recognised when the
    first byte is 0x61 and the length is 2 modulo 3 (a body is a multiple of
    three). A trailing incomplete triple is ignored.
    """
    body = _group_body(payload)
    fields = []
    for offset in range(0, len(body) - 2, 3):
        formula, a, b = body[offset], body[offset + 1], body[offset + 2]
        value, unit = decode_value(formula, a, b)
        numeric = formula in KNOWN_FORMULAS and not isinstance(value, str)
        fields.append({
            "index": offset // 3 + 1,
            "formula": formula,
            "a": a,
            "b": b,
            "value": value,
            "unit": unit,
            "numeric": numeric,
            "text": format_value(value),
        })
    return fields


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

def parse_group_periods(raw):
    if not isinstance(raw, dict):
        raise ValueError("group_periods_ms must be an object")
    periods = {}
    for group, period in raw.items():
        if isinstance(group, bool) or not isinstance(group, (str, int)):
            raise ValueError("Measuring group must be an integer between 0 and 255")
        group = int(group)
        if not 0 <= group <= 255:
            raise ValueError("Measuring group must be between 0 and 255")
        if isinstance(period, bool) or not isinstance(period, (int, float)):
            raise ValueError("Group periods must be positive finite milliseconds")
        if not math.isfinite(period) or period <= 0:
            raise ValueError("Group periods must be positive finite milliseconds")
        periods[group] = float(period)
    return periods


class GroupScheduler:
    """Rate-aware round-robin over measuring groups.

    Periods are milliseconds; 0 means "as fast as possible". Every ``now``
    argument is optional and defaults to the injected monotonic ``clock``.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.periods: Dict[int, float] = {}
        self.next_due: Dict[int, float] = {}
        self.last_started: Dict[int, float] = {}
        self.stats: Dict[int, dict] = {}
        self.cursor = 0

    def _now(self, now):
        return self.clock() if now is None else now

    def configure(self, normal=(), low=(), timed=None, now=None):
        now = self._now(now)
        periods = {group: 60000.0 for group in low}
        for group, period in (timed or {}).items():
            periods[group] = min(periods.get(group, period), period)
        periods.update({group: 0.0 for group in normal})
        for group, period in periods.items():
            if group not in self.periods:
                self.next_due[group] = now
            elif period != self.periods[group]:
                self.next_due[group] = self.last_started.get(group, now) + period / 1000
        self.periods = periods
        self.next_due = {group: self.next_due[group] for group in periods}
        self.last_started = {group: value for group, value in self.last_started.items()
                             if group in periods}

    def configure_groups(self, groups, interval_ms: float = 0, now=None):
        """Poll every group at one interval (0 = as fast as possible)."""
        groups = list(groups)
        if interval_ms:
            self.configure(timed={group: float(interval_ms) for group in groups}, now=now)
        else:
            self.configure(normal=groups, now=now)

    def select(self, now=None, blocked=(), advance=True):
        """Round-robin due groups so unlimited polling cannot starve others."""
        now = self._now(now)
        groups = sorted(self.periods)
        blocked = set(blocked)
        for step in range(len(groups)):
            index = (self.cursor + step) % len(groups)
            group = groups[index]
            if group not in blocked and now >= self.next_due[group]:
                if advance:
                    self.cursor = (index + 1) % len(groups)
                return group
        return None

    def next_due_time(self, blocked=()):
        blocked = set(blocked)
        due = [when for group, when in self.next_due.items() if group not in blocked]
        return min(due) if due else None

    def started(self, group, now=None):
        now = self._now(now)
        self.last_started[group] = now
        self.next_due[group] = now + self.periods.get(group, 0) / 1000

    def completed(self, group, now=None, timestamp=None, duration_ms=0.0, success=True):
        now = self._now(now)
        period = self.periods.get(group, 0) / 1000
        if group in self.next_due and period and now >= self.next_due[group]:
            # Skip missed deadlines; never queue catch-up requests.
            self.next_due[group] = now + period
        stat = self.stats.setdefault(group, {"observed_count": 0,
                                             "success_times": deque(maxlen=32)})
        stat["request_duration_ms"] = duration_ms
        if success:
            stat["observed_count"] += 1
            stat["last_successful_acquisition_timestamp"] = timestamp
            stat["success_times"].append(now)

    def snapshot(self, now=None):
        now = self._now(now)
        result = {}
        for group, period in self.periods.items():
            stat = self.stats.get(group, {})
            successes = stat.get("success_times", ())
            rate = None
            if len(successes) > 1:
                # Include current idle age: a stopped source must not retain its peak rate.
                elapsed = max(now, successes[-1]) - successes[0]
                if elapsed > 0:
                    rate = (len(successes) - 1) / elapsed
            overdue = (period > 0 and group in self.last_started
                       and now > self.next_due[group] + period / 1000)
            result[str(group)] = {
                "requested_period_ms": period,
                "observed_count": stat.get("observed_count", 0),
                "last_successful_acquisition_timestamp": stat.get("last_successful_acquisition_timestamp"),
                "request_duration_ms": stat.get("request_duration_ms"),
                "achieved_hz": rate,
                "overrun": bool(period and (overdue
                    or stat.get("request_duration_ms", 0) > period
                    or (len(successes) >= 3 and rate is not None and rate < 900 / period))),
            }
        return result


def group_observation(module, group, response, timestamp, duration_ms, error=None):
    """Return ``(payload, failure)`` for one ``21 <group>`` exchange.

    Exactly one is not None. ``response`` is the full KWP response.
    """
    common = {"module": module, "group": group, "acquisition_timestamp": timestamp,
              "request_duration_ms": duration_ms}
    response = bytes(response or b"")
    nrc = None
    transient = True
    kind = "transport"
    if error is None and len(response) >= 2 and response[0] == READ_GROUP_POSITIVE \
            and response[1] == group:
        raw = response[2:]
        decoded = decode_group(raw)
        complete = bool(decoded) and len(raw) % 3 == 0
        payload = dict(common, data=decoded, raw_data_hex=raw.hex(),
                       block_count=len(decoded), trailing_bytes=len(raw) % 3,
                       complete=complete)
        if complete:
            return payload, None
        error, kind = "Incomplete or empty measuring-group payload", "malformed"
    elif error is None and response and response[0] == 0x7F:
        nrc = response[2] if len(response) >= 3 else None
        kind = "negative_response" if nrc is not None else "malformed"
        error = (f"Request rejected (NRC 0x{nrc:02X})" if nrc is not None
                 else "Malformed negative response")
        # Unsupported service/group are not going to recover by retrying.
        transient = nrc not in (0x11, 0x12, 0x31)
    elif error is None:
        kind = "malformed" if response else "transport"
        error = "Unexpected measuring-group response" if response else "No measuring-group response"
    failure = dict(common, error=str(error), error_kind=kind, nrc=nrc,
                   transient=transient, complete=False, raw_response_hex=response.hex())
    return None, failure


# ---------------------------------------------------------------------------
# Polling session
# ---------------------------------------------------------------------------

def _default_transport_factory(device, *, module, timeout, debug, log_fn):
    from .tp2 import TP2Transport
    return TP2Transport(device, module=module, timeout=timeout, debug=debug, log_fn=log_fn)


class MeasuringSession:
    """Poll measuring groups on one module until ``should_stop()`` is true.

    The caller owns ``device`` (open/close). This class opens and closes only
    the TP2 channel. ``transport_factory(device, module=, timeout=, debug=,
    log_fn=)`` returns an opened transport; tests inject a fake.

    ``run()`` raises :class:`MeasuringError` when no connection could ever be
    established (``connect_attempts`` consecutive failures before the first
    success). Exceptions raised by ``on_sample`` propagate after the channel
    is closed.
    """

    def __init__(self, device, module: int, groups: List[int], *,
                 interval_ms: int = 0, session: Optional[int] = DEFAULT_SESSION,
                 on_sample: Optional[Callable[[dict], None]] = None,
                 should_stop: Optional[Callable[[], bool]] = None,
                 log_fn: Optional[Callable[[str], None]] = None,
                 timeout: float = 2.0, transport_factory=None,
                 connect_attempts: int = 3, debug: bool = False,
                 clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time,
                 sleeper: Callable[[float], None] = time.sleep):
        if not 0 <= int(module) <= 0x7F:
            raise ValueError("TP2 logical module ID must be within 0x00..0x7F")
        groups = sorted({int(group) for group in groups})
        if not groups:
            raise ValueError("At least one measuring group is required")
        if any(not 0 <= group <= 0xFF for group in groups):
            raise ValueError("Measuring group must be between 0 and 255")
        if interval_ms < 0 or not math.isfinite(interval_ms):
            raise ValueError("interval_ms must be zero or positive")
        self.device = device
        self.module = int(module)
        self.groups = groups
        self.interval_ms = interval_ms
        self.session = session
        self.on_sample = on_sample or (lambda sample: None)
        self.should_stop = should_stop or (lambda: False)
        self.log_fn = log_fn or logger.info
        self.timeout = timeout
        self.transport_factory = transport_factory or _default_transport_factory
        self.connect_attempts = max(1, int(connect_attempts))
        self.debug = debug
        self.clock = clock
        self.wall_clock = wall_clock
        self.sleeper = sleeper

        self.scheduler = GroupScheduler(clock=clock)
        self.scheduler.configure_groups(groups, interval_ms)
        self.transport = None
        self.kwp: Optional[KWPClient] = None
        self.connected = False
        self.ever_connected = False
        self.last_connect_attempt: Optional[float] = None
        self.connect_failures = 0
        self.last_kwp_request = 0.0
        self.group_errors: Dict[int, int] = {}
        self.group_cooldowns: Dict[int, float] = {}
        self.error_count = 0
        self.samples = 0
        self.errors = 0
        self.reconnects = 0
        self._first_success: Dict[int, float] = {}
        self._last_success: Dict[int, float] = {}
        self._success_count: Dict[int, int] = {}

    def log(self, message: str):
        self.log_fn(f"[MEAS 0x{self.module:02X}] {message}")

    # -- connection -------------------------------------------------------

    def _connect(self) -> bool:
        self.last_connect_attempt = self.clock()
        transport = None
        try:
            transport = self.transport_factory(self.device, module=self.module,
                                               timeout=self.timeout, debug=self.debug,
                                               log_fn=self.log_fn)
            kwp = KWPClient(transport, debug=self.debug, log_fn=self.log_fn,
                            clock=self.clock, sleeper=self.sleeper)
            if self.session is not None:
                try:
                    kwp.session(self.session)
                except KWPNegativeResponse as error:
                    self.log(f"Session 0x{self.session:02X} refused ({error}); "
                             "continuing in the current session")
            self.last_kwp_request = self.clock()
            keepalive = getattr(transport, "maybe_send_keep_alive", None)
            if keepalive is not None:
                keepalive(force=True)
        except Exception as error:
            self.log(f"Connect failed: {error}")
            if transport is not None:
                self._close_transport(transport)
            self.connect_failures += 1
            return False
        if self.ever_connected:
            self.reconnects += 1
        self.transport = transport
        self.kwp = kwp
        self.connected = True
        self.ever_connected = True
        self.connect_failures = 0
        self.error_count = 0
        self.log("Connected")
        return True

    def _close_transport(self, transport):
        try:
            transport.disconnect()
        except Exception as error:
            self.log(f"TP2 disconnect failed: {error}")

    def _drop(self, reason: str):
        self.log(f"Dropping channel: {reason}")
        if self.transport is not None:
            self._close_transport(self.transport)
        self.transport = None
        self.kwp = None
        self.connected = False

    # -- keepalive --------------------------------------------------------

    def _idle_keepalive(self):
        """3E when no KWP request for >2 s, then a rate-limited TP2 A3."""
        try:
            if self.clock() - self.last_kwp_request > TESTER_PRESENT_IDLE_SECONDS:
                self.last_kwp_request = self.clock()
                try:
                    self.kwp.request(b"\x3E", raise_negative=False, validate_positive=False)
                except KWPNegativeResponse:
                    pass
            keepalive = getattr(self.transport, "maybe_send_keep_alive", None)
            if keepalive is not None:
                keepalive()
        except Exception as error:
            self._drop(f"keepalive failed: {error}")

    # -- polling ----------------------------------------------------------

    def _blocked(self, now):
        return [group for group, until in self.group_cooldowns.items() if now < until]

    def _emit(self, group, started, response, error):
        finished = self.clock()
        wall = self.wall_clock()
        duration_ms = (finished - started) * 1000.0
        payload, failure = group_observation(self.module, group, response, wall,
                                             duration_ms, error=error)
        success = failure is None
        self.scheduler.completed(group, finished, wall, duration_ms, success)
        response = bytes(response or b"")
        body = response[2:] if (len(response) >= 2 and response[0] == READ_GROUP_POSITIVE) else b""
        if success:
            self.samples += 1
            self._first_success.setdefault(group, finished)
            self._last_success[group] = finished
            self._success_count[group] = self._success_count.get(group, 0) + 1
        else:
            self.errors += 1
        self.on_sample({
            "group": group,
            "time": finished,
            "wall_time": wall,
            "fields": payload["data"] if success else decode_group(body),
            "raw": response.hex(),
            "error": None if success else failure["error"],
            "round_trip_ms": duration_ms,
        })
        return success

    def _poll_once(self, group):
        started = self.clock()
        self.scheduler.started(group, started)
        self.last_kwp_request = started
        try:
            response = self.kwp.request(bytes([READ_GROUP_SID, group]),
                                        raise_negative=False, validate_positive=False)
        except Exception as error:
            self._emit(group, started, None, error)
            self.group_errors[group] = self.group_errors.get(group, 0) + 1
            self.error_count += 1
            if self.error_count >= SESSION_ERROR_LIMIT:
                self.error_count = 0
                self._drop("too many session errors")
            else:
                try:
                    self.transport.maybe_send_keep_alive(force=True)
                except Exception as keepalive_error:
                    self._drop(f"keepalive after error failed: {keepalive_error}")
        else:
            if self._emit(group, started, response, None):
                self.group_errors[group] = 0
                self.error_count = 0
                try:
                    self.transport.maybe_send_keep_alive()
                except Exception as error:
                    self._drop(f"keepalive after read failed: {error}")
            else:
                self.group_errors[group] = self.group_errors.get(group, 0) + 1
        if self.group_errors.get(group, 0) >= GROUP_FAILURE_LIMIT:
            self.log(f"Group {group} failed {GROUP_FAILURE_LIMIT} times; "
                     f"suspending for {GROUP_COOLDOWN_SECONDS:.0f} s")
            self.group_cooldowns[group] = self.clock() + GROUP_COOLDOWN_SECONDS
            self.group_errors[group] = 0

    def _idle_sleep(self, now):
        due = self.scheduler.next_due_time(self._blocked(now))
        if due is None:
            delay = IDLE_SLEEP_SECONDS
        else:
            delay = min(max(due - now, 0.0), IDLE_SLEEP_SECONDS * 5)
        self.sleeper(max(delay, 0.001))

    def run(self) -> dict:
        try:
            while not self.should_stop():
                now = self.clock()
                if not self.connected:
                    if (self.last_connect_attempt is not None
                            and now - self.last_connect_attempt < RECONNECT_DELAY_SECONDS):
                        self.sleeper(0.05)
                        continue
                    if not self._connect():
                        if not self.ever_connected and self.connect_failures >= self.connect_attempts:
                            raise MeasuringError(
                                f"Could not open a measuring session on module 0x{self.module:02X} "
                                f"after {self.connect_failures} attempts")
                    continue
                group = self.scheduler.select(now, self._blocked(now))
                if group is None:
                    self._idle_keepalive()
                    if self.connected:
                        self._idle_sleep(now)
                    continue
                self._poll_once(group)
        finally:
            if self.transport is not None:
                self._close_transport(self.transport)
            self.transport = None
            self.kwp = None
            self.connected = False
        return self.summary()

    def snapshot(self) -> dict:
        """Live rolling per-group statistics (string group keys)."""
        return self.scheduler.snapshot()

    def summary(self) -> dict:
        achieved = {}
        for group in self.groups:
            count = self._success_count.get(group, 0)
            elapsed = self._last_success.get(group, 0.0) - self._first_success.get(group, 0.0)
            achieved[group] = (count - 1) / elapsed if count > 1 and elapsed > 0 else None
        return {"samples": self.samples, "errors": self.errors,
                "reconnects": self.reconnects, "achieved_hz": achieved}
