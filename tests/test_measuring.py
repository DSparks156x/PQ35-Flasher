"""Offline measuring-block decoder, scheduler and polling-session checks.

No CAN hardware: transports are scripted fakes and the clock is simulated.
The formula table is compared against RNS-E-Hudiy ``tp2/tp2_coding.py`` when
that checkout is present (override with HUDIY_ROOT).
"""

import importlib.util
import math
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if "flasher" not in sys.modules:
    try:
        import flasher  # noqa: F401  (submodule mount on sys.path)
    except ImportError:
        spec = importlib.util.spec_from_file_location(
            "flasher", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
        module = importlib.util.module_from_spec(spec)
        sys.modules["flasher"] = module
        spec.loader.exec_module(module)

from flasher.vag_protocols import measuring
from flasher.vag_protocols.measuring import (
    GroupScheduler, MeasuringError, MeasuringSession, decode_group, decode_value,
)
from flasher.vag_protocols.tp2 import MessageTimeoutError


HUDIY_ROOT = Path(os.environ.get("HUDIY_ROOT", str(ROOT.parent / "RNS-E-Hudiy")))
HUDIY_CODING = HUDIY_ROOT / "tp2" / "tp2_coding.py"


def load_hudiy_coding():
    spec = importlib.util.spec_from_file_location("hudiy_tp2_coding", HUDIY_CODING)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TP2Coding


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeTransport:
    """Scripted KWP-level transport; ``handler(request) -> bytes`` or raises."""

    def __init__(self, handler, clock, latency=0.02):
        self.handler = handler
        self.clock = clock
        self.latency = latency
        self.sent = []
        self.keepalives = []
        self.disconnected = False
        self.pending = None

    def send(self, payload):
        self.sent.append(bytes(payload))
        self.pending = bytes(payload)

    def recv(self):
        self.clock.now += self.latency
        request, self.pending = self.pending, None
        return self.handler(request)

    def maybe_send_keep_alive(self, force=False):
        self.keepalives.append((self.clock.now, force))
        return True

    def disconnect(self):
        self.disconnected = True


def group_reply(group, triples=((1, 200, 50), (5, 10, 120), (6, 50, 250), (4, 1, 150))):
    return bytes([0x61, group]) + bytes(b for triple in triples for b in triple)


def default_handler(request):
    if request[0] == 0x10:
        return bytes([0x50, request[1]])
    if request[0] == 0x21:
        return group_reply(request[1])
    if request[0] == 0x3E:
        return b"\x7E"
    raise AssertionError(f"unexpected request {request.hex()}")


class Harness:
    def __init__(self, handler=default_handler, stop_after=None, stop_at=None, factory_error=None):
        self.clock = FakeClock()
        self.samples = []
        self.transports = []
        self.handler = handler
        self.stop_after = stop_after
        self.stop_at = stop_at
        self.factory_error = factory_error
        self.factory_calls = 0

    def factory(self, device, *, module, timeout, debug, log_fn):
        self.factory_calls += 1
        self.module = module
        if self.factory_error is not None:
            raise self.factory_error
        transport = FakeTransport(self.handler, self.clock)
        self.transports.append(transport)
        return transport

    def should_stop(self):
        if self.stop_after is not None and len(self.samples) >= self.stop_after:
            return True
        return self.stop_at is not None and self.clock.now >= self.stop_at

    def session(self, groups, **kwargs):
        kwargs.setdefault("on_sample", self.samples.append)
        return MeasuringSession(
            object(), 0x01, groups, should_stop=self.should_stop,
            transport_factory=self.factory, clock=self.clock.monotonic,
            wall_clock=lambda: 1.7e9 + self.clock.now, sleeper=self.clock.sleep,
            log_fn=lambda message: None, **kwargs)

    def sent(self):
        return [request for transport in self.transports for request in transport.sent]


class DecodeTests(unittest.TestCase):
    VALUES = (0, 1, 2, 3, 5, 10, 25, 48, 99, 100, 101, 126, 127, 128, 129, 200, 254, 255)

    @unittest.skipUnless(HUDIY_CODING.is_file(), "RNS-E-Hudiy checkout not present")
    def test_every_formula_matches_hudiy_tp2coding(self):
        coding = load_hudiy_coding()
        compared = 0
        for formula in range(256):
            for a in self.VALUES:
                for b in self.VALUES:
                    expected = coding.decode_value(formula, a, b)
                    got = decode_value(formula, a, b)
                    self.assertEqual(type(got[0]), type(expected[0]), (formula, a, b))
                    self.assertEqual(got, expected, (formula, a, b))
                    compared += 1
        self.assertEqual(compared, 256 * len(self.VALUES) ** 2)

    @unittest.skipUnless(HUDIY_CODING.is_file(), "RNS-E-Hudiy checkout not present")
    def test_decode_group_matches_hudiy_decode_block(self):
        coding = load_hudiy_coding()
        body = bytes([1, 200, 50, 5, 10, 120, 16, 0xF0, 0xA5, 17, 0x41, 0x42, 99, 1, 2, 7])
        expected = coding.decode_block(list(body))
        fields = decode_group(body)
        self.assertEqual([(f["value"], f["unit"], f["formula"]) for f in fields],
                         [(e["value"], e["unit"], e["type"]) for e in expected])

    def test_field_shape_and_full_response_acceptance(self):
        body = bytes([1, 200, 50, 5, 10, 120, 99, 0x12, 0x34])
        fields = decode_group(body)
        self.assertEqual(decode_group(b"\x61\x07" + body), fields)
        rpm, temp, unknown = fields
        self.assertEqual(rpm, {"index": 1, "formula": 1, "a": 200, "b": 50, "value": 2000.0,
                               "unit": "rpm", "numeric": True, "text": "2000"})
        self.assertEqual((temp["value"], temp["unit"], temp["text"]), (20.0, "°C", "20"))
        self.assertEqual(unknown["index"], 3)
        self.assertFalse(unknown["numeric"])
        self.assertEqual((unknown["text"], unknown["unit"]), ("0x1234", "Type_99"))

    def test_text_values_and_trailing_bytes(self):
        fields = decode_group(bytes([16, 0xF0, 0xA5, 10, 0, 0, 44, 3, 7, 6, 1]))
        self.assertEqual(len(fields), 3)  # incomplete trailing triple ignored
        self.assertEqual([f["text"] for f in fields], ["1010XXXX", "COLD", "3:07"])
        self.assertTrue(all(not f["numeric"] for f in fields))
        self.assertEqual(decode_group(bytes([6, 50, 251]))[0]["text"], "12.55")
        self.assertEqual(decode_group(b""), [])


class SchedulerTests(unittest.TestCase):
    def test_round_robin_unlimited(self):
        clock = FakeClock()
        scheduler = GroupScheduler(clock=clock.monotonic)
        scheduler.configure_groups([3, 1, 2])
        order = []
        for _ in range(6):
            group = scheduler.select()
            scheduler.started(group)
            scheduler.completed(group, timestamp=0, duration_ms=1, success=True)
            order.append(group)
        self.assertEqual(order, [1, 2, 3, 1, 2, 3])
        self.assertIsNone(scheduler.select(blocked=[1, 2, 3]))

    def test_interval_and_rate(self):
        clock = FakeClock()
        scheduler = GroupScheduler(clock=clock.monotonic)
        scheduler.configure_groups([5], interval_ms=100)
        for _ in range(5):
            self.assertEqual(scheduler.select(), 5)
            scheduler.started(5)
            self.assertIsNone(scheduler.select())
            clock.now += 0.02
            scheduler.completed(5, timestamp=0, duration_ms=20, success=True)
            clock.now += 0.05
            self.assertIsNone(scheduler.select())
            clock.now += 0.031
        snap = scheduler.snapshot()["5"]
        self.assertEqual(snap["observed_count"], 5)
        # The rate includes the idle age since the last success.
        self.assertAlmostEqual(snap["achieved_hz"], 4 / (4 * 0.101 + 0.081), places=6)


class MeasuringSessionTests(unittest.TestCase):
    def test_polls_round_robin_and_disconnects(self):
        harness = Harness(stop_after=6)
        summary = harness.session([3, 1]).run()
        sent = harness.sent()
        self.assertEqual(sent[0], b"\x10\x89")
        self.assertEqual([r for r in sent if r[0] == 0x21],
                         [b"\x21\x01", b"\x21\x03"] * 3)
        self.assertEqual(harness.module, 0x01)
        self.assertTrue(harness.transports[0].disconnected)
        sample = harness.samples[0]
        self.assertEqual(set(sample), {"group", "time", "wall_time", "fields", "raw",
                                       "error", "round_trip_ms"})
        self.assertEqual(sample["group"], 1)
        self.assertIsNone(sample["error"])
        self.assertEqual(sample["raw"], group_reply(1).hex())
        self.assertEqual([f["value"] for f in sample["fields"]][:2], [2000.0, 20.0])
        self.assertAlmostEqual(sample["round_trip_ms"], 20.0)
        self.assertEqual(summary["samples"], 6)
        self.assertEqual(summary["errors"], 0)
        self.assertEqual(summary["reconnects"], 0)
        self.assertEqual(set(summary["achieved_hz"]), {1, 3})
        self.assertGreater(summary["achieved_hz"][1], 0)

    def test_stop_before_start_opens_nothing(self):
        harness = Harness(stop_after=0)
        summary = harness.session([1]).run()
        self.assertEqual(harness.factory_calls, 0)
        self.assertEqual(summary, {"samples": 0, "errors": 0, "reconnects": 0,
                                   "achieved_hz": {1: None}})

    def test_session_nrc_is_tolerated_and_session_none_skips_it(self):
        def handler(request):
            if request[0] == 0x10:
                return b"\x7f\x10\x12"
            return default_handler(request)
        harness = Harness(handler, stop_after=2)
        harness.session([1]).run()
        self.assertEqual(harness.sent()[:2], [b"\x10\x89", b"\x21\x01"])

        harness = Harness(stop_after=1)
        harness.session([1], session=None).run()
        self.assertEqual(harness.sent(), [b"\x21\x01"])

    def test_nrc_group_cools_down_after_three_failures(self):
        def handler(request):
            if request == b"\x21\x02":
                return b"\x7f\x21\x31"
            return default_handler(request)
        harness = Harness(handler, stop_at=1000.0 + 29.0)
        summary = harness.session([1, 2], interval_ms=100).run()
        reads = [r for r in harness.sent() if r[0] == 0x21]
        self.assertEqual(reads.count(b"\x21\x02"), 3)
        self.assertGreater(reads.count(b"\x21\x01"), 100)
        failed = [s for s in harness.samples if s["group"] == 2]
        self.assertEqual(len(failed), 3)
        self.assertEqual(failed[0]["error"], "Request rejected (NRC 0x31)")
        self.assertEqual((failed[0]["fields"], failed[0]["raw"]), ([], "7f2131"))
        self.assertEqual(summary["errors"], 3)
        self.assertIsNone(summary["achieved_hz"][2])
        self.assertEqual(harness.factory_calls, 1)

        # After the 30 s cooldown it gets three more tries, then cools again.
        harness = Harness(handler, stop_at=1000.0 + 35.0)
        harness.session([1, 2], interval_ms=100).run()
        self.assertEqual([r for r in harness.sent() if r[0] == 0x21].count(b"\x21\x02"), 6)

    def test_ten_transport_errors_force_reconnect(self):
        state = {"fail": True}

        def handler(request):
            if request[0] == 0x21 and state["fail"]:
                raise MessageTimeoutError("no answer")
            return default_handler(request)

        harness = Harness(handler)
        original = harness.factory

        def factory(*args, **kwargs):
            if harness.factory_calls >= 1:
                state["fail"] = False
            return original(*args, **kwargs)

        harness.factory = factory
        harness.stop_after = 14
        summary = harness.session([1, 2, 3, 4]).run()
        self.assertEqual(harness.factory_calls, 2)
        self.assertTrue(harness.transports[0].disconnected)
        first_reads = [r for r in harness.transports[0].sent if r[0] == 0x21]
        self.assertEqual(len(first_reads), 10)
        self.assertTrue(any(force for _, force in harness.transports[0].keepalives))
        self.assertEqual(summary["errors"], 10)
        self.assertEqual(summary["samples"], 4)
        self.assertEqual(summary["reconnects"], 1)
        errors = [s for s in harness.samples if s["error"]]
        self.assertTrue(errors[0]["error"].startswith("no answer"))
        # The reconnect waits the reconnect delay after the failed channel.
        self.assertEqual(harness.transports[1].sent[0], b"\x10\x89")

    def test_idle_keepalive_sends_tester_present(self):
        harness = Harness(stop_at=1000.0 + 4.5)
        harness.session([1], interval_ms=10000).run()
        sent = harness.sent()
        self.assertEqual([r for r in sent if r[0] == 0x21], [b"\x21\x01"])
        self.assertIn(b"\x3e", sent)
        self.assertGreater(len(harness.transports[0].keepalives), 10)

    def test_unreachable_module_raises_after_attempts(self):
        harness = Harness(factory_error=MessageTimeoutError("no channel"), stop_at=1000.0 + 600)
        with self.assertRaises(MeasuringError):
            harness.session([1]).run()
        self.assertEqual(harness.factory_calls, 3)

    def test_malformed_and_incomplete_responses_are_errors(self):
        def handler(request):
            if request == b"\x21\x01":
                return b"\x61\x01\x01\xc8"
            if request == b"\x21\x02":
                return b"\x61\x09\x01\xc8\x32"
            return default_handler(request)
        harness = Harness(handler, stop_after=2)
        harness.session([1, 2]).run()
        first, second = harness.samples
        self.assertEqual(first["error"], "Incomplete or empty measuring-group payload")
        self.assertEqual(second["error"], "Unexpected measuring-group response")

    def test_validation(self):
        with self.assertRaises(ValueError):
            MeasuringSession(object(), 0x01, [])
        with self.assertRaises(ValueError):
            MeasuringSession(object(), 0x01, [256])
        with self.assertRaises(ValueError):
            MeasuringSession(object(), 0x80, [1])


if __name__ == "__main__":
    unittest.main()
