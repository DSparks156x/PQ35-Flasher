"""Offline checks for the PQ EPS flash lifecycle; no CAN hardware is used.

Run from the repository root: python -m pytest tests (or python -m unittest).
The repository is the `flasher` package itself, so it is registered under that
name when it is not already importable (for example from a submodule mount).
"""

import argparse
import contextlib
import dataclasses
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

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

from flasher import engine
from flasher.controllers.pq_eps import protocol
from flasher.controllers.pq_eps.protocol import PQEPSFlasher


def prepared(start, end, **extra):
    region = bytes((i * 7) & 0xFF for i in range(end - start + 1))
    return {"region": region, "metadata": dict(
        start_addr=start, end_addr=end, size=len(region), checksum=sum(region) & 0xFFFF, **extra)}


class FakeKWP:
    """Records every request a flash sends, in order."""

    def __init__(self, calls):
        self.calls = calls

    def request_download(self, start, size):
        self.calls.append(("34", start, size))
        return 0xF2

    def routine(self, routine, payload):
        self.calls.append(("31", routine))

    def routine_result(self, routine):
        self.calls.append(("33", routine))
        return bytes([0x73, routine, 0])

    def transfer(self, block):
        self.calls.append(("36",))

    def transfer_exit(self):
        self.calls.append(("37",))

    def raw(self, request):
        self.calls.append((request.hex(),))


class FakeSecurity:
    def __init__(self, calls):
        self.calls = calls

    def unlock(self, kwp):
        self.calls.append(("27",))


class FakeDevice:
    def close(self):
        pass


class FakeTransport:
    keepalive_after_response = False

    def disconnect(self):
        pass


class SingleBlockFlashTests(unittest.TestCase):
    def test_block_flash_requests_the_download_once(self):
        calls = []
        flasher = PQEPSFlasher(device=FakeDevice())
        flasher.profile = dataclasses.replace(
            flasher.profile,
            kwp_factory=lambda tp, log, debug: FakeKWP(calls),
            verify_programming_channel=lambda tp: calls.append(("verify",)),
            programming_security=FakeSecurity(calls),
            identify=lambda kwp, tp: {"sw_version": "3305", "part_number": "8J0909144P",
                                      "flash_status": 0})
        flasher.reconnect_tp = lambda *a, **k: FakeTransport()
        with patch.object(engine.time, "sleep"):
            flasher.flash_prepared(prepared(0x5D000, 0x5DFFF), recovery=True)
        self.assertEqual([c for c in calls if c != ("36",)], [
            ("verify",), ("27",), ("34", 0x5D000, 0x1000), ("31", 0xC4), ("33", 0xC4),
            ("37",), ("31", 0xC5), ("33", 0xC5), ("82",)])


class ApplicationFlashBlockedTests(unittest.TestCase):
    def args(self, **values):
        defaults = dict(correct_checksum=False, read_eps_can_config=False, read_eps_supply=False,
                        read_eps_assist=False, read_eps_motion=False, read_eps_faults=False,
                        read_eeprom=False, ident_only=False, readout=False, input="rack.bin",
                        start=0x0A000, end=0x5FFFF, recovery=False)
        defaults.update(values)
        return argparse.Namespace(**defaults)

    def check(self, **values):
        parser = argparse.ArgumentParser()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                protocol.validate_cli(parser, self.args(**values))
            except SystemExit:
                return err.getvalue()
        return None

    def test_full_flash_is_refused(self):
        self.assertIn("disabled", self.check())

    def test_application_only_range_is_refused(self):
        self.assertIn("disabled", self.check(end=0x5BFFF))

    def test_recovery_may_still_try(self):
        self.assertIsNone(self.check(recovery=True))

    def test_block_flashes_are_unaffected(self):
        for start, end in ((0x5C000, 0x5DFFF), (0x5D000, 0x5DFFF), (0x5E000, 0x5EFFF)):
            self.assertIsNone(self.check(start=start, end=end))


class EpsProfileTests(unittest.TestCase):
    def test_eps_flash_transport_uses_legacy_acks(self):
        profile = PQEPSFlasher(device=object()).profile
        transport = profile.transport_factory(object(), module=0x09, timeout=2.0,
                                              auto_open=False)
        self.assertTrue(transport.legacy_ack)


if __name__ == "__main__":
    unittest.main()
