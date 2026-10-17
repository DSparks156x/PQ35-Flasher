"""Offline checks that the BCM identifies via service 22, never KWP 1A.

The BCM (8P0907063E/0575) has no 1A service; any 1A returns 7F 1A 11. These
tests script the transport, so no CAN hardware is used.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_pq_bcm_page_ff import AUTH, PART, VERSION, ScriptedTransport, _FakeDevice, page_replies

from flasher import runner
from flasher.controllers.pq_bcm import protocol as bcm_protocol
from flasher.controllers.registry import family_for_module
from flasher.vag_protocols import tp2


IDENT_REQUESTS = [b"\x22\xf1\x87", b"\x22\xf1\x89"]


class NRCForOneA(ScriptedTransport):
    """Answers any 1A request like the real BCM: 7F 1A 11 serviceNotSupported."""

    def recv(self):
        if self.sent and self.sent[-1][:1] == b"\x1a":
            return b"\x7f\x1a\x11"
        return super().recv()


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = runner.main(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def scripted_car(replies, transport_class=NRCForOneA):
    holder = {}

    def factory(device, **kwargs):
        holder["module"] = kwargs.get("module")
        holder["transport"] = transport_class(replies)
        return holder["transport"]

    with patch.object(tp2, "TP2Transport", factory), \
            patch.object(bcm_protocol, "TP2Transport", factory), \
            patch.object(runner, "open_adapter", lambda args: _FakeDevice()), \
            patch.object(runner, "_progress", lambda *a: None):
        yield holder


@contextlib.contextmanager
def temporary_cwd():
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            os.chdir(previous)


class BCMIdentifyTests(unittest.TestCase):
    def test_read_identification_uses_service_22_only(self):
        transport = NRCForOneA([PART, VERSION])
        info = runner.read_identification(family_for_module("bcm"), transport)
        self.assertEqual(transport.sent, IDENT_REQUESTS)
        self.assertEqual((info["part_number"], info["sw_version"]), ("8P0907063E", "0575"))
        family_for_module("bcm").validate_identification(info)

    def test_ident_only_prints_flat_identity_without_session_security_or_files(self):
        with temporary_cwd() as cwd, scripted_car([PART, VERSION]) as car:
            for _ in range(2):  # repeatable: no output folder left behind
                code, out, err = run_main(["--module", "bcm", "--ident-only"])
                self.assertEqual(code, 0, err)
                self.assertEqual(car["transport"].sent, IDENT_REQUESTS)
                self.assertTrue(car["transport"].disconnected)
                self.assertEqual(list(cwd.iterdir()), [])
        self.assertEqual(car["module"], 0x20)
        result = json.loads(out)
        self.assertEqual(result["part_number"], "8P0907063E")
        self.assertEqual(result["software_part_number"], "8P0907063E")
        self.assertEqual(result["sw_version"], "0575")
        self.assertTrue(result["connected"])
        self.assertEqual((result["module"], result["controller_family"]), (0x20, "pq-bcm"))
        self.assertEqual(result["raw_f187"], PART.hex())

    def test_ident_only_fails_cleanly_on_wrong_identity(self):
        other = b"\x62\xf1\x87" + b"1K0907063A "
        with temporary_cwd(), scripted_car([other, VERSION]) as car:
            with self.assertRaises(Exception):
                run_main(["--module", "bcm", "--ident-only"])
        self.assertNotIn(b"\x1a", [r[:1] for r in car["transport"].sent])
        self.assertTrue(car["transport"].disconnected)

    def test_ident_only_dry_run_touches_no_adapter(self):
        with patch.object(runner, "open_adapter", side_effect=AssertionError("no adapter")):
            code, out, _ = run_main(["--module", "bcm", "--ident-only", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["requests"], ["22f187", "22f189"])

    def test_pageff_after_identify_never_sends_1a(self):
        replies = [PART, VERSION, *AUTH, *page_replies(), b"\x50\x89", PART, VERSION]
        with tempfile.TemporaryDirectory() as tmp, scripted_car(replies) as car:
            code, out, err = run_main(["--module", "bcm", "--read-bcm-pageff", "--out", tmp])
            self.assertEqual(code, 0, err)
            self.assertTrue(Path(out.strip().splitlines()[-1]).is_file())
        sent = car["transport"].sent
        self.assertEqual(sent[:2], IDENT_REQUESTS)  # identity gate first
        self.assertEqual(sent[2:6], [b"\x10\x89", b"\x27\x03",
                                     b"\x27\x04\x01\x02\xa7\x21", b"\x10\x86"])
        self.assertNotIn(0x1A, {r[0] for r in sent})
        self.assertNotIn(b"\x10\x85", sent)  # never the programming handoff
        self.assertTrue({r[0] for r in sent} <= {0x10, 0x22, 0x27, 0x35, 0x36, 0x37})

    def test_readout_accepts_existing_empty_out_directory(self):
        replies = [PART, VERSION, *AUTH, b"\x75\x43", b"\x76\x01\x02\x03\x04", b"\x77",
                   b"\x50\x89"]
        with tempfile.TemporaryDirectory() as tmp, scripted_car(replies):
            code, _, err = run_main(["--module", "bcm", "--readout", "--bcm-target", "sensor",
                                     "--out", tmp])
            self.assertEqual(code, 0, err)
            self.assertEqual((Path(tmp) / "sensor.bin").read_bytes(), b"\x01\x02\x03\x04")
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):  # non-empty folder
                run_main(["--module", "bcm", "--readout", "--out", tmp])


class OtherFamiliesStillUse1ATests(unittest.TestCase):
    IDENT_9B = (b"\x5a\x9b" + b"1K0909144J  " + b"3001" + b"\x00" * 10
                + b"EPS_ZFLS Kl.4  ")
    STATUS_9C = b"\x5a\x9c\x00\x01\x01\x00\x10\x01\x01\x00\x00"

    def test_eps_identify_keeps_1a_9b_9c(self):
        transport = ScriptedTransport([self.IDENT_9B, self.STATUS_9C])
        info = runner.read_identification(family_for_module("eps"), transport)
        self.assertEqual(transport.sent, [b"\x1a\x9b", b"\x1a\x9c"])
        self.assertEqual(info["part_number"], "1K0909144J")


if __name__ == "__main__":
    unittest.main()
