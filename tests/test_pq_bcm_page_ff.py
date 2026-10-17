"""Offline checks for the read-only BCM page FF dump; no CAN hardware is used.

Run from the repository root: python -m pytest tests (or python -m unittest).
The repository is the `flasher` package itself, so it is registered under that
name when it is not already importable (for example from a submodule mount).
"""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
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

from flasher import readout as readout_module, runner
from flasher.controllers.pq_bcm import codec
from flasher.controllers.pq_bcm.protocol import PQBCMReader, validate_range
from flasher.vag_protocols import tp2


PART = b"\x62\xf1\x87" + b"8P0907063E "
VERSION = b"\x62\xf1\x89" + b"0575"
AUTH = [b"\x50\x89", b"\x67\x03\x01\x02\x03\x04", b"\x67\x04\x34", b"\x50\x86"]
PAGE = bytes((i * 7 + (i >> 8)) & 0xFF for i in range(codec.PAGE_FF_SIZE))
READ_ONLY_SIDS = {0x10, 0x22, 0x27, 0x35, 0x36, 0x37}


def page_replies(page=PAGE):
    replies = []
    for offset in range(0, len(page), codec.PAGE_FF_CHUNK):
        replies += [b"\x75\x43", b"\x76" + page[offset:offset + codec.PAGE_FF_CHUNK], b"\x77"]
    return replies


class ScriptedTransport:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.disconnected = False

    def send(self, payload):
        self.sent.append(bytes(payload))

    def recv(self):
        if not self.replies:
            raise AssertionError("Unexpected receive")
        return self.replies.pop(0)

    def disconnect(self):
        self.disconnected = True


def setups(sent):
    return [(int.from_bytes(r[1:4], "big"), int.from_bytes(r[5:8], "big"))
            for r in sent if r[:1] == b"\x35"]


class PageFFProtocolTests(unittest.TestCase):
    def test_sweeps_exact_window_in_256_chunks_read_only(self):
        transport = ScriptedTransport([PART, VERSION, *AUTH, *page_replies()])
        reader = PQBCMReader(transport)
        reader.identification()
        progress = []
        data = reader.read_page_ff(progress_cb=lambda *a: progress.append(a))

        self.assertEqual(data, PAGE)
        self.assertEqual(len(data), 16384)
        requested = setups(transport.sent)
        self.assertEqual(len(requested), 256)
        self.assertEqual(requested, [(0x80C000 + i * 0x40, 0x40) for i in range(256)])
        self.assertEqual(requested[0][0], 0x80C000)
        self.assertEqual(requested[-1][0] + requested[-1][1], 0x810000)
        self.assertEqual(progress[-1], (256, 256, 0x80FFC0))
        self.assertTrue(all(r[0] in READ_ONLY_SIDS for r in transport.sent))
        self.assertTrue(all(r == b"\x36" for r in transport.sent if r[0] == 0x36))
        self.assertEqual(transport.sent.count(b"\x27\x03"), 1)
        self.assertFalse(transport.replies)

    def test_out_of_window_or_oversized_uploads_are_refused(self):
        for address, length in ((0x80BFC0, 0x40), (0x80FFC1, 0x40), (0x80C000, 0x41),
                                (0x80C000, 0x200), (0x810000, 1), (0x7FC000, 0x40),
                                (0x80C000, 0), (0x000000, 0x40)):
            with self.subTest(address=hex(address), length=length):
                with self.assertRaises(ValueError):
                    validate_range(address, length)
                with self.assertRaises(codec.ProtocolError):
                    codec.window_setup_request(address, length)

        transport = ScriptedTransport([PART, VERSION, *AUTH])
        reader = PQBCMReader(transport)
        reader.identification()
        reader.enter()
        sent_before = list(transport.sent)
        with self.assertRaises(ValueError):
            reader.read_upload(0x80FFC1, 0x40)
        with self.assertRaises(ValueError):
            reader.read_upload(0x80C000, 0x41)
        # Raw requests outside the setup state machine, and writes, never reach the transport.
        for request in (b"\x35\x80\xc0\x00\x00\x00\x00\x40",
                        b"\x34\x80\xc0\x00\x00\x00\x00\x40",
                        b"\x36\x00", b"\x31\x01", b"\x2e\x06\x10\x00\x00\x00"):
            with self.subTest(request=request.hex()):
                with self.assertRaises(ValueError):
                    reader.exchange(request)
        self.assertEqual(transport.sent, sent_before)

    def test_page_ff_requires_identity(self):
        reader = PQBCMReader(ScriptedTransport([]))
        with self.assertRaises(Exception):
            reader.read_page_ff()

    def test_named_target_encoding_unchanged(self):
        self.assertEqual(codec.setup_request("resident_prefix"), bytes.fromhex("3580c00000000004"))
        self.assertEqual(validate_range(0x80C000, 4), None)
        self.assertEqual(codec.upload_target(0x8034B1, 4), "sensor")
        with self.assertRaises(ValueError):
            validate_range(0x8034B1, 5)

    def test_named_target_read_still_works(self):
        transport = ScriptedTransport([PART, VERSION, *AUTH,
                                       b"\x75\x43", b"\x76\x01\x02\x03\x04", b"\x77"])
        reader = PQBCMReader(transport)
        reader.identification()
        reader.enter()
        self.assertEqual(reader.read_target("sensor"), b"\x01\x02\x03\x04")
        self.assertEqual(transport.sent[-3], bytes.fromhex("358034b100000004"))


class PageFFRunnerTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_flag_is_bcm_only_and_exclusive(self):
        for argv in (["--module", "eps", "--read-bcm-pageff"],
                     ["--module", "awd", "--read-bcm-pageff"],
                     ["--module", "bcm", "--read-bcm-pageff", "--readout"],
                     ["--module", "bcm", "--read-bcm-pageff", "--input", "x.bin"],
                     ["--module", "bcm", "--read-bcm-pageff", "--bcm-target", "sensor"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    runner.main(argv)

    def test_dry_run_sends_nothing(self):
        with patch.object(runner, "open_adapter", side_effect=AssertionError("no adapter")):
            code, out, _ = self.run_main(["--module", "bcm", "--read-bcm-pageff", "--dry-run"])
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual((plan["chunks"], plan["chunk"]), (256, 0x40))
        self.assertFalse(plan["hardware_access"])

    def scripted(self, replies):
        holder = {}

        def factory(device, **kwargs):
            holder["transport"] = ScriptedTransport(replies)
            return holder["transport"]
        return holder, factory

    def test_end_to_end_saves_bin_and_sidecar(self):
        post_leave = [b"\x50\x89", PART, VERSION]
        holder, factory = self.scripted([PART, VERSION, *AUTH, *page_replies(), *post_leave])
        progress = []
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(tp2, "TP2Transport", factory), \
                patch.object(runner, "open_adapter", lambda args: _FakeDevice()), \
                patch.object(runner, "_progress", lambda *a: progress.append(a)):
            code, out, err = self.run_main(["--module", "bcm", "--read-bcm-pageff", "--out", tmp])
            self.assertEqual(code, 0, err)
            path = Path(out.strip().splitlines()[-1])
            self.assertTrue(path.is_absolute())
            self.assertRegex(path.name, r"^8P0907063E_0575_pageFF_\d{8}T\d{6}Z\.bin$")
            self.assertEqual(path.read_bytes(), PAGE)
            sidecar = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
            self.assertEqual(sidecar["status"], "ok")
            self.assertEqual(sidecar["chunk_count"], 256)
            self.assertEqual(sidecar["chunks_completed"], 256)
            self.assertEqual(sidecar["size"], 16384)
            self.assertEqual(sidecar["identification"]["part_number"], "8P0907063E")
            self.assertIn("identification_after", sidecar)
            self.assertFalse(sidecar["firmware_writes"])
            import hashlib
            self.assertEqual(sidecar["sha256"], hashlib.sha256(PAGE).hexdigest().upper())
            self.assertTrue((path.parent / sidecar["events_file"]).exists())
        self.assertTrue(holder["transport"].disconnected)
        self.assertTrue(any("chunk 256/256" in str(a[2]) for a in progress))
        self.assertTrue(all(r[0] in READ_ONLY_SIDS for r in holder["transport"].sent))

    def test_failure_exits_nonzero_and_writes_no_image(self):
        replies = [PART, VERSION, *AUTH, *page_replies()[:30], b"\x7f\x35\x22", b"\x77",
                   b"\x50\x89", PART, VERSION]
        _, factory = self.scripted(replies)
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(tp2, "TP2Transport", factory), \
                patch.object(runner, "open_adapter", lambda args: _FakeDevice()), \
                patch.object(runner, "_progress", lambda *a: None):
            code, out, err = self.run_main(["--module", "bcm", "--read-bcm-pageff",
                                            "--out", str(Path(tmp) / "page.bin")])
            self.assertEqual(code, 1)
            self.assertFalse((Path(tmp) / "page.bin").exists())
            sidecar = json.loads((Path(tmp) / "page_failed.json").read_text(encoding="utf-8"))
            self.assertEqual(sidecar["status"], "failed")
            self.assertEqual(sidecar["chunks_completed"], 10)
        self.assertIn("Page FF read failed", err)


class _FakeDevice:
    def close(self):
        pass


if __name__ == "__main__":
    unittest.main()
