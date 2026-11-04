"""Offline DTC parsing, measuring catalog and generic engine/TCU family checks.

No CAN hardware: KWP runs over scripted transports and the runner's adapter
and TP2 transport are patched.
"""

import contextlib
import importlib.util
import io
import json
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

from flasher import measuring_catalog, runner
from flasher.controllers.registry import FAMILIES, family_for_module, get_family
from flasher.vag_protocols import dtc, tp2
from flasher.vag_protocols.kwp import KWPClient


class MapTransport:
    """Answers each request from a dict keyed by request bytes."""

    def __init__(self, replies):
        self.replies = dict(replies)
        self.sent = []
        self.disconnected = False

    def send(self, payload):
        self.sent.append(bytes(payload))

    def recv(self):
        request = self.sent[-1]
        if request not in self.replies:
            raise AssertionError(f"unexpected request {request.hex()}")
        return self.replies[request]

    def disconnect(self):
        self.disconnected = True


def kwp_for(replies):
    transport = MapTransport(replies)
    return KWPClient(transport, debug=False), transport


NRC_18 = b"\x7f\x18\x12"


class DTCTests(unittest.TestCase):
    def test_read_by_status_three_byte_entries(self):
        # 17965 (P1557) status 0x23, 00573 status 0x60.
        kwp, transport = kwp_for({b"\x18\x02\xff\x00": bytes.fromhex("5802462d23023d60")})
        result = dtc.read_dtcs(kwp)
        self.assertEqual(transport.sent, [b"\x18\x02\xff\x00"])
        self.assertEqual(result["method"], "18 02 FF 00")
        self.assertIsNone(result["error"])
        self.assertEqual(result["raw"], "5802462d23023d60")
        first, second = result["codes"]
        self.assertEqual((first["code"], first["code_text"], first["p_code"]), (17965, "17965", "P1557"))
        self.assertEqual(first["status"], 0x23)
        self.assertEqual(first["status_text"], f"status 0x{first['status']:02X}")
        self.assertEqual((second["code_text"], second["p_code"]), ("00573", None))

    def test_no_codes(self):
        kwp, _ = kwp_for({b"\x18\x02\xff\x00": b"\x58\x00"})
        result = dtc.read_dtcs(kwp)
        self.assertEqual((result["codes"], result["error"], result["count"]), ([], None, 0))

    def test_fallback_chain_to_service_13(self):
        kwp, transport = kwp_for({
            b"\x18\x02\xff\x00": NRC_18,
            b"\x18\x00\xff\x00": NRC_18,
            b"\x13": bytes.fromhex("5301412c"),
        })
        result = dtc.read_dtcs(kwp)
        self.assertEqual(transport.sent, [b"\x18\x02\xff\x00", b"\x18\x00\xff\x00", b"\x13"])
        self.assertEqual(result["method"], "13")
        self.assertEqual(result["codes"][0]["code"], 0x412C)
        self.assertEqual(result["codes"][0]["code_text"], "16684")
        self.assertEqual(result["codes"][0]["p_code"], "P0300")
        self.assertEqual(result["codes"][0]["status_text"], "")

    def test_fallback_to_obd_mode_03_and_all_rejected(self):
        replies = {b"\x18\x02\xff\x00": NRC_18, b"\x18\x00\xff\x00": NRC_18,
                   b"\x13": b"\x7f\x13\x11", b"\x03": bytes.fromhex("43010301")}
        kwp, _ = kwp_for(replies)
        result = dtc.read_dtcs(kwp)
        self.assertEqual(result["method"], "03")
        self.assertEqual([c["code_text"] for c in result["codes"]], ["P0301"])

        replies[b"\x03"] = b"\x7f\x03\x11"
        kwp, _ = kwp_for(replies)
        result = dtc.read_dtcs(kwp)
        self.assertEqual(result["codes"], [])
        self.assertIn("NRC 0x11", result["error"])
        self.assertEqual(result["raw"], "7f0311")

    def test_short_response_keeps_complete_entries(self):
        kwp, _ = kwp_for({b"\x18\x02\xff\x00": bytes.fromhex("5802462d23023d")})
        result = dtc.read_dtcs(kwp)
        self.assertEqual(len(result["codes"]), 1)
        self.assertIn("length mismatch", result["error"])

    def test_freeze_frame_optional(self):
        kwp, transport = kwp_for({
            b"\x18\x02\xff\x00": bytes.fromhex("5801462d23"),
            b"\x12\x00\x04\x46\x2d": bytes.fromhex("52462d0300123458322e7f4e0bb8"),
        })
        result = dtc.read_dtcs(kwp, freeze_frames=True)
        frame = result["codes"][0]["freeze_frame"]
        self.assertEqual([(f["label"], f["value"]) for f in frame["fields"]],
                         [("Mileage", 0x001234),
                          ("Speed", 50), ("Voltage", 12.7), ("Engine Speed", 3000)])

    def test_clear(self):
        kwp, transport = kwp_for({b"\x14\xff\x00": b"\x54\xff\x00"})
        self.assertEqual(dtc.clear_dtcs(kwp), {"cleared": True, "raw": "54ff00", "error": None})
        self.assertEqual(transport.sent, [b"\x14\xff\x00"])
        kwp, _ = kwp_for({b"\x14\xff\x00": b"\x7f\x14\x22"})
        result = dtc.clear_dtcs(kwp)
        self.assertFalse(result["cleared"])
        self.assertIn("NRC 0x22", result["error"])

    def test_code_helpers(self):
        self.assertEqual(dtc.vag_p_code(16486), "P0102")
        self.assertEqual(dtc.vag_p_code(17544), "P1136")
        self.assertIsNone(dtc.vag_p_code(16384 + 1000))
        self.assertIsNone(dtc.vag_p_code(1))
        self.assertEqual(dtc.obd_code_text(0x4123), "C0123")
        self.assertEqual(dtc.decode_dtc_status(0), ["No Status"])


class CatalogTests(unittest.TestCase):
    def test_shape_and_modules(self):
        for module in (0x01, 0x02, 0x0A):
            values = measuring_catalog.values_for_module(module)
            self.assertTrue(values)
            ids = [value["id"] for value in values]
            self.assertEqual(len(ids), len(set(ids)))
            for value in values:
                self.assertTrue({"id", "name", "unit", "group", "field", "category",
                                 "module"} <= set(value))
                self.assertEqual(value["module"], module)
                self.assertGreaterEqual(value["field"], 1)
                self.assertEqual([value["group"], value["field"]], value["locations"][0])
        self.assertEqual(measuring_catalog.values_for_module(0x09), [])

    def test_known_locations_and_categories(self):
        boost = measuring_catalog.value_by_id("engine.boost.actual_absolute", 0x01)
        self.assertEqual((boost["group"], boost["field"], boost["unit"], boost["category"]),
                         (115, 4, "mbar", "Boost"))
        haldex = {v["id"]: v for v in measuring_catalog.values_for_module(0x0A)}
        self.assertEqual(sorted({v["group"] for v in haldex.values()}), [1, 3, 5])
        self.assertEqual(haldex["awd.oil_temperature"]["category"], "Haldex")
        tcu = measuring_catalog.values_for_module(0x02)
        self.assertTrue(all(v["category"] == "Transmission" for v in tcu))

    def test_groups_for(self):
        self.assertEqual(measuring_catalog.groups_for(
            ["engine.boost.actual_absolute", "engine.rpm", "engine.n75_duty", "engine.rpm"], 0x01),
            [1, 114, 115])
        self.assertEqual(measuring_catalog.groups_for([], 0x01), [])
        with self.assertRaises(ValueError):
            measuring_catalog.groups_for(["awd.oil_temperature"], 0x01)


class _FakeDevice:
    def close(self):
        pass


IDENT_9B = (b"\x5a\x9b" + b"06F906056AK " + b"0040" + b"\x00" * 10 + b"2.0l R4/4V TFSI  ")
IDENT_9C = bytes.fromhex("5a9c0001020000000000")


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = runner.main(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def scripted_car(replies):
    holder = {}

    def factory(device, **kwargs):
        holder["module"] = kwargs.get("module")
        holder["transport"] = MapTransport(replies)
        return holder["transport"]

    with patch.object(tp2, "TP2Transport", factory), \
            patch.object(runner, "open_adapter", lambda args: _FakeDevice()):
        yield holder


class GenericFamilyTests(unittest.TestCase):
    def test_registry(self):
        engine = family_for_module("ecu")
        self.assertEqual((engine.name, engine.module), ("engine", 0x01))
        self.assertEqual(family_for_module("tcu").name, "transmission")
        self.assertEqual(family_for_module("gearbox").module, 0x02)
        for name in ("engine", "transmission"):
            family = get_family(name)
            self.assertEqual(family.operations, {"identify", "log", "dtc", "dtc_clear"})
            self.assertEqual(family.patches_module, "")
            self.assertTrue(family.matches_identification({"part_number": "06F906056AK"}))
            self.assertFalse(family.matches_identification({"part_number": ""}))
            family.validate_identification({"part_number": "anything"})
            protocol = family.protocol()
            for hook in ("add_cli_arguments", "apply_defaults", "validate_cli"):
                self.assertTrue(callable(getattr(protocol, hook)))
        haldex = get_family("haldex-gen4")
        self.assertTrue(haldex.supports("log"))
        self.assertEqual(haldex.operations, {"identify", "readout", "flash", "log"})
        self.assertFalse(haldex.matches_identification({"part_number": "06F906056AK"}))
        with self.assertRaises(ValueError):
            haldex.validate_identification({"part_number": "06F906056AK"})
        self.assertEqual(len({f.module for f in FAMILIES}), len(FAMILIES))

    def test_engine_ident_only_uses_default_kwp_path(self):
        with scripted_car({b"\x1a\x9b": IDENT_9B, b"\x1a\x9c": IDENT_9C}) as car:
            code, out, err = run_main(["--module", "engine", "--ident-only"])
        self.assertEqual(code, 0, err)
        self.assertEqual(car["module"], 0x01)
        self.assertEqual(car["transport"].sent, [b"\x1a\x9b", b"\x1a\x9c"])
        self.assertTrue(car["transport"].disconnected)
        result = json.loads(out)
        self.assertEqual((result["part_number"], result["controller_family"]),
                         ("06F906056AK", "engine"))

    def test_read_and_clear_dtcs_cli(self):
        replies = {b"\x10\x89": b"\x7f\x10\x12",
                   b"\x18\x02\xff\x00": bytes.fromhex("5801462d23"),
                   b"\x14\xff\x00": b"\x54\xff\x00"}
        with scripted_car(replies) as car:
            code, out, err = run_main(["--module", "tcu", "--read-dtcs"])
        self.assertEqual(code, 0, err)
        self.assertEqual(car["module"], 0x02)
        self.assertEqual(car["transport"].sent, [b"\x10\x89", b"\x18\x02\xff\x00"])
        self.assertTrue(car["transport"].disconnected)
        result = json.loads(out)
        self.assertEqual(result["codes"][0]["code_text"], "17965")
        self.assertEqual(result["controller_family"], "transmission")

        with scripted_car(replies) as car:
            code, out, err = run_main(["--module", "engine", "--clear-dtcs"])
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["cleared"])

    def test_cli_rejections(self):
        for argv in (["--module", "engine"],  # flash is not an engine operation
                     ["--module", "engine", "--readout"],
                     ["--module", "engine", "--ident-only", "--input", "x.bin"],
                     ["--module", "engine", "--read-dtcs", "--clear-dtcs"],
                     ["--module", "eps", "--read-dtcs"]):
            with patch.object(runner, "open_adapter", side_effect=AssertionError("no adapter")):
                with self.assertRaises(SystemExit, msg=argv):
                    run_main(argv)


if __name__ == "__main__":
    unittest.main()
