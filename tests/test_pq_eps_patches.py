"""Offline checks for the PQ EPS patcher; no CAN hardware is used.

Run from the repository root: python -m pytest tests (or python -m unittest).
The repository is the `flasher` package itself, so it is registered under that
name when it is not already importable (for example from a submodule mount).
"""

import binascii
import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import sys
import tempfile
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

from flasher.controllers.pq_eps import patches as P


STOCK_GAINS = [[88, 113, 155]] * 3
TRIP_3P8 = bytes.fromhex("33337340")


def gen3_image(identity_at, identity, sites=()):
    """A synthetic gen3 rack image with valid CRCs, stock HCA gains and the given bytes."""
    data = bytearray(b"\xff" * P.IMAGE_SIZE)
    data[0x5DFF8:0x5DFFC] = P.CRC_MARKER
    data[identity_at:identity_at + len(identity)] = identity
    for address, value in sites:
        data[address:address + len(value)] = value
    for index, lut in enumerate(P.GAIN_LUTS):
        pointer = P.DATASET_START + P.GAIN_POINTERS + 4 * index
        data[pointer:pointer + 4] = (P.DATASET_START + lut).to_bytes(4, "little")
        data[P.DATASET_START + lut:P.DATASET_START + lut + 8] = P.GAIN_HEADER + bytes(STOCK_GAINS[index])
    return P.update_checksums(bytes(data))


def tt3305():
    return gen3_image(0x5D824, b"8J0909144P \x003305", (
        (0x5D0A4, b"\x01\x00"), (0x5D0A6, b"\x0a\x00"), (0x5D285, b"\x64"), (0x5D2F6, b"\x14"),
        (P.TORQUE_TRIP, TRIP_3P8)))


def tt3001():
    return gen3_image(0x5D7A0, b"8J0909144J \x003001", (
        (0x5D0A4, b"\x01\x00"), (0x5D0A6, b"\xcc\x00"), (0x5D249, b"\x64"), (0x5D2AE, b"\x14"),
        (P.END_MARKER_OFFSET, b"Ende"), (P.TORQUE_TRIP, TRIP_3P8)))


def crcs_valid(data):
    _, sites = P.checksum_layout(data)
    return all(int.from_bytes(data[word:word + 2], "big") == binascii.crc_hqx(data[low:high], 0)
               for _, word, low, high in sites)


def changed(before, after):
    return {i for i in range(len(before)) if before[i] != after[i]}


class EpsPatchTests(unittest.TestCase):
    def test_3305_patches_and_gains_found(self):
        image = tt3305()
        self.assertEqual(P.known_patches(image), {
            "hca-timeout-minspeed (8J0909144P 3305)": "stock",
            "slew-up-10 (8J0909144P 3305)": "stock",
            "slew-20 (8J0909144P 3305)": "stock",
            "hca-gain-140": "stock", "hca-gain-160": "stock"})
        self.assertEqual(P.hca_gains(image), STOCK_GAINS)

    def test_minspeed_and_slew_combine_in_0x5d(self):
        image = tt3305()
        out = P.apply_patches(image, [P.HCA_TIMEOUT_MINSPEED, P.SLEW_UP_10])
        self.assertTrue(crcs_valid(out))
        self.assertEqual(changed(image, out), {0x5D0A4, 0x5D285, 0x5D2F6, 0x5DFFE, 0x5DFFF})
        self.assertEqual(out[0x5D0A4:0x5D0A8], b"\x0a\x00\x0a\x00")

    def test_slew_20_sets_both_steps(self):
        out = P.apply_patches(tt3305(), [P.SLEW_20])
        self.assertEqual(out[0x5D0A4:0x5D0A8], b"\x14\x00\x14\x00")
        self.assertTrue(crcs_valid(out))

    def test_slew_patches_are_exclusive(self):
        with self.assertRaisesRegex(ValueError, "only one"):
            P.apply_patches(tt3305(), [P.SLEW_UP_10, P.SLEW_20])

    def test_gain_preset_touches_only_0x5e(self):
        image = tt3305()
        out = P.apply_patches(image, ["hca-gain-160"])
        self.assertEqual(P.hca_gains(out), [[160] * 3] * 3)
        self.assertTrue(crcs_valid(out))
        self.assertTrue(all(P.DATASET_START <= i <= P.DATASET_END for i in changed(image, out)))
        self.assertEqual(P.known_patches(out)["hca-gain-160"], "applied")

    def test_custom_gains_per_variant(self):
        gains = [[95, 140, 155], [100, 120, 140], [0, 128, 160]]
        out = P.apply_patches(tt3305(), [P.HCA_TIMEOUT_MINSPEED], gains)
        self.assertEqual(P.hca_gains(out), gains)
        self.assertTrue(crcs_valid(out))

    def test_gain_limits(self):
        with self.assertRaisesRegex(ValueError, "0 to 160"):
            P.apply_patches(tt3305(), [], [[161, 100, 100]] * 3)
        with self.assertRaisesRegex(ValueError, "one HCA gain preset"):
            P.apply_patches(tt3305(), ["hca-gain-140"], [[100] * 3] * 3)

    def test_gains_refused_on_unknown_firmware(self):
        image = gen3_image(0x5D824, b"8J0909144P \x003999")
        self.assertIsNone(P.hca_gains(image))
        with self.assertRaises(P.UnsupportedFirmwarePatch):
            P.apply_patches(image, ["hca-gain-140"])

    def test_gains_refused_when_lut_layout_differs(self):
        image = bytearray(tt3305())
        image[P.DATASET_START + P.GAIN_LUTS[1] + 2] = 0x14  # x[0] = 20 km/h
        self.assertIsNone(P.hca_gains(P.update_checksums(bytes(image))))

    def test_3001_gets_gains_but_no_slew(self):
        image = tt3001()
        self.assertNotIn("slew-up-10 (8J0909144J 3001)", P.known_patches(image))
        with self.assertRaises(P.UnsupportedFirmwarePatch):
            P.apply_patches(image, [P.SLEW_UP_10])
        out = P.apply_patches(image, [P.HCA_TIMEOUT_MINSPEED, "hca-gain-140"])
        self.assertEqual(P.hca_gains(out), [[140] * 3] * 3)
        self.assertEqual(out[P.END_MARKER_OFFSET:], b"\xff" * 4)
        self.assertTrue(crcs_valid(out))

    def test_4k_dataset_gains(self):
        dataset = tt3305()[P.DATASET_START:P.DATASET_END + 1]
        self.assertEqual(P.hca_gains(dataset), STOCK_GAINS)
        out = P.apply_patches(dataset, [], [[120, 130, 140]] * 3)
        self.assertEqual(P.hca_gains(out), [[120, 130, 140]] * 3)
        self.assertTrue(crcs_valid(out))
        with self.assertRaises(P.UnsupportedFirmwarePatch):
            P.apply_patches(dataset, [P.HCA_TIMEOUT_MINSPEED])

    def test_mismatching_preimage_is_refused(self):
        image = bytearray(tt3305())
        image[0x5D2F6] = 0x10
        with self.assertRaises(P.UnsupportedFirmwarePatch):
            P.apply_patches(P.update_checksums(bytes(image)), [P.HCA_TIMEOUT_MINSPEED])

    def test_patch_options(self):
        options = P.patch_options(tt3305())
        by_feature = {f["feature"]: f for f in options["features"]}
        self.assertEqual(by_feature[P.SLEW_20]["status"], "stock")
        self.assertEqual(by_feature[P.SLEW_20]["group"], [P.SLEW_20, P.SLEW_UP_10])
        self.assertEqual(options["gains"], STOCK_GAINS)
        self.assertEqual(options["gain_max"], 160)

    def test_torque_trip(self):
        image = tt3305()
        self.assertAlmostEqual(P.hca_torque_trip(image), 3.8, places=5)
        word = set(range(P.TORQUE_TRIP, P.TORQUE_TRIP + 4))
        crc = {0x5DFFE, 0x5DFFF}
        for value in (4.0, 3.5, 12.25, 0.1, 20.0):
            out = P.apply_patches(image, torque_trip=value)
            # Only the existing float word and the 0x5D CRC are ever written.
            self.assertLessEqual(changed(image, out), word | crc)
            self.assertEqual(P.hca_torque_trip(out), struct.unpack("<f", struct.pack("<f", value))[0])
            self.assertTrue(crcs_valid(out))
        out = P.apply_patches(image, [P.HCA_TIMEOUT_MINSPEED], torque_trip=4.0)
        self.assertEqual(out[P.TORQUE_TRIP:P.TORQUE_TRIP + 4], bytes.fromhex("00008040"))
        self.assertEqual(changed(image, out), {0x5D09C, 0x5D09D, 0x5D09E, 0x5D285, 0x5D2F6} | crc)
        self.assertTrue(crcs_valid(out))
        self.assertEqual(P.apply_patches(image, torque_trip=3.8), image)
        with self.assertRaisesRegex(ValueError, "0.1 to 20"):
            P.apply_patches(image, torque_trip=38.0)

    def test_torque_trip_needs_known_firmware(self):
        self.assertIsNone(P.hca_torque_trip(tt3305()[P.DATASET_START:P.DATASET_END + 1]))
        unknown = gen3_image(0x5D824, b"8J0909144P \x003999", ((P.TORQUE_TRIP, TRIP_3P8),))
        self.assertIsNone(P.hca_torque_trip(unknown))
        with self.assertRaises(P.UnsupportedFirmwarePatch):
            P.apply_patches(unknown, torque_trip=4.0)

    def test_cli_combines_patches_and_gains(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "rack.bin"
            source.write_bytes(tt3305())
            output = Path(folder) / "out.bin"
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                code = P.main([str(source), str(output), "--patch", P.HCA_TIMEOUT_MINSPEED,
                               "--patch", P.SLEW_20, "--gains", "100,120,140",
                               "--torque-trip", "4"])
            self.assertEqual(code, 0)
            out = output.read_bytes()
            self.assertEqual(P.hca_gains(out), [[100, 120, 140]] * 3)
            self.assertEqual(out[0x5D0A4:0x5D0A8], b"\x14\x00\x14\x00")
            self.assertEqual(P.hca_torque_trip(out), 4.0)
            self.assertIn("0x5D and 0x5E", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
