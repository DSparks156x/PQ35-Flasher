"""Offline explicit-ACK TP2 replay regressions; no adapter or hardware imports.

Core checkout: python -B -m unittest discover -s tests -p test_tp2_retry.py
Workspace: python -B artifacts/test_tp2_retry.py
Override the source with TP2_RETRY_SOURCE; no command-line parsing at import.
"""
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "vag_protocols" / "tp2.py"
if not DEFAULT_SOURCE.exists():
    DEFAULT_SOURCE = Path(__file__).with_name("tp2_retry_candidate.py")
SOURCE = Path(os.environ.get("TP2_RETRY_SOURCE", str(DEFAULT_SOURCE)))
spec = importlib.util.spec_from_file_location("retry_test_tp2", SOURCE)
tp2 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tp2
spec.loader.exec_module(tp2)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeCAN:
    def __init__(self, clock, frames):
        self.clock = clock
        self.frames = list(frames)
        self.sent = []

    def can_send(self, can_id, data, bus):
        self.sent.append((self.clock.now, can_id, bytes(data), bus))

    def can_recv(self, timeout_ms):
        self.clock.sleep(timeout_ms / 1000.0)
        # Batch delivery exercises the transport's queued-frame preservation.
        batch, self.frames = self.frames, []
        return [(0x300, frame, 0) for frame in batch]


class ExplicitReplayTests(unittest.TestCase):
    REQUEST35 = bytes.fromhex("3580c00000000040")
    OLD_RESPONSE = bytes.fromhex("1c2000e681")

    def setUp(self):
        self.clock = FakeClock()
        p = patch.object(tp2, "time", types.SimpleNamespace(
            monotonic=self.clock.monotonic, sleep=self.clock.sleep))
        p.start()
        self.addCleanup(p.stop)

    def transport(self, replies, sequence=9, block_size=15):
        device = FakeCAN(self.clock, replies)
        transport = tp2.TP2Transport.fixed_channel(
            device, tx_addr=0x338, rx_addr=0x300, timeout=0.2,
            block_size=block_size, t3_ms=1)
        transport.tx_seq = sequence
        return transport, device

    def sent(self, device):
        return [frame for _, _, frame, _ in device.sent]

    def expected_frames(self, payload, sequence, block_size=15):
        return tp2.segment_message(payload, sequence, block_size=block_size)[0]

    def waits(self):
        return self.clock.sleeps.count(tp2.NOT_READY_WAIT_SECONDS)

    def test_99_replays_exact_single_sequence9_transfer_frame(self):
        transport, device = self.transport([b"\x99", b"\xba"])
        transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")] * 2)
        self.assertEqual(transport.tx_seq, 10)
        self.assertEqual(self.waits(), 1)

    def test_97_replays_both_sequence7_and8_download_setup_frames(self):
        transport, device = self.transport([b"\x97", b"\xb9"], sequence=7)
        expected = self.expected_frames(self.REQUEST35, 7)
        transport.send(self.REQUEST35)
        self.assertEqual(self.sent(device), expected + expected)
        self.assertEqual([f[0] & 15 for f in expected], [7, 8])
        self.assertEqual(transport.tx_seq, 9)
        self.assertEqual(self.waits(), 1)

    def test_partial_ack_replays_only_requested_suffix(self):
        transport, device = self.transport([b"\x98", b"\xb9"], sequence=7)
        expected = self.expected_frames(self.REQUEST35, 7)
        transport.send(self.REQUEST35)
        self.assertEqual(self.sent(device), expected + expected[1:])

    def test_ready_ack_rewind_does_not_insert_notready_wait(self):
        transport, device = self.transport([b"\xb7", b"\xb9"], sequence=7)
        expected = self.expected_frames(self.REQUEST35, 7)
        transport.send(self.REQUEST35)
        self.assertEqual(self.sent(device), expected + expected)
        self.assertEqual(self.waits(), 0)

    def test_replay_supports_wrap_and_wrapped_suffix(self):
        for requested, suffix in ((0x9F, 0), (0x90, 1)):
            with self.subTest(requested=hex(requested)):
                transport, device = self.transport([bytes([requested]), b"\xb1"], sequence=15)
                expected = self.expected_frames(self.REQUEST35, 15)
                transport.send(self.REQUEST35)
                self.assertEqual([f[0] & 15 for f in expected], [15, 0])
                self.assertEqual(self.sent(device), expected + expected[suffix:])
                self.assertEqual(transport.tx_seq, 1)

    def test_maximum_unique_window_supports_sequence_wrap(self):
        payload = bytes(range(100))  # 15 frames, sequence9..7; next sequence8.
        transport, device = self.transport([b"\x9b", b"\xb8"])
        expected = self.expected_frames(payload, 9)
        self.assertEqual(len(expected), 15)
        transport.send(payload)
        self.assertEqual(self.sent(device), expected + expected[2:])
        self.assertEqual(transport.tx_seq, 8)

    def test_outside_window_sequence_fails_without_replay(self):
        for ack in (b"\x98", b"\xb8"):
            with self.subTest(ack=ack.hex()):
                transport, device = self.transport([ack])
                with self.assertRaisesRegex(tp2.TP2Error, "outside outstanding"):
                    transport.send(b"\x36")
                self.assertEqual(self.sent(device), [bytes.fromhex("19000136")])
                self.assertEqual(transport.tx_seq, 9)

    def test_acknowledged_prefix_cannot_be_replayed(self):
        transport, device = self.transport([b"\x98", b"\x97"], sequence=7)
        expected = self.expected_frames(self.REQUEST35, 7)
        with self.assertRaisesRegex(tp2.TP2Error, "outside outstanding"):
            transport.send(self.REQUEST35)
        self.assertEqual(self.sent(device), expected + expected[1:])

    def test_sixth_explicit_rewind_fails_after_five_replays(self):
        transport, device = self.transport([b"\x99"] * 6)
        with self.assertRaisesRegex(tp2.TP2Error, "retransmission limit"):
            transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")] * 6)
        self.assertEqual(self.waits(), 5)

    def test_silence_never_retries(self):
        transport, device = self.transport([])
        with self.assertRaisesRegex(tp2.TP2Error, "expected ACK 0xBA"):
            transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")])
        self.assertEqual(self.waits(), 0)

    def test_queued_old_notready_cannot_request_new_message_replay(self):
        transport, device = self.transport([b"\xba"])
        transport.msgs = [(transport.rx_addr, b"\x99")]
        transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")])
        self.assertEqual(self.waits(), 1)
        self.assertGreaterEqual(device.sent[0][0], 0.100)
        self.assertEqual(transport.msgs, [])

    def test_silence_after_explicit_replay_does_not_add_retry(self):
        transport, device = self.transport([b"\x99"])
        with self.assertRaisesRegex(tp2.TP2Error, "expected ACK 0xBA"):
            transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")] * 2)

    def test_expected_notready_sequence_acknowledges_without_replay(self):
        transport, device = self.transport([b"\x9a"])
        transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")])
        self.assertEqual(transport.tx_seq, 10)
        self.assertEqual(self.waits(), 1)

    def test_expected_notready_waits_before_next_block_without_readiness_handshake(self):
        transport, device = self.transport([b"\x98", b"\xb9"], sequence=7, block_size=1)
        expected = self.expected_frames(self.REQUEST35, 7, block_size=1)
        transport.send(self.REQUEST35)
        self.assertEqual(self.sent(device), expected)
        self.assertGreaterEqual(device.sent[1][0] - device.sent[0][0], 0.100)
        self.assertEqual(self.waits(), 1)

    def test_duplicate_old_response_is_reacked_but_not_implicit_ack(self):
        transport, device = self.transport([self.OLD_RESPONSE])
        transport.rx_seq = 13
        transport.last_acked_rx_frame = self.OLD_RESPONSE
        with self.assertRaisesRegex(tp2.TP2Error, "expected ACK 0xBA"):
            transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136"), b"\xbd"])
        self.assertEqual(transport.rx_seq, 13)

    def test_duplicate_old_response_then_rewind_keeps_replay_exact(self):
        transport, device = self.transport([self.OLD_RESPONSE, b"\x99", b"\xba"])
        transport.rx_seq = 13
        transport.last_acked_rx_frame = self.OLD_RESPONSE
        transport.send(b"\x36")
        request = bytes.fromhex("19000136")
        self.assertEqual(self.sent(device), [request, b"\xbd", request])
        self.assertEqual(transport.rx_seq, 13)

    def test_new_data_still_implicitly_acknowledges_and_is_preserved(self):
        fresh = bytes.fromhex("1d000176")
        transport, device = self.transport([fresh])
        transport.rx_seq = 13
        transport.send(b"\x36")
        self.assertEqual(transport.tx_seq, 10)
        self.assertEqual(transport.recv(), b"\x76")
        self.assertEqual(transport.rx_seq, 14)
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136"), b"\xbe"])

    def test_malformed_ack_fails_without_replay(self):
        transport, device = self.transport([b"\x99\x00"])
        with self.assertRaisesRegex(tp2.TP2Error, "Malformed TP2 acknowledgement"):
            transport.send(b"\x36")
        self.assertEqual(len(self.sent(device)), 1)

    def test_ambiguous_block_larger_than15_fails_before_transmission(self):
        transport, device = self.transport([], block_size=0)
        with self.assertRaisesRegex(tp2.TP2Error, "15-frame window"):
            transport.send(bytes(104))
        self.assertEqual(self.sent(device), [])

    def test_public_wait_for_ack_remains_compatible_without_cache(self):
        transport, _ = self.transport([b"\xba"])
        self.assertIsNone(transport.wait_for_ack(9))


class LegacyAckTests(unittest.TestCase):
    """legacy_ack (the PQ EPS flash path) keeps the pre-8d98ca7 ACK rules."""

    def setUp(self):
        self.clock = FakeClock()
        p = patch.object(tp2, "time", types.SimpleNamespace(
            monotonic=self.clock.monotonic, sleep=self.clock.sleep))
        p.start()
        self.addCleanup(p.stop)

    def transport(self, replies, sequence=9):
        device = FakeCAN(self.clock, replies)
        transport = tp2.TP2Transport.fixed_channel(
            device, tx_addr=0x338, rx_addr=0x300, timeout=0.2, block_size=15, t3_ms=1)
        transport.legacy_ack = True
        transport.tx_seq = sequence
        return transport, device

    @staticmethod
    def sent(device):
        return [frame for _, _, frame, _ in device.sent]

    def test_notready_only_waits_for_the_ready_ack(self):
        transport, device = self.transport([b"\x9a", b"\xba"])
        transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")])
        self.assertNotIn(tp2.NOT_READY_WAIT_SECONDS, self.clock.sleeps)
        self.assertEqual(transport.tx_seq, 10)

    def test_notready_alone_is_not_an_ack(self):
        transport, device = self.transport([b"\x9a"])
        with self.assertRaisesRegex(tp2.TP2Error, "expected ACK 0xBA"):
            transport.send(b"\x36")
        self.assertEqual(len(self.sent(device)), 1)

    def test_rewind_requests_are_never_replayed(self):
        transport, device = self.transport([b"\x99", b"\xba"])
        transport.send(b"\x36")
        self.assertEqual(self.sent(device), [bytes.fromhex("19000136")])

    def test_response_frame_acknowledges_and_is_preserved(self):
        transport, _ = self.transport([bytes.fromhex("1d000176")])
        transport.rx_seq = 13
        transport.send(b"\x36")
        self.assertEqual(transport.recv(), b"\x76")

    def test_disconnect_while_waiting_raises_connection_error(self):
        transport, _ = self.transport([b"\xa8"])
        with self.assertRaisesRegex(ConnectionError, "closed TP2 channel"):
            transport.send(b"\x36")


if __name__ == "__main__":
    unittest.main()
