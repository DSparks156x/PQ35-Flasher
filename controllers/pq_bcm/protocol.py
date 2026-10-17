"""Read-only BCM 8P0907063E/0575 policy for the existing PQ engine.

This module owns no CAN/J2534/TP2 implementation or adapter factory. The caller
injects the same transport used by other flasher controller readers. This controller has not yet been exercised on hardware.
"""

import hashlib
import json
from pathlib import Path
import sys
import time

from flasher.engine import PQMemoryReader, PQReadError, PQReadProfile, SecurityAccess, add32
from flasher.vag_protocols.kwp import KWPClient, KWPProfile
from flasher.vag_protocols.tp2 import TP2Transport

from . import codec


BCM_MODULE_ADDR = 0x20
BCM_READ_KEY_ADD = 0xA41D
MAX_UPLOAD = 0x43
SUPPORTED_OPERATIONS = frozenset({"identify", "readout", "pageff"})


def _target_for_range(address: int, length: int) -> str:
    if type(address) is not int or type(length) is not int:
        raise ValueError("BCM address and length must be integers")
    if not 1 <= length <= MAX_UPLOAD:
        raise ValueError("BCM upload length must be 1..67")
    try:
        return codec.upload_target(address, length)
    except codec.ProtocolError as error:
        raise ValueError(str(error)) from None


def validate_range(address: int, length: int) -> None:
    _target_for_range(address, length)


BCM_READ_KWP_PROFILE = KWPProfile(
    exact_session_responses={0x89: b"\x50\x89", 0x86: b"\x50\x86"},
    reject_unprofiled_sessions=True,
    exact_key_status=0x34,
    single_byte_positive_services=frozenset({0x37}),
    exact_response_lengths={0x35: 2},
)

BCM_READ_PROFILE = PQReadProfile(
    name="pq-bcm",
    module=BCM_MODULE_ADDR,
    image_size=0,  # This reader exposes named targets, never a CPU flash image.
    validate_range=validate_range,
    initial_session=0x89,
    privileged_session=0x86,
    security=SecurityAccess(0x03, 0x04, add32(BCM_READ_KEY_ADD), "bcm-0575-read"),
    methods=("upload",),
    upload_block_max=MAX_UPLOAD,
    strict_upload_blocks=True,
    mark_upload_before_request=True,
    leave_requests=(b"\x10\x89",),
    key_response=b"\x67\x04\x34",
)


class PQBCMReader(PQMemoryReader):
    """BCM policy using shared enter/leave/read_window and KWP machinery.

    Each instance permits one authorization attempt and no automatic probing.
    The identity gate runs before seed/key/session86 requests. Each named read
    uses one final 35/36/37 transaction, avoiding BCM multi-response framing.
    """

    def __init__(self, transport, record=lambda event: None):
        super().__init__(
            transport, BCM_READ_PROFILE, record=record,
            kwp_factory=lambda tp, **kwargs: KWPClient(
                tp, profile=BCM_READ_KWP_PROFILE, debug=False),
        )
        self._part_reply = None
        self._version_reply = None
        self._identity = None
        self._seed_attempted = False
        self._key_attempted = False
        self._expected_key = None
        self._read_session_verified = False
        self._upload_stage = "idle"
        self._upload_target = None
        self._upload_window = None
        self._inflight_request = None
        # Coding writes (2E 0610/0611) are refused unless explicitly armed by
        # enable_coding_write(); reads never arm it.
        self._allow_coding_write = False

    def _allowed(self, request: bytes) -> bool:
        if self._inflight_request == request:
            return True
        if request in (codec.part_number_request(), codec.software_version_request(), b"\x10\x89"):
            return not self.upload_active
        if request in tuple(codec.subsystem_request(name) for name in codec.SUBSYSTEM_FIELDS):
            return self._identity is not None and not self._seed_attempted and not self.upload_active
        if request == b"\x27\x03":
            return self._identity is not None and not self._seed_attempted and not self.upload_active
        if request[:2] == b"\x27\x04":
            return (self._identity is not None and self._seed_attempted
                    and not self._key_attempted and self._expected_key is not None
                    and request == b"\x27\x04" + self._expected_key)
        if request == b"\x10\x86":
            return self._identity is not None and self.security_unlocked and not self.upload_active
        if request[:1] == b"\x35":
            return (self.privileged_active and self._read_session_verified
                    and self._upload_stage == "setup" and self._upload_window is not None
                    and request == codec.window_setup_request(*self._upload_window))
        if request == codec.transfer_request():
            return self.upload_active and self._upload_stage == "transfer"
        if request == codec.exit_request():
            return self.upload_active
        if request == codec.dtc_read_request():
            return self._identity is not None and not self.upload_active
        if len(request) == 2 and request[:1] == b"\x21":  # measuring block read
            return self._identity is not None and not self.upload_active
        if len(request) == 6 and request[:1] == b"\x2e":  # LIN sub-bus coding write
            dids = tuple(codec.SUBSYSTEM_FIELDS[n].identifier.to_bytes(2, "big")
                         for n in codec.CODING_WRITE_FIELDS)
            return (self._allow_coding_write and self._identity is not None
                    and not self.upload_active and request[1:3] in dids)
        return False

    def _exchange(self, request: bytes) -> bytes:
        request = bytes(request)
        if self._inflight_request is not None:
            raise PQReadError("Reentrant BCM exchanges are forbidden")
        # Guard before super()._exchange invokes KWPClient/transport.send.
        if not self._allowed(request):
            raise ValueError("Request is outside the bounded BCM read policy: " + request.hex())
        if request == b"\x27\x03":
            self._seed_attempted = True
            # Shared leave() must restore session89 even after uncertain security.
            self.privileged_active = True
        elif request[:2] == b"\x27\x04":
            self._key_attempted = True
        elif request == b"\x10\x89":
            self._read_session_verified = False
        elif request == codec.transfer_request():
            self._upload_stage = "consumed"  # Never resend an ambiguous transfer.

        # Shared engine repeats its allowlist check. Authorization/transfer state
        # changed above, so call its recording/validation exchange through a
        # temporary one-request permission, scoped to this synchronous call.
        self._inflight_request = request
        try:
            response = super()._exchange(request)
        finally:
            self._inflight_request = None

        if request == codec.part_number_request():
            codec.parse_part_number_response(response)
            self._part_reply = response
        elif request == codec.software_version_request():
            codec.parse_software_version_response(response)
            self._version_reply = response
        elif request == b"\x27\x03":
            if len(response) != 6 or response[:2] != b"\x67\x03":
                raise PQReadError("Expected67 03 followed by exactly four seed bytes")
            self._expected_key = self.profile.security.derive_key(response[2:])
        elif request == b"\x10\x86":
            self._read_session_verified = True
        elif request[:1] == b"\x35":
            codec.parse_setup_response(response)
            self._upload_stage = "transfer"
        elif request == codec.transfer_request():
            codec.parse_window_transfer_response(*self._upload_window, response)
        elif request == codec.exit_request():
            codec.parse_exit_response(response)
        if self._part_reply is not None and self._version_reply is not None:
            self._identity = codec.validate_known_identity(self._part_reply, self._version_reply)
        return response

    def identify(self) -> bytes:
        """Return the raw 11-byte part field, replacing inherited service1A."""
        return self._exchange(codec.part_number_request())[3:]

    def identification(self) -> dict:
        self._exchange(codec.part_number_request())
        self._exchange(codec.software_version_request())
        return {
            "part_number": self._identity.part_number,
            "software_part_number": self._identity.part_number,
            "sw_version": self._identity.software_version,
            "firmware_revision": self._identity.software_version,
            "raw_f187": self._part_reply.hex(),
            "raw_f189": self._version_reply.hex(),
        }

    def read_subsystems(self) -> dict:
        fields = {}
        # Alternate NADs to avoid repeated same-NAD cache reuse where possible.
        # Firmware has no cache-age check; freshness remains unverified.
        for name in ("part_nad1", "part_nad2", "version_nad1", "version_nad2",
                     "coding_nad1", "coding_nad2"):
            request = codec.subsystem_request(name)
            data = codec.parse_subsystem_response(name, self._exchange(request))
            field = {"request_hex": request.hex(), "raw_hex": data.hex().upper()}
            if name.startswith("part_") and all(0x20 <= b <= 0x7E for b in data):
                field["ascii"] = data.decode("ascii").strip()
            fields[name] = field
        return {"fields": fields,
                "freshness": "Unverified: firmware may reuse an indefinitely cached LIN diagnostic reply",
                "coding_order": "Wire byte order preserved; compare with VCDS before assigning correction bytes",
                "version_format": "Raw four bytes; first source byte masked by firmware with 0x7F"}

    def read_dtcs(self) -> dict:
        """Read stored DTCs via 18 02 FF 00 (requires identity first)."""
        if self._identity is None:
            raise PQReadError("Identify the BCM before reading DTCs")
        reply = self._exchange(codec.dtc_read_request())
        dtcs = codec.parse_dtc_response(reply)
        return {"request_hex": codec.dtc_read_request().hex(),
                "raw_hex": bytes(reply).hex(),
                "count": len(dtcs),
                "dtcs": [{"code": f"{d['code']:04X}", "status": f"{d['status']:02X}"}
                         for d in dtcs]}

    def read_measuring(self, groups) -> dict:
        """Read one or more measuring groups via 21 <group> (identity first).

        Returns raw bodies; triple decoding is the worker's TP2Coding job.
        """
        if self._identity is None:
            raise PQReadError("Identify the BCM before reading measuring blocks")
        out = {}
        for group in groups:
            request = codec.measuring_request(group)
            body = codec.parse_measuring_response(group, self._exchange(request))
            out[f"group_{group:02X}"] = {"request_hex": request.hex(),
                                         "raw_body_hex": body.hex().upper()}
        return out

    def enable_coding_write(self) -> None:
        """Arm LIN sub-bus coding writes for this reader instance only.

        Writes stay refused until this is called. The caller is the sole
        hardware owner and must have confirmed identity and a read-back first.
        """
        self._allow_coding_write = True

    def write_subsystem_coding(self, name: str, data: bytes, *, confirm: bool = False):
        """Write 3 coding bytes to a channel-0 LIN slave (2E 0610/0611).

        Refuses unless enable_coding_write() was called AND confirm=True. Reads
        the coding back afterwards and returns both for the caller to compare.
        """
        if name not in codec.CODING_WRITE_FIELDS:
            raise PQReadError("Coding write supports only coding_nad1/coding_nad2")
        if not (self._allow_coding_write and confirm):
            raise PQReadError("LIN coding write not armed (enable_coding_write()+confirm=True)")
        if self._identity is None:
            raise PQReadError("Identify the BCM before writing sub-bus coding")
        before = codec.parse_subsystem_response(name, self._exchange(codec.subsystem_request(name)))
        request = codec.subsystem_coding_write_request(name, data)
        codec.parse_subsystem_coding_write_response(name, self._exchange(request))
        after = codec.parse_subsystem_response(name, self._exchange(codec.subsystem_request(name)))
        self.record({"event": "lin_coding_write", "field": name,
                     "before": before.hex().upper(), "after": after.hex().upper()})
        return {"field": name, "request_hex": request.hex(),
                "before_hex": before.hex().upper(), "after_hex": after.hex().upper(),
                "applied": bytes(after) == bytes(data)}

    def read_upload(self, address: int, length: int) -> bytes:
        name = _target_for_range(address, length)
        if self.upload_active:
            raise PQReadError("Previous BCM upload requires leave() cleanup")
        if not self.privileged_active or not self._read_session_verified:
            raise PQReadError("A verified BCM read session is required")
        self._upload_target = name
        self._upload_window = (address, length)
        self._upload_stage = "setup"
        self.upload_active = True  # Shared leave() handles uncertain setup.
        self._exchange(codec.window_setup_request(address, length))
        data = self._exchange(codec.transfer_request())[1:]
        self.record({"event": "block_received", "address": address,
                     "length": len(data), "end_exclusive": address + len(data)})
        self._exchange(codec.exit_request())
        self.upload_active = False
        self._upload_stage = "idle"
        self._upload_target = None
        self._upload_window = None
        return data

    def read_target(self, name: str) -> bytes:
        if name not in codec.TARGETS:
            raise ValueError("Unknown BCM read target")
        selected = codec.TARGETS[name]
        return self.read_window(selected.encoded_address, selected.length)

    def read_page_ff(self, progress_cb=None) -> bytes:
        """Dump page FF (global 0x7FC000..0x7FFFFF) via its CPU-local alias.

        Strictly read-only: identity, then the shared single-attempt
        seed/key/session86 entry, then 256 sequential 35/36/37 uploads of 0x40
        bytes across encoded 0x80C000..0x80FFFF. No download, erase, write or
        coding request is permitted by _allowed(). progress_cb receives
        (chunk_number, chunk_count, encoded_address) after each chunk.
        """
        if self._identity is None:
            raise PQReadError("Identify the BCM before reading page FF")
        if not self._read_session_verified:
            self.enter()
        count = codec.PAGE_FF_SIZE // codec.PAGE_FF_CHUNK
        data = bytearray()
        for index in range(count):
            address = codec.PAGE_FF_START + index * codec.PAGE_FF_CHUNK
            block = self.read_window(address, codec.PAGE_FF_CHUNK)
            if len(block) != codec.PAGE_FF_CHUNK:
                raise PQReadError(f"Page FF chunk at 0x{address:06X}: got {len(block)} bytes")
            data.extend(block)
            self.record({"event": "page_ff_chunk", "chunk": index + 1, "chunks": count,
                         "encoded_address": address,
                         "global_address": codec.PAGE_FF_GLOBAL_START + index * codec.PAGE_FF_CHUNK})
            if progress_cb is not None:
                progress_cb(index + 1, count, address)
        return bytes(data)

    def probe(self, addresses, *, requested="auto"):
        raise PQReadError("BCM automatic address/service probing is disabled")


class CheckedCANDevice:
    """Record the existing provider's raw frames and reject failed CAN sends.

    Driver implementations remain in the shared flasher. J2534 hardware RX
    timestamps are retained when can_recv_ts is available; host timestamps are
    separate. Read error status hidden by an existing provider cannot be
    recovered here. No provider is imported or constructed by this wrapper.
    """

    def __init__(self, device, record=lambda event: None):
        self.device = device
        self.record = record

    def can_send(self, can_id, data, bus=0):
        event = {"event": "can_tx", "id": can_id, "hex": bytes(data).hex(),
                 "bus": bus, "host_monotonic_ns": time.monotonic_ns()}
        try:
            status = self.device.can_send(can_id, data, bus)
        except Exception as error:
            self.record(dict(event, error=str(error)))
            raise
        self.record(dict(event, status=status))
        if status is not None and status != 0:
            raise RuntimeError(f"CAN provider send failed: status {status!r}")
        return status

    def can_recv(self, timeout_ms=10):
        stamped = getattr(self.device, "can_recv_ts", None)
        frames = (stamped(timeout_ms) if stamped is not None else
                  [(*frame, None) for frame in self.device.can_recv(timeout_ms)])
        received = []
        for can_id, data, bus, driver_timestamp_us in frames:
            payload = bytes(data)
            self.record({"event": "can_rx", "id": can_id, "hex": payload.hex(),
                         "bus": bus, "driver_timestamp_us": driver_timestamp_us,
                         "host_monotonic_ns": time.monotonic_ns()})
            received.append((can_id, payload, bus))
        return received

    def close(self):
        return self.device.close()


def add_cli_arguments(parser):
    parser.add_argument("--bcm-subsystems", action="store_true",
                        help="Read NAD 1/2 identity, version candidate and coding; replies may be cached")
    parser.add_argument("--bcm-target", action="append", choices=tuple(codec.TARGETS),
                        help="Named bounded BCM target; repeat to select several")
    parser.add_argument("--bcm-dtcs", action="store_true",
                        help="Also read stored DTCs (18 02 FF 00)")
    parser.add_argument("--bcm-measuring", action="append", type=lambda v: int(v, 0),
                        help="Also read measuring group N (21 NN); repeat for several")
    parser.add_argument("--bcm-loader-config",
                        help="JSON of captured resident-loader params required for a live BCM flash")


def apply_defaults(args):
    args.out = args.out or "data/raw/readout/pq-bcm"


def validate_cli(parser, args):
    if args.module != BCM_MODULE_ADDR:
        parser.error("BCM application requires TP2 logical module0x20")
    if getattr(args, "read_bcm_pageff", False):
        if (args.input or args.recovery or args.start is not None or args.end is not None
                or args.reference or args.readout_passes != 1 or args.readout_window != 0x10000
                or getattr(args, "bcm_target", None) or getattr(args, "bcm_subsystems", False)
                or getattr(args, "bcm_dtcs", False) or getattr(args, "bcm_measuring", None)
                or getattr(args, "bcm_loader_config", None)):
            parser.error("--read-bcm-pageff takes only adapter options and --out")
        return
    flashing = bool(args.input) and not (args.ident_only or args.readout)
    if flashing:
        # Flash path validated in run_flash (needs a captured loader config).
        if args.reference or args.readout_passes != 1 or args.readout_window != 0x10000:
            parser.error("BCM flash does not take readout range/pass options")
        return
    if not (args.ident_only or args.readout):
        parser.error("BCM supports identification, bounded readout, and (scaffold) flash")
    if args.ident_only and getattr(args, "bcm_target", None):
        parser.error("--bcm-target requires --readout")
    if (args.input or args.recovery or args.start is not None or args.end is not None
            or args.reference or args.readout_passes != 1 or args.readout_window != 0x10000):
        parser.error("BCM accepts named targets rather than image/flash/range options")


def _capture(args, runtime, *, identify_only):
    """Use existing runtime/TP2/reader lifecycle; default provider stays external."""
    if args.module != BCM_MODULE_ADDR:
        raise ValueError("BCM application requires TP2 logical module0x20")
    names = () if identify_only else tuple(getattr(args, "bcm_target", None) or codec.DEFAULT_TARGETS)
    if len(set(names)) != len(names) or any(name not in codec.TARGETS for name in names):
        raise ValueError("BCM targets must be distinct reviewed names")
    output = Path(args.out)
    # An existing empty directory (e.g. a caller's mkdtemp) is fine; never overwrite.
    if output.exists() and not (output.is_dir() and not any(output.iterdir())):
        raise ValueError(f"Refusing to overwrite {output}")
    report = {
        "controller_family": "pq-bcm", "module": BCM_MODULE_ADDR,
        "operation": "identify" if identify_only else "readout",
        "adapter": args.adapter, "baud": args.baud, "bus": args.bus,
        "output": str(output), "hardware_access": not args.dry_run,
        "targets": {name: {"encoded_address": codec.TARGETS[name].encoded_address,
                           "length": codec.TARGETS[name].length,
                           "interpretation": codec.TARGETS[name].interpretation} for name in names},
        "status": "dry_run" if args.dry_run else "capturing",
        "live_protocol_validated": False,
        "subsystem_reads_requested": bool(getattr(args, "bcm_subsystems", False)),
    }
    if args.dry_run:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    output.mkdir(parents=True, exist_ok=True)
    events = []
    raw = {}
    device = transport = reader = None
    cleanup_errors = []
    try:
        device = CheckedCANDevice(runtime.open_adapter(args), events.append)
        transport = TP2Transport(device, module=BCM_MODULE_ADDR, bus=0,
                                 timeout=2.0, debug=args.verbose)
        reader = PQBCMReader(transport, record=events.append)
        report["identity"] = reader.identification()
        if getattr(args, "bcm_subsystems", False):
            report["lin_subsystems"] = reader.read_subsystems()
        if getattr(args, "bcm_dtcs", False):
            report["dtcs"] = reader.read_dtcs()
        measuring_groups = getattr(args, "bcm_measuring", None)
        if measuring_groups:
            report["measuring"] = reader.read_measuring(measuring_groups)
        if not identify_only:
            reader.enter()
            for name in names:
                raw[name] = reader.read_target(name)
        report["status"] = "captured_complete"
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "capture_interrupted" if isinstance(error, KeyboardInterrupt) else "capture_failed"
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        if reader is not None:
            cleanup_errors.extend(reader.leave())
        if transport is not None:
            try:
                transport.disconnect()
            except Exception as error:
                cleanup_errors.append("TP2 disconnect: " + str(error))
        if device is not None:
            try:
                device.close()
            except Exception as error:
                cleanup_errors.append("provider close: " + str(error))
    report["cleanup_errors"] = cleanup_errors
    report["captured"] = {}
    for name, data in raw.items():
        filename = name + ".bin"
        with (output / filename).open("xb") as stream:
            stream.write(data)
        report["captured"][name] = {"file": filename, "length": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()}
    if "sensor" in raw:
        report["sensor"] = codec.decode_sensor_data(raw["sensor"])
    if "frontparams" in raw:
        report["frontparams"] = codec.decode_front_parameter_data(raw["frontparams"])
    if cleanup_errors and report["status"] == "captured_complete":
        report["status"] = "requires_attention"
    with (output / "events.jsonl").open("x", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
    with (output / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return (0 if report["status"] == "captured_complete" else
            130 if report["status"] == "capture_interrupted" else 1)


def read_identification(transport, record=lambda event: None) -> dict:
    """Shared-runner identity hook: 22 F187/F189 on an open TP2 channel.

    This BCM has no KWP 1A (any 1A returns NRC 11), so the generic 1A 9B/9C
    identify can never succeed here. Default session, no security, read-only.
    """
    info = PQBCMReader(transport, record=record).identification()
    info["identity_service"] = "22 F187/F189"
    return info


def run_ident(args, runtime):
    """Plain --ident-only prints the flat identity like other families and
    writes nothing; the optional subsystem/DTC/measuring reads keep the
    report-folder capture."""
    if (getattr(args, "bcm_subsystems", False) or getattr(args, "bcm_dtcs", False)
            or getattr(args, "bcm_measuring", None)):
        return _capture(args, runtime, identify_only=True)
    if args.dry_run:
        print(json.dumps({"controller_family": "pq-bcm", "module": BCM_MODULE_ADDR,
                          "operation": "identify", "status": "dry_run",
                          "hardware_access": False,
                          "requests": [codec.part_number_request().hex(),
                                       codec.software_version_request().hex()]},
                         indent=2, sort_keys=True))
        return 0
    from flasher.runner import identify_module
    return identify_module(args, runtime)


def run_readout(args, runtime):
    return _capture(args, runtime, identify_only=False)


def run_pageff(args, runtime):
    """Read-only page FF dump; prints the saved .bin path on success."""
    from flasher.readout import PQBCMPageFFReadout

    if args.dry_run:
        print(json.dumps({
            "controller_family": "pq-bcm", "module": BCM_MODULE_ADDR,
            "operation": "pageff", "status": "dry_run", "hardware_access": False,
            "encoded_window": [codec.PAGE_FF_START, codec.PAGE_FF_END - 1],
            "global_window": [codec.PAGE_FF_GLOBAL_START,
                              codec.PAGE_FF_GLOBAL_START + codec.PAGE_FF_SIZE - 1],
            "chunk": codec.PAGE_FF_CHUNK,
            "chunks": codec.PAGE_FF_SIZE // codec.PAGE_FF_CHUNK,
            "output": args.out, "firmware_writes": False,
        }, indent=2, sort_keys=True))
        return 0
    readout = PQBCMPageFFReadout(open_device=lambda: runtime.open_adapter(args),
                                 progress_cb=runtime.progress, verbose=args.verbose)
    try:
        report = readout.readout(args.out)
    except KeyboardInterrupt:
        print("Page FF read interrupted; see sidecar report", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Page FF read failed: {error}", file=sys.stderr)
        if readout.last_result.get("report_path"):
            print("Report: " + readout.last_result["report_path"], file=sys.stderr)
        return 1
    print(report["path"])
    return 0


def run_flash(args, runtime):
    """Scaffold BCM flash. Dry-run validates the image slice and prints the plan;
    a live flash requires a captured resident-loader config (--bcm-loader-config)
    and explicit YES, because the BCM has no anti-brick net and the loader's
    erase/checksum/security are not known from our dump."""
    from . import flash as bcm_flash

    plan = {
        "controller_family": "pq-bcm", "module": BCM_MODULE_ADDR,
        "operation": "flash", "input": args.input,
        "start": args.start, "end": args.end,
        "no_anti_brick": True,
        "required_capture": bcm_flash.REQUIRED_CAPTURE,
    }
    if not args.input:
        raise ValueError("BCM flash requires --input")
    prepared = bcm_flash.prepare_image(args.input, args.start, args.end)
    plan["metadata"] = prepared["metadata"]

    if args.dry_run:
        plan["status"] = "validated_dry_run"
        print(json.dumps(plan, indent=2, sort_keys=True))
        print("No CAN traffic sent. Supply --bcm-loader-config and --yes for a live flash.")
        return 0

    if not getattr(args, "bcm_loader_config", None):
        plan["status"] = "refused_no_loader_config"
        print(json.dumps(plan, indent=2, sort_keys=True))
        raise bcm_flash.BCMFlashNotConfigured(
            "Live BCM flash refused: no resident-loader config. Capture a real BCM "
            "programming session and supply --bcm-loader-config. Needed: "
            + "; ".join(bcm_flash.REQUIRED_CAPTURE))

    loader = bcm_flash.LoaderConfig.from_file(args.bcm_loader_config)
    print(json.dumps(dict(plan, status="loader_config_loaded",
                          flash_range=[loader.flash_start, loader.flash_end]),
                     indent=2, sort_keys=True))
    print("WARNING: the PQ BCM has NO anti-brick recovery. A wrong checksum or "
          "routine can require BSL recovery. You are the sole hardware owner.")
    if not args.yes and input("Type YES to erase and flash the BCM: ") != "YES":
        print("Cancelled before adapter access.")
        return 1
    device = runtime.open_adapter(args)
    flasher = bcm_flash.PQBCMFlasher(
        loader, device=device, module=args.module,
        device_factory=lambda: runtime.open_adapter(args),
        progress_cb=runtime.progress, debug=args.verbose)
    result = flasher.flash_prepared(prepared, recovery=args.recovery)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

