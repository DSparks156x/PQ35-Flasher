"""Generic read-only KWP2000 application diagnostics over TP2.

Used by families without a flash path (engine 0x01, transmission 0x02).
Identification uses the runner's default KWP 1A 9B/9C path. Measuring-block
logging is driven through :class:`flasher.vag_protocols.measuring.MeasuringSession`
by the caller; the CLI exposes DTC read and clear only.
"""
from contextlib import contextmanager
import json
import logging

from flasher.vag_protocols.kwp import KWPClient, KWPNegativeResponse


DEFAULT_SESSION = 0x89


def add_cli_arguments(parser):
    parser.add_argument("--dtc-freeze-frames", action="store_true",
                        help="With --read-dtcs, also request 12 00 04 freeze frames per code")


def apply_defaults(args):
    pass


def validate_cli(parser, args):
    if (args.input or args.recovery or args.dry_run or args.start is not None
            or args.end is not None or args.reference or args.readout
            or args.readout_passes != 1 or args.readout_window != 0x10000):
        parser.error(f"{args.family.name} supports identification and DTC read/clear only; "
                     "image, range and readout options do not apply")
    if getattr(args, "dtc_freeze_frames", False) and not getattr(args, "read_dtcs", False):
        parser.error("--dtc-freeze-frames requires --read-dtcs")


@contextmanager
def application_session(args, runtime, *, session=DEFAULT_SESSION):
    """Open adapter, TP2 channel and KWP client; close them in reverse order.

    A negative response to the diagnostic session is tolerated: the module
    stays in its current session.
    """
    from flasher.vag_protocols.tp2 import TP2Transport
    device = tp = None
    log = logging.getLogger("KWPGeneric").info
    try:
        device = runtime.open_adapter(args)
        tp = TP2Transport(device, module=args.module, timeout=2.0,
                          debug=args.verbose, log_fn=log)
        kwp = KWPClient(tp, debug=args.verbose, log_fn=log)
        if session is not None:
            try:
                kwp.session(session)
            except KWPNegativeResponse as error:
                log(f"Diagnostic session 0x{session:02X} refused ({error}); continuing")
        yield kwp
    finally:
        if tp is not None:
            tp.disconnect()
        if device is not None:
            device.close()


def run_dtc(args, runtime):
    from flasher.vag_protocols.dtc import read_dtcs
    with application_session(args, runtime) as kwp:
        result = read_dtcs(kwp, freeze_frames=getattr(args, "dtc_freeze_frames", False))
    result.update(module=args.module, controller_family=args.family.name)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("error") is None else 1


def run_dtc_clear(args, runtime):
    from flasher.vag_protocols.dtc import clear_dtcs
    with application_session(args, runtime) as kwp:
        result = clear_dtcs(kwp)
    result.update(module=args.module, controller_family=args.family.name)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["cleared"] else 1
