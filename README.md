# Haldex Flasher
This is a project to flash and readout a Gen4 VW Haldex Controller, or probably most other modules with little adaptation. It is somewhat probably derived from pq-flasher, that EPS RE project. Testing was mostly done on a clone SM2 pro, hence the 32 bit shit, panda is untested and socketcan should work.  

The TP2/KWP implementation is the gateway-proven implementation from
RNS-E-Hudiy. It is also used directly against the Haldex bench controller.

Haldex-specific patching and checksum policy lives with the Haldex controller
family. The flasher automatically corrects selected-sector checksums and
applies the exact-preimage anti-brick patches. Simulator patches additionally
require the known firmware-layout manifest.

The anti-brick patches trigger the haldex to drop back into bootloader ready to reflash on checksum and some other errors, rather than ending up in an unflashable bootloop. If you do not apply them, a bad checksum or some other errors will put the haldex in a bootloop, as the stock error handling routine for many things basically just freezes and lets the watchdog reset, within about 40ms. You cannot start a flash section in 40ms, and will need to open the controller and recover via BSL. See BSL folder for that. 

I have flashed this thing over 180 times, I have only had to recover via BSL once. 

Do what you want with this stuff, more to be released about the actual editing of this binary eventually. maybe. This took a lot of human time. 

The rest of this readme is AI written. It looks fine, but i didn't read it all that thoroughly. 

There is one PQ flash/readout implementation for every CAN adapter and
controller family. The active architecture is deliberately small:

- `runner.py`: selects the adapter and module, then dispatches a generic operation;
  it contains no controller-specific ranges, options, or workflows.
- `engine.py`: the controller-neutral programming and memory-read state machines,
  profile contracts, SecurityAccess algorithms, reconnect, transfer, commit,
  capture, and boot verification.
- `controllers/registry.py`: TP2 module aliases/raw IDs, family selection, and
  operation-level gating.
- `controllers/haldex_gen4/protocol.py`: Haldex CLI policy, defaults, addresses,
  sessions, security, identification, readout, and flash orchestration.
- `controllers/haldex_gen4/patches.py`: Haldex image validation, checksums,
  anti-brick policy, and exact-manifest simulator patches.
- `controllers/pq_eps/protocol.py`: EPS CLI policy, programming/read security,
  conventional-KWP readout, and the shared flash lifecycle binding.
- `controllers/pq_eps/patches.py`: EPS image/range validation and loader-C5
  checksum preparation. It does not mutate firmware.
- `vag_protocols/`: source-identical canonical TP2 and KWP implementation from Hudiy.
- `j2534.py`: Windows J2534 driver binding.

Family recognition is deliberately broader than patch recognition. `0BR`,
`0AY`, and `0BS` Haldex identities share the Gen4 transport, sessions, flash
layout, and checksum implementation. Firmware-changing features are selected
inside the family package and require exact byte preimages. Consequently an
unknown-but-compatible family member can use safe family operations without
silently inheriting a simulator or future firmware-specific patch set.

`--module` is required and is the only controller selector. It accepts aliases
such as `awd`, `haldex`, `eps`, and `steering`, plus raw TP2 logical IDs such as
`0x0A` and `0x09`. Normal identification, readout, and flash operations query
KWP identifiers `0x9B` and `0x9C` first. Reports expose the software part
number, firmware revision, description, flash status/counters, and raw replies;
controller packages may use those fields as gates before destructive work.
Raw TP2/KWP frame tracing is quiet by default and enabled with `--verbose`.
Identification also decodes the controller's flash date and tool ID. During a
write, the shared engine supplies the host's current local date to the
controller-specific erase/programming payload.


## Commands

On this Windows host, use the project interpreter for J2534:

```powershell
$python = 'C:\Users\raccoon\AppData\Local\Programs\Python\Python311-32\python.exe'
& $python flasher/runner.py --help
& $python flasher/runner.py --module awd --adapter j2534 --readout --dry-run
& $python flasher/runner.py --module 0x0A --adapter j2534 --readout --start 0x30000 --end 0x3ffff --out data/raw/readout/calibration_original
& $python flasher/runner.py --module awd --adapter j2534 --input artifacts/candidate_320k.bin --start 0x18000 --end 0x4ffff --dry-run
```

`--dry-run` does not load a hardware driver, access CAN, or relaunch Python.
Real J2534 access requires 32-bit Python. `run_j2534.bat` selects the standard
per-user Python311-32 installation; set `PYTHON32` to override its path.
`--dll` overrides the J2534 DLL. Panda and SocketCAN can use 64-bit Python.

Only adapter options differ; the same operations work with either backend:

```text
python -m flasher.runner --module awd --adapter panda --bus 0 --readout --out data/raw/readout/panda_original
python -m flasher.runner --module 0x0A --adapter socketcan --channel can0 --readout --out data/raw/readout/socketcan_original
```

Panda requires the comma.ai Panda Python package and supports `--serial` and
`--bus 0|1|2`. The runner sets its bitrate from `--baud` (default 500000),
enables all-output safety for the session, and returns it to silent mode on
close. SocketCAN requires Linux and `python-can`; configure and bring up the
named interface at the ECU bitrate before running. The runner does not change
Linux interface configuration; `--baud` controls J2534/Panda only.

## Image and readout behavior

### PQ35 EPS readout and flashing

The runner has a `pq-eps` target at TP2 logical address `0x09`. Its readout
path probes `ReadMemoryByAddress` (`0x23`) first, then makes at
most one `27 03/04` key attempt using the TT 3001 firmware-derived engineering
slot additive constant `0x1596`, enters session `0x86`, and tries `RequestUpload` (`0x35`)
as a fallback. The readout object remains explicitly write-blocked.

The separate `--read-eeprom` operation saves the complete 1 KiB EPS serial
EEPROM as a raw file. It identifies the application, makes one `27 03/04`
security attempt, enters engineering session `0x86`, sends
`35 00 00 00 00 00 04 00`, and requests 128 eight-byte blocks. The output
file must not already exist. `--eps-sa-add` can override the read-level
additive constant if its exact slot value is established for another rack.

```powershell
& $python flasher/runner.py --module eps --read-eeprom --out data/raw/eps/tt3001_eeprom_1k.bin --dry-run
& $python flasher/runner.py --module eps --read-eeprom --out data/raw/eps/tt3001_eeprom_1k.bin
& $python tools/decode_eps_eeprom_record.py data/raw/eps/tt3001_eeprom_1k.bin
```

The user subsequently supplied a complete 1 KiB TT 3001 rack EEPROM read
(`binaries/8J0909144J_eps_eeprom.bin`); its checksum and DTC records are
decoded in `artifacts/eps_tt_3001_239_re/eeprom_dtc_slots_20260923.md`.

After a new EPS fault, `--read-eps-faults` captures all five stock KWP
fault-slot headers and their three snapshot pages (`21 32` through `21 45`)
as raw application responses in a JSON file. It identifies the EPS, reads
in the default diagnostic session, and does not request security access,
clear faults, or write firmware. It refuses to overwrite an existing file.
Run it while stationary, before clearing the stored event; do not poll KWP
pages routinely while driving.

```powershell
& $python flasher/runner.py --module eps --read-eps-faults --out data/raw/eps/fault_pages.json --dry-run
& $python flasher/runner.py --module eps --read-eps-faults --out data/raw/eps/fault_pages.json
& $python tools/decode_eps_kwp_fault_pages.py data/raw/eps/fault_pages.json
```

The offline decoder checks the predicted TT 3001 page format and reports
internal `0x42` guard operands or internal `0x43` formatted fields when
present. The page layout still needs confirmation from a live response;
keep the raw JSON even if the decoder rejects a field.

For a controlled **stationary** EPS motion check, `--read-eps-motion` reads
stock KWP `21 01` fields 1 and 3. Field 3 is the signed angle-rate value;
its absolute value selects the motion-dependent assist cap, including the
branch at internal magnitude 3650. Field 1 reports the raw byte at
`0x03FF2B39`, which selects a separate post-slew cap curve. Values at or below
38 select that curve's 3072-count minimum knot. The command records both
values, raw responses and host timestamps. KWP latency can miss brief peaks,
so this is a bench or stationary diagnostic check, not a driving logger. It does not request
security access, clear faults, or write firmware. The field's predicted wire
layout still needs a live response check; the raw response is retained.

```powershell
& $python flasher/runner.py --module eps --read-eps-motion --motion-samples 20 --motion-interval-ms 100 --out data/raw/eps/stationary_motion.json --dry-run
& $python flasher/runner.py --module eps --read-eps-motion --motion-samples 20 --motion-interval-ms 100 --out data/raw/eps/stationary_motion.json
```

To establish the rack's **actual** HCA calibration before comparing tests,
read both parameter sectors using the existing read-only CPU readout path,
then identify them offline. This readout uses the EPS `27 03/04` read-access
key; it does not enter programming or write flash. The analyzer verifies the
readout file against `report.json`, refuses to identify a sector with an
unreadable hole, compares complete sectors to pinned 3001/slew/237/239
references, and reports the current `0x5D0A4/A6/A8` values and all three
`0x5E` HCA gain records. A padded `FF` region outside the requested read
range is never treated as captured rack data.

```powershell
& $python flasher/runner.py --module eps --readout --start 0x5D000 --end 0x5EFFF --out data/raw/eps/hca_sectors --dry-run
& $python flasher/runner.py --module eps --readout --start 0x5D000 --end 0x5EFFF --out data/raw/eps/hca_sectors
& $python tools/identify_eps_hca_readout.py data/raw/eps/hca_sectors --out artifacts/eps_hca_sectors_identified.json
```

The readout span is not a flash partition: the TT 3001 resident loader
accepts `0x5D000..0x5DFFF` and `0x5E000..0x5EFFF` separately, but rejects
one `0x5D000..0x5EFFF` write.

For a controlled **stationary** assist comparison, `--read-eps-assist` samples
stock KWP `21 05`. Its four formatter fields correspond to the speed-selected
assist-map output, protected motor request, pre-limiter assist, and published
driver torque. The command saves raw 14-byte application responses and host
timestamps without security access or writes. KWP bandwidth and the stock
compressed fields cannot resolve millisecond response or prove motor current.
Use a distinct output filename for each calibration and command condition.
`tools/decode_tt3001_group05.js` decodes an individual raw response into
intervals of possible internal counts; its field layout still awaits a live
response check.

```powershell
& $python flasher/runner.py --module eps --read-eps-assist --assist-samples 20 --assist-interval-ms 100 --out data/raw/eps/stationary_assist.json --dry-run
& $python flasher/runner.py --module eps --read-eps-assist --assist-samples 20 --assist-interval-ms 100 --out data/raw/eps/stationary_assist.json
node --jitless tools/decode_tt3001_group05.js data/raw/eps/stationary_assist.json
```

For stationary TT 3001 supply-proxy sampling, `--read-eps-supply` requests
KWP `21 02` without security access. It stores each full response, host request
and completion timestamps, and request round-trip time. The first field's
`61 02 06 7D XX` prefix encodes `(u16(raw) >> 3) & 0xFF` from RAM
`0x03FF2BAA`; each byte represents an eight-count interval modulo 2048.
The normal ADC producer range, 19..1703, makes the interval unambiguous on
that path. This proxy is neither a calibrated voltage nor the held rate
factor. Preserve the raw response if the layout differs.

```powershell
& $python flasher/runner.py --module eps --read-eps-supply --supply-samples 20 --supply-interval-ms 100 --out data/raw/eps/stationary_supply.json --dry-run
& $python flasher/runner.py --module eps --read-eps-supply --supply-samples 20 --supply-interval-ms 100 --out data/raw/eps/stationary_supply.json
node --jitless tools/decode_tt3001_group02_supply.js 61 02 06 7D 54
```

For a **stationary** check of the conditional stock `0x6D0/0x6D1` CAN
configuration, `--read-eps-can-config` requests KWP `21 08` without security
access. It saves each complete raw response and host timestamps. A first
field beginning `61 08 6B` contains the secondary configuration halfword
in big-endian wire order; the low byte is the selected transmit-gate input
only when the two runtime configuration selectors choose the secondary
branch. A clear bit 0 is necessary for this branch to request those CAN
frames, but does not prove the branch was selected, page 0 is active, the CAN
controller is ready, or any frame was transmitted. This command does not
change the configuration. Do not routine-poll KWP while driving.

```powershell
& $python flasher/runner.py --module eps --read-eps-can-config --out data/raw/eps/stationary_can_config.json --dry-run
& $python flasher/runner.py --module eps --read-eps-can-config --out data/raw/eps/stationary_can_config.json
```

Always inspect the offline plan first.  A real run requires the EPS to be
reachable through the selected adapter (for example through the vehicle
gateway at the OBD connector):

```powershell
& $python flasher/runner.py --module eps --readout --dry-run
& $python flasher/runner.py --module 0x09 --readout --out data/raw/readout/pq_eps_obd
& $python flasher/runner.py --module eps --input artifacts/eps_3001_slew_test/TT_3001_239_hca_slew4.bin --start 0x5D000 --end 0x5DFFF --dry-run
& $python flasher/runner.py --module eps --adapter j2534 --input artifacts/eps_3001_slew_test/TT_3001_239_hca_slew4.bin --start 0x5D000 --end 0x5DFFF
```

The output is a 393216-byte CPU-linear image padded with `0xff`.  `report.json`
distinguishes bytes actually read from rejected ranges; padding is not evidence
that flash contained `0xff`.  Use `--readout-method read-memory` or `upload` to
force one service while investigating controller variants.

EPS flashing uses programming session `0x85`, security level `27 01/02`,
RequestDownload, routines `C4`/`C5`, TransferData, and StopCommunication `0x82`
through the same RNS-E-Hudiy-derived shared TP2/KWP stack. Input images remain
exactly 393216-byte CPU-linear files. The local preparer currently accepts an
inclusive contiguous range within `0x00A000..0x05FFFF`; the default is the
4 KiB parameter block `0x05D000..0x05DFFF`. For images retaining the captured
TT 3001 resident loader, preparation now checks the loader-bank fingerprint
and requires exact bounds from its partition table. In particular,
`0x28000..0x5DFFF` is rejected locally and by that loader, whereas listed
`0xA000..0x5DFFF` covers the HCA code and excludes the `0x5E` dataset.
SGO-derived images do not contain a resident loader to check, so verify the
selected partition against the actual target loader before using a new range; see
`artifacts/eps_tt_3001_239_re/tt3001_loader_sector_mapping_20260923.md`.
The loader checksum is the
16-bit additive byte sum over precisely the selected range. The image is not
modified, and both a stock `Ende` trailer and an erased `ff ff ff ff` trailer
are accepted. Use `--dry-run` first; a real run retains the destructive `YES`
prompt unless `--yes` is supplied.

Both flash and readout default to the full application `0x18000..0x4ffff`.
The same `--start`/`--end` flags select contiguous whole sectors for either
operation. Allowed sectors are `0x18000..0x1ffff`, `0x20000..0x2ffff`,
`0x30000..0x3ffff`, and `0x40000..0x4ffff`. Partial-sector selections are
rejected before hardware is opened. Images and comparison references must be
exactly 327680 bytes; packed 256 KiB images and file-offset overrides are no
longer supported. Readout uses one pass by default. Each
`passN.bin` is exactly 327680 bytes. CPU addresses are file offsets, the selected
range contains captured bytes, and all unread bytes are `0xff`. The report
records saved ranges even on failure; padding must never be mistaken for
captured bootloader or gap contents. Checksums and `--reference` comparisons
cover captured bytes only. Existing capture directories are refused.

For flashing, explicitly select the minimum whole sectors covering every
changed byte and its checksum. The patcher updates only selected sectors:
checksums in each selected sector, and anti-brick hooks/routine/traps when
`0x20000..0x2ffff` is selected. It changes no bytes outside the selected range. Flash preparation
uses the patcher for the normal resumable flash path and stops if patching
fails. Simulator bypass creation is forbidden in this vehicle workflow. The
final StopCommunication ACK commits and resets; the engine then releases and
reopens the selected adapter for a fresh application identification. This is a
boot check, not a binary readback. If the module is already resident in its
CAN bootloader, `--recovery` skips application identification, application
security, and the programming-session transition; it refuses an application
channel and begins with loader security.

Standalone patching and checksum commands are now in one tool:

```text
python -m flasher.controllers.haldex_gen4.patches input.bin patched.bin
python -m flasher.controllers.haldex_gen4.patches input.bin --verify
python -m flasher.controllers.haldex_gen4.patches input.bin --fix 0x30000 --out corrected.bin
```

`--verify` and `--fix` are checksum-only operations and install no patches.
Verification exits nonzero on a mismatch. `--fix` without `--out` updates the
input, so use a derived output path when preserving original evidence.

## Offline regression checks

```text
python -m unittest discover -s tests -p test_app_flash_dump.py
python -m unittest discover -s tests -p test_tp20_upload_receive.py
python -m unittest discover -s tests -p test_flasher_readout_cli.py
python -m unittest discover -s tests -p test_flasher_shared.py
python -m unittest discover -s tests -p test_flasher_engine.py
python -m unittest discover -s tests -p test_shared_protocols.py
```

These tests exercise simulated protocol exchanges, adapter contracts, cleanup,
padding and checksum scope. They do not establish live Panda/SocketCAN timing
or constitute a post-refactor bench flash. Only the coordinating session may
own hardware, as specified in [AGENTS.md](AGENTS.md).
