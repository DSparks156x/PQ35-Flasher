# PQ35 Flasher

TP2.0/KWP2000 flash, readout and diagnostics for VAG PQ35 controllers over
J2534, Panda or SocketCAN. It started as the Gen4 Haldex flasher and now also
covers the PQ35 EPS rack and (read-only) the BCM.

This is a project to flash and readout a Gen4 VW Haldex Controller, or probably most other modules with little adaptation. It is somewhat probably derived from pq-flasher, that EPS RE project. Testing was mostly done on a clone SM2 pro, hence the 32 bit shit, panda is untested and socketcan should work.

The anti-brick patches trigger the haldex to drop back into bootloader ready to reflash on checksum and some other errors, rather than ending up in an unflashable bootloop. If you do not apply them, a bad checksum or some other errors will put the haldex in a bootloop, as the stock error handling routine for many things basically just freezes and lets the watchdog reset, within about 40ms. You cannot start a flash section in 40ms, and will need to open the controller and recover via BSL. See [BSLScripts](BSLScripts/README.md) for that.

I have flashed this thing over 180 times, I have only had to recover via BSL once.

Do what you want with this stuff, more to be released about the actual editing of this binary eventually. maybe. This took a lot of human time.

The rest of this readme is AI written. It looks fine, but i didn't read it all that thoroughly.

## Supported controllers

| Family | `--module` | TP2 ID | Parts | Operations |
|---|---|---|---|---|
| `haldex-gen4` | `awd`, `haldex`, `allrad` | `0x0A` | `0BR`, `0AY`, `0BS` | identify, readout, flash |
| `pq-eps` | `eps`, `steering` | `0x09` | `1K0909144`, `8J0909144` | identify, readout, flash, EEPROM, faults, motion, assist, supply, CAN config |
| `pq-bcm` | `bcm`, `cent-elec` | `0x20` | `8P0907063E` | identify, readout (flash is a blocked scaffold; not yet run on hardware) |

`--module` is required and is the only controller selector; it also accepts the
raw TP2 ID. Family recognition is deliberately broader than patch recognition:
an unknown but compatible family member can use the safe family operations
without inheriting firmware-specific patches.

## Installing

The import name is `flasher`, so the repository must be checked out in a
folder called `flasher`. Projects use it as a git submodule:

```bash
git submodule add https://github.com/DSparks156x/PQ35-Flasher.git flasher
git submodule update --init
```

Run commands from the parent project's root, where `flasher/` is importable.
For a standalone checkout, clone it as `flasher` and run from the folder above
it:

```bash
git clone https://github.com/DSparks156x/PQ35-Flasher.git flasher
python -m flasher.runner --help
```

Real J2534 access needs 32-bit Python because the J2534 DLLs are 32-bit. Panda
and SocketCAN work with 64-bit Python. `python-can` is needed for SocketCAN,
the comma.ai `panda` package for Panda, and `pyserial` for the BSL scripts.

## Commands

On Windows, use a 32-bit interpreter for J2534:

```powershell
$python = 'C:\Users\raccoon\AppData\Local\Programs\Python\Python311-32\python.exe'
& $python -m flasher.runner --help
& $python -m flasher.runner --module awd --ident-only
& $python -m flasher.runner --module awd --readout --dry-run
& $python -m flasher.runner --module awd --readout --out data/raw/readout/haldex_original
& $python -m flasher.runner --module awd --input candidate_320k.bin --dry-run
& $python -m flasher.runner --module awd --input candidate_320k.bin
```

`--adapter` defaults to `j2534`. `--dry-run` does not load a hardware driver or
access CAN; always inspect the plan first. A real flash asks for `YES` unless
`--yes` is given. `--dll` overrides the registry-discovered J2534 DLL,
`--verbose` traces raw TP2/KWP frames, and `--log FILE` writes a session log.
Families add their own options, which show with the module selected, for
example `--module eps --help`.

Only adapter options differ between backends:

```text
python -m flasher.runner --module awd --adapter panda --bus 0 --readout --out data/raw/readout/panda_original
python -m flasher.runner --module 0x0A --adapter socketcan --channel can0 --readout --out data/raw/readout/socketcan_original
```

Panda supports `--serial` and `--bus 0|1|2`; the runner sets its bitrate from
`--baud` (default 500000), enables all-output safety for the session and
returns it to silent mode on close. SocketCAN requires Linux; configure and
bring up the interface at the ECU bitrate first. The runner does not change
Linux interface configuration, so `--baud` applies to J2534 and Panda only.

Normal identification, readout and flash operations query KWP identifiers
`0x9B` and `0x9C` first. Reports expose the software part number, firmware
revision, description, flash status/counters, flash date, tool ID and raw
replies; controller packages use those fields as gates before destructive
work. During a write the engine supplies the host's local date to the
controller's programming payload.

The final StopCommunication ACK commits and resets the controller. The engine
then reopens the adapter for a fresh application identification. That is a
boot check, not a binary readback. If the module is already sitting in its CAN
bootloader, `--recovery` skips application identification, application
security and the programming-session transition, and starts with loader
security.

## Haldex Gen4

Images and comparison references are exactly 327680-byte (320 KiB)
CPU-linear files. Flash and readout both default to the full application
`0x18000..0x4ffff`. `--start`/`--end` select contiguous whole sectors:
`0x18000..0x1ffff`, `0x20000..0x2ffff`, `0x30000..0x3ffff` and
`0x40000..0x4ffff`. Partial sectors are rejected before hardware is opened.

The patcher only accepts an input image whose four Layer-1 checksums are
valid. A mismatched image is refused rather than repaired, so a corrupted
image can never be flashed with a freshly valid checksum. On a valid image it
applies the exact-preimage anti-brick hooks, routine and trap hardening when
`0x20000..0x2ffff` is selected, then recalculates the checksums of the
selected sectors. It changes no bytes outside the selected range.
`--simulator-mode` additionally applies bench simulator bypasses that require
the known firmware-layout manifest; never use a simulator-mode image in a car.

Readout uses one pass by default (`--readout-passes 2` for two). Each
`passN.bin` is exactly 327680 bytes; the selected range holds captured bytes
and everything else is `0xff` padding, which must never be mistaken for
captured bootloader contents. `report.json` records saved ranges even on
failure. Checksums and `--reference` comparisons cover captured bytes only.
Existing capture directories are refused.

Standalone patch and checksum tools:

```text
python -m flasher.controllers.haldex_gen4.patches input.bin patched.bin
python -m flasher.controllers.haldex_gen4.patches input.bin --verify
python -m flasher.controllers.haldex_gen4.patches input.bin --fix 0x30000 --out corrected.bin
python -m flasher input.bin
```

`--verify` and `--fix` are checksum-only operations and install no patches.
Verification exits nonzero on a mismatch. `--fix` without `--out` updates the
input in place, so use a derived output path when preserving evidence.
`python -m flasher input.bin` validates a vehicle image entirely offline
(`--start`/`--end` select the range) and prints the prepared metadata.

## PQ35 EPS

The `pq-eps` family is at TP2 ID `0x09`. The decoder tools named below
(`tools/…`) and the referenced `artifacts/…` notes live in the HaldexRE
project, not in this repository.

### Readout

Readout probes `ReadMemoryByAddress` (`0x23`) first, then makes at most one
`27 03/04` key attempt using the TT 3001 firmware-derived engineering slot
additive constant `0x1596`, enters session `0x86`, and falls back to
`RequestUpload` (`0x35`). The readout object is explicitly write-blocked.

```powershell
& $python -m flasher.runner --module eps --readout --dry-run
& $python -m flasher.runner --module 0x09 --readout --out data/raw/readout/pq_eps_obd
```

The output is a 393216-byte CPU-linear image padded with `0xff`. `report.json`
distinguishes bytes actually read from rejected ranges; padding is not evidence
that flash contained `0xff`. `--readout-method read-memory` or `upload` forces
one service while investigating controller variants.

To establish the rack's actual HCA calibration before comparing tests, read
both parameter sectors with the read-only path (it uses the `27 03/04`
read-access key and never enters programming), then identify them offline:

```powershell
& $python -m flasher.runner --module eps --readout --start 0x5D000 --end 0x5EFFF --out data/raw/eps/hca_sectors
& $python tools/identify_eps_hca_readout.py data/raw/eps/hca_sectors --out artifacts/eps_hca_sectors_identified.json
```

The analyzer verifies the readout against `report.json`, refuses sectors with
unreadable holes, compares complete sectors to pinned 3001/slew/237/239
references, and reports the `0x5D0A4/A6/A8` values and all three `0x5E` HCA
gain records. The readout span is not a flash partition: the TT 3001 resident
loader accepts `0x5D000..0x5DFFF` and `0x5E000..0x5EFFF` separately but
rejects one `0x5D000..0x5EFFF` write.

### Flashing

EPS flashing uses programming session `0x85`, security level `27 01/02`,
RequestDownload, routines `C4`/`C5`, TransferData and StopCommunication `0x82`.
Input images are exactly 393216-byte CPU-linear files. The preparer accepts an
inclusive contiguous range within `0x00A000..0x05FFFF`; the default is the
4 KiB parameter block `0x05D000..0x05DFFF`. For images that retain the
captured TT 3001 resident loader, preparation checks the loader-bank
fingerprint and requires exact bounds from its partition table: for example
`0x28000..0x5DFFF` is rejected, while `0xA000..0x5DFFF` covers the HCA code
and excludes the `0x5E` dataset. SGO-derived images have no resident loader
to check, so verify the partition against the actual target loader before
using a new range (see
`artifacts/eps_tt_3001_239_re/tt3001_loader_sector_mapping_20260923.md`).
The loader checksum is the 16-bit additive byte sum over exactly the selected
range. The image is not modified, and both a stock `Ende` trailer and an
erased `ff ff ff ff` trailer are accepted.

```powershell
& $python -m flasher.runner --module eps --input TT_3001_239_hca_slew4.bin --start 0x5D000 --end 0x5DFFF --dry-run
& $python -m flasher.runner --module eps --input TT_3001_239_hca_slew4.bin --start 0x5D000 --end 0x5DFFF
```

### Read-only diagnostics

None of these request programming access, clear faults or write anything,
and each refuses to overwrite an existing output file. They are stationary
or bench checks: KWP latency misses brief peaks, so do not poll KWP pages
while driving. Where a field layout is still predicted rather than confirmed,
the raw response is kept.

- `--read-eeprom` saves the complete 1 KiB serial EEPROM. It identifies the
  application, makes one `27 03/04` attempt, enters session `0x86`, sends
  `35 00 00 00 00 00 04 00` and requests 128 eight-byte blocks.
  `--eps-sa-add` overrides the read-level additive constant for another rack.
  Decode with `tools/decode_eps_eeprom_record.py`.
- `--read-eps-faults` captures all five stock KWP fault-slot headers and their
  snapshot pages (`21 32` through `21 45`) in the default session. Run it
  before clearing the stored event. Decode with
  `tools/decode_eps_kwp_fault_pages.py`.
- `--read-eps-motion` samples `21 01` fields 1 and 3. Field 3 is the signed
  angle rate whose magnitude selects the motion-dependent assist cap
  (including the branch at 3650); field 1 is the raw byte at `0x03FF2B39`,
  which selects the post-slew cap curve (38 or below selects its 3072-count
  minimum knot). `--motion-samples` / `--motion-interval-ms`.
- `--read-eps-assist` samples `21 05`: speed-selected assist-map output,
  protected motor request, pre-limiter assist and published driver torque.
  It cannot resolve millisecond response or prove motor current.
  `--assist-samples` / `--assist-interval-ms`; decode a response with
  `tools/decode_tt3001_group05.js`.
- `--read-eps-supply` samples `21 02`. The `61 02 06 7D XX` prefix encodes
  `(u16(raw) >> 3) & 0xFF` from RAM `0x03FF2BAA`, an eight-count interval
  modulo 2048 that is unambiguous over the normal ADC range 19..1703. It is a
  supply proxy, not a calibrated voltage. `--supply-samples` /
  `--supply-interval-ms`; decode with `tools/decode_tt3001_group02_supply.js`.
- `--read-eps-can-config` reads `21 08`. A first field beginning `61 08 6B`
  holds the secondary configuration halfword (big-endian); its low byte is the
  transmit-gate input for the conditional stock `0x6D0/0x6D1` frames only when
  the runtime selectors choose the secondary branch. A clear bit 0 is necessary
  for those frames but does not prove they were sent.
  `--can-config-samples` / `--can-config-interval-ms`.

```powershell
& $python -m flasher.runner --module eps --read-eeprom --out data/raw/eps/tt3001_eeprom_1k.bin
& $python -m flasher.runner --module eps --read-eps-faults --out data/raw/eps/fault_pages.json
& $python -m flasher.runner --module eps --read-eps-motion --motion-samples 20 --motion-interval-ms 100 --out data/raw/eps/stationary_motion.json
& $python -m flasher.runner --module eps --read-eps-assist --assist-samples 20 --assist-interval-ms 100 --out data/raw/eps/stationary_assist.json
& $python -m flasher.runner --module eps --read-eps-supply --supply-samples 20 --supply-interval-ms 100 --out data/raw/eps/stationary_supply.json
& $python -m flasher.runner --module eps --read-eps-can-config --out data/raw/eps/stationary_can_config.json
```

## PQ BCM

The `pq-bcm` family (TP2 ID `0x20`, `8P0907063E`) identifies the controller
and reads memory with the read key; flashing is scaffolded and blocked. It
has not yet been exercised on hardware.

## Layout

- `runner.py`: command line. Selects the adapter and module and dispatches a
  generic operation; it holds no controller-specific ranges or workflows.
- `engine.py`: controller-neutral programming and memory-read state machines,
  SecurityAccess algorithms, reconnect, transfer, commit, capture and boot check.
- `controllers/registry.py`: module aliases, raw IDs, family selection and
  per-operation gating.
- `controllers/<family>/protocol.py`: that family's CLI policy, addresses,
  sessions, security, identification, readout and flash orchestration.
- `controllers/<family>/patches.py`: image validation, checksums and patch
  policy (Haldex anti-brick and simulator patches; EPS range and loader-C5
  checksum preparation, which never modifies firmware).
- `vag_protocols/`: the canonical TP2 and KWP implementation (see its
  [README](vag_protocols/README.md)).
- `j2534.py`, `socketcan_device.py`: adapter bindings (Panda uses the comma.ai
  package directly).
- `readout.py`: readout progress, naming and persistence around the
  application readers, used by the Hudiy web UI.
- `traffic.py`: cross-process inhibition of normal application CAN
  transmissions while a flash owns the bus (Linux `flock`).
- `__main__.py`: the offline image validator.
- `BSLScripts/`: UART bootstrap-loader recovery for a bootlooping Haldex.

## Tests

The regression tests live in the projects that use this package, and run
there against the submodule:

- HaldexRE `tests/`: `test_flasher_engine.py`, `test_flasher_shared.py`,
  `test_flasher_readout_cli.py`, `test_shared_protocols.py`,
  `test_tp20_upload_receive.py`, `test_app_flash_dump.py`.
- RNS-E-Hudiy `tests/`: `test_flasher_engine.py`, `test_flasher_transport.py`,
  `test_flashing_mode.py`, `test_readout.py`, `test_pq_eps_readout.py`,
  `test_shared_protocols.py`, `test_tp2_*.py`.

They exercise simulated protocol exchanges, adapter contracts, cleanup,
padding and checksum scope. They do not establish live Panda/SocketCAN timing
or replace a bench flash. Only one process may own the hardware; see
[AGENTS.md](AGENTS.md).
