# PQ35 Flasher

Flash and read VAG PQ35 controllers over TP2.0/KWP2000 with a J2534, Panda or
SocketCAN adapter: the Gen4 Haldex and the EPS steering rack.

This is a project to flash and readout a Gen4 VW Haldex Controller, or probably most other modules with little adaptation. It is somewhat probably derived from pq-flasher, that EPS RE project. Testing was mostly done on a clone SM2 pro, hence the 32 bit shit, panda is untested and socketcan should work.

The anti-brick patches trigger the haldex to drop back into bootloader ready to reflash on checksum and some other errors, rather than ending up in an unflashable bootloop. If you do not apply them, a bad checksum or some other errors will put the haldex in a bootloop, as the stock error handling routine for many things basically just freezes and lets the watchdog reset, within about 40ms. You cannot start a flash section in 40ms, and will need to open the controller and recover via BSL. See [BSLScripts](BSLScripts/README.md) for that.

I have flashed this thing over 180 times, I have only had to recover via BSL once.

Do what you want with this stuff, more to be released about the actual editing of this binary eventually. maybe. This took a lot of human time.

## Setup

The package imports as `flasher`, so the checkout must be a folder named
`flasher`. Either add it to a project as a submodule, or clone it on its own
and run from the folder above it:

```bash
git submodule add https://github.com/DSparks156x/PQ35-Flasher.git flasher
git clone https://github.com/DSparks156x/PQ35-Flasher.git flasher
```

Tested on Python 3.11 (32-bit) and 3.12. The flasher itself only
uses the standard library. Which extra you need depends on your adapter:

| Adapter | Python | Install |
| --- | --- | --- |
| J2534 (default, Windows) | **32-bit** (the J2534 DLLs are 32-bit) | nothing; just install your adapter's J2534 driver |
| SocketCAN (Linux) | any | `python -m pip install -r requirements-socketcan.txt` (`python-can`) |
| Panda (untested) | any | `python -m pip install -r requirements-panda.txt` (`pandacan`) |
| BSL recovery scripts | any | `python -m pip install -r BSLScripts/requirements.txt` (`pyserial`) |

Run these from inside the checkout.

All examples use `python -m flasher.runner`. Add `--dry-run` to a flash or
readout command to check the plan without touching CAN. A real flash asks you
to type `YES`.

## What happens to your image

Every flash reads your file, checks it, may patch a copy in memory, and sends
only the selected range. The file on disk is never changed. `--dry-run`
prints the full plan, including every patched byte range and the checksums.

Each controller has its own image rules:

| Module | Size check | Checks checksums inside the image | Patches it | Checksums it calculates |
|---|---|---|---|---|
| Haldex Gen4 (`awd`) | 320 KiB | Yes: Layer-1 word in all four app blocks must be valid (`--correct-checksum` to override) | Yes: anti-brick recovery, always | Layer-1 for flashed blocks, plus the loader's `0xC5` sum |
| EPS rack (`eps`) | 384 KiB, or a 4 KiB `0x5E` dataset | Yes: the dataset CRC16s must be valid (`--correct-checksum` to override) | Never (only CRC words, with `--correct-checksum`) | The loader's `0xC5` sum over the flashed range |
| BCM (`bcm`) | Must match `--start`/`--end` | No | Never | None yet; flash is an unfinished scaffold |

The loader's `0xC5` checksum is a 16-bit sum of every byte sent. The flasher
calculates it, and the controller's bootloader checks it after the transfer.
It catches transfer errors only. It says nothing about whether the firmware
inside is consistent.

`--correct-checksum` works on the Haldex and the EPS. It accepts an image
whose internal checksums are wrong and recalculates them for the blocks being
flashed. Each one it fixes is printed as a `WARNING`. Only use it on an image
you edited yourself and know is otherwise intact. The module sections below
say which checksums each controller has. The flasher checks nothing beyond
those: for example, no checksum over the EPS program code is known, so none
is checked.

## Haldex Gen4 (`--module awd`)

Images are 320 KiB CPU-linear files. Normally you read and flash the whole
application, `0x18000..0x4FFFF`, which is the default for both.

**Read out:**

```bash
python -m flasher.runner --module awd --readout --out haldex_readout
```

This writes `pass1.bin` (320 KiB; unread areas are `0xFF` padding) and
`report.json` into a new `haldex_readout` folder.

**Flash:**

```bash
python -m flasher.runner --module awd --input tune_320k.bin
```

The flasher adds the anti-brick patches and recalculates the checksums.
Afterwards it checks that the controller boots again. Run with `--dry-run`
first to see every byte range that will change.

### What the flasher checks and patches

**Checks on the input image** (anything that fails is refused before CAN is
touched):

- It is exactly 320 KiB (`0x50000` bytes), CPU-linear. 64 KiB calibration
  files and raw dumps are rejected.
- All four application blocks have a valid Layer-1 checksum: the last 16-bit
  word of each block equals the one's complement of the little-endian 16-bit
  word sum of the rest of the block. The blocks are:

  | Block | Range | Checksum word at |
  |---|---|---|
  | B0F4 | `0x18000..0x1FFFF` | `0x1FFFE` |
  | B0F5 | `0x20000..0x2FFFF` | `0x2FFFE` |
  | B0F6 (tuning tables) | `0x30000..0x3FFFF` | `0x3FFFE` |
  | B0F7 | `0x40000..0x4FFFF` | `0x4FFFE` |

  This catches a truncated download or an accidental edit. The flasher won't
  fix this for you by default, because then it would flash the corruption with
  a fresh valid checksum. If you edited the tables on purpose, either fix the
  checksum offline (see below) or add `--correct-checksum`.
- The anti-brick patch locations must hold either the stock bytes or the
  patch already in place. Anything else (a different firmware layout, or
  someone else's patch) is refused.
- `--start`/`--end` must cover whole blocks.

**Patches it always applies** (only when B0F5, `0x20000..0x2FFFF`, is in the
flashed range; they all live in that block):

- An anti-brick reset routine at `0x2027C`. It sets the RAM flag that keeps
  the bootloader waiting for CAN, then resets the CPU.
- A hook at `0x20364`, the firmware's panic handler (a failed startup
  checksum lands there), that calls that routine instead of hanging until the
  watchdog fires.
- Every unused trap vector in `0x20002..0x20200` that just loops forever is
  pointed at the same routine, so illegal opcodes, stack faults and bus
  errors also land in the bootloader.

Re-flashing an image that already has these patches is fine; they are
recognised and left as they are.

**Checksums:** after patching, the Layer-1 checksum of every block in the
flashed range is recalculated. The loader's `0xC5` transfer checksum (a plain
byte sum of the flashed range) is calculated for you too.

**What it does not do:**

- It does not touch any tuning data, or anything outside the selected
  range. Blocks outside `--start`/`--end` are neither changed nor sent.
- It does not repair a bad input checksum unless you pass
  `--correct-checksum`.
- Bench simulator patches (`--simulator-mode`) are off by default. They force
  the controller's state machine into normal operation and hide valve and
  pump faults, so it runs on a bench without the rest of the car. Never put
  them in a car.

**`--correct-checksum`:** accepts an input with wrong Layer-1 checksums and
recalculates them for the flashed blocks. Each corrected block is printed as a
`WARNING`, and listed under `input_checksum_mismatches` in the dry-run output.
Only use it on an image you edited yourself and know is otherwise intact:

```bash
python -m flasher.runner --module awd --input tune_320k.bin --correct-checksum --dry-run
```

**Bootlooping or stuck in the bootloader:** add `--recovery` to flash a module
that is already sitting in its CAN bootloader. If it can't even reach that,
use the UART [BSLScripts](BSLScripts/README.md).

**Offline tools:**

```bash
python -m flasher tune_320k.bin                                        # validate an image
python -m flasher.controllers.haldex_gen4.patches tune_320k.bin --verify  # check checksums
python -m flasher.controllers.haldex_gen4.patches tune_320k.bin --fix 0x30000 --out fixed.bin
python -m flasher.controllers.haldex_gen4.patches tune_320k.bin        # write tune_320k_patched.bin
```

`--verify` prints each block's stored and calculated checksum and exits
non-zero on a mismatch. `--fix ADDR` rewrites only that block's checksum
word. With no option, the patcher writes the same anti-brick patched image
the flasher would send (`--correct-checksum` works here too), which is
useful for diffing or for flashing with another tool.

## EPS steering rack (`--module eps`)

Images are 384 KiB CPU-linear files. There are three normal flash targets:

| Target | Range | How to select |
|---|---|---|
| Full firmware | `0x0A000..0x5FFFF` | `--start 0x0A000 --end 0x5FFFF` |
| `0x5D` configuration block | `0x5D000..0x5DFFF` | default for a 384 KiB image |
| `0x5E` steer dataset | `0x5E000..0x5EFFF` | `--start 0x5E000 --end 0x5EFFF`, or pass a 4 KiB dataset file |

```bash
python -m flasher.runner --module eps --input rack_384k.bin --start 0x0A000 --end 0x5FFFF
python -m flasher.runner --module eps --input rack_384k.bin
python -m flasher.runner --module eps --input steer_dataset_4k.bin
```

The `0x5D` and `0x5E` blocks only exist on Gen3 racks running firmware 3000
or newer; older firmware doesn't have those datasets. So step 1 for a rack
below 3000 is a full firmware flash to update it. The flasher refuses a
partial flash unless the rack reports revision 3000 or newer.

The flasher never patches EPS firmware while flashing. Patch the image
offline first, then flash the result like any other image.

### EPS patches

```bash
python -m flasher.controllers.pq_eps.patches rack_384k.bin                                   # report CRCs and known patches
python -m flasher.controllers.pq_eps.patches rack_384k.bin --patch hca-timeout-minspeed      # writes rack_384k_hca-timeout-minspeed.bin
python -m flasher.runner --module eps --input rack_384k_hca-timeout-minspeed.bin            # flash the 0x5D block
```

Available patches:

| Patch | What it does | Firmware |
|---|---|---|
| `hca-timeout-minspeed` | Zeroes the HCA disengage countdown (so HCA doesn't time out) and the HCA minimum speed | `8J0909144J` 3001, `1K0909144R` 3501 |

Each patch has a separate manifest for each firmware it supports. The
patcher picks the manifest from the software number and version in the image.
A manifest lists the exact stock bytes at every address it changes. It
refuses an image where any of those bytes are something else, such as a
different firmware or someone else's edit. Patching an image that already
has the patch changes nothing.

The patcher also checks the dataset CRCs first and rewrites them afterwards.
It replaces the `Ende` end marker with `ff ff ff ff`, like the original
pq-flasher patcher did.

The patched bytes are in the `0x5D` configuration block, so the default `0x5D`
flash sends them along with their CRC. The end marker only goes out with a full
firmware flash. The flasher's `--dry-run` lists any known patch it finds in an
image (`known_patches`).

These were ported from pq-flasher's `02_patcher.py` (`3001_v2_hca` and
`3501`). The 3001 output is byte-identical to the existing
`TT_3001_239_hca.bin`. To add another patch or firmware, add a
`PatchManifest` to `PATCH_MANIFESTS` in `controllers/pq_eps/patches.py`.

### EPS dataset checksums

The datasets carry CRC-16/XMODEM words (poly `0x1021`, init 0, stored
big-endian). The flasher checks all of them before anything is sent. Which
words exist depends on the firmware generation, which the flasher detects
from the `78 56 34 12` marker just before the CRC words:

| Firmware | Marker at | CRC word | Covers |
|---|---|---|---|
| 3000+ | `0x5DFF8` | `0x5DFFC` | `0x5C000..0x5CFFE` (`0x5C` dataset) |
| | | `0x5DFFE` | `0x5CFFF..0x5DFFB` (`0x5D` configuration) |
| | | `0x5EFFE` | `0x5E000..0x5EFFD` (`0x5E` steer dataset) |
| below 3000 | `0x5EFF8` | `0x5EFFC` | `0x5E000..0x5EFFB` |
| 4 KiB `0x5E` file | | last word | the rest of the file |

The odd `0x5CFFF` boundary is real: that byte (always `0xFF`) belongs to the
`0x5D` CRC. These ranges were checked against 41 stock and tuned rack images
from 2301 to 3501. An image with no marker is refused. So is a 4 KiB file
that is really a `0x5D` block, since it would otherwise be flashed to
`0x5E`.

With `--correct-checksum`, a wrong CRC is only fixed when its word and all
the data it covers are inside the flashed range. Otherwise the rack would end
up holding a CRC that doesn't match its other blocks. For example, if you
edited the `0x5C` dataset, flash `--start 0x5C000 --end 0x5DFFF`, not just
the default `0x5D` block.

The rack does not give its flash back over TP2/KWP, so there is no firmware
readout. (`--readout` is an experimental probe and the rack refuses it.)

**Read-only diagnostics.** None of these unlock programming, clear faults or
write anything. Run them stationary, not while driving.

```bash
python -m flasher.runner --module eps --read-eeprom --out eps_eeprom.bin      # 1 KiB serial EEPROM
python -m flasher.runner --module eps --read-eps-faults --out eps_faults.json # stored fault slots and snapshots
```

There are also `--read-eps-motion`, `--read-eps-assist`, `--read-eps-supply`
and `--read-eps-can-config`, which sample stock measuring blocks into a JSON
file; see `python -m flasher.runner --module eps --help`.

## Adapters

`--adapter` defaults to `j2534` (the registered DLL; override with `--dll`).

```bash
python -m flasher.runner --module awd --adapter panda --bus 0 --readout --out haldex_readout
python -m flasher.runner --module awd --adapter socketcan --channel can0 --readout --out haldex_readout
```

Panda: `--serial` picks the device, `--bus 0|1|2` the CAN bus, `--baud` the
bitrate (default 500000). SocketCAN: bring the interface up at the right
bitrate yourself first; `--baud` does not apply.

Other useful options: `--ident-only` (just identify the module), `--yes` (skip
the `YES` prompt), `--verbose` (raw frame trace), `--log FILE`.

## Code layout

- `runner.py`: command line; picks the adapter and controller.
- `engine.py`: the shared flash and readout state machines.
- `controllers/`: one package per controller (`haldex_gen4`, `pq_eps`, and an
  untested read-only `pq_bcm`) with its addresses, security and image rules.
- `vag_protocols/`: TP2 and KWP2000.
- `j2534.py`, `socketcan_device.py`: adapter bindings.
- `readout.py`, `traffic.py`: used by the RNS-E-Hudiy web UI (readout
  progress, and pausing other CAN traffic during a flash).

The tests live in the projects that use this package (HaldexRE and
RNS-E-Hudiy `tests/`). Only one program may use the adapter at a time; see
[AGENTS.md](AGENTS.md).
