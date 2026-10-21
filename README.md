# PQ35 Flasher

This project contains framework code for vw TP2/KWP2000, as well as a functional flasher setup for the ZF Gen3 EPS, and the Gen4 Haldex. It also contains a patcher containing some patches for the haldex and the EPS, namely HCA min speed/timebomb patches for 3001 EPS firmware, and anti brick patches for the haldex (to avoid it ending up in an unflashable bootloop should you successfully flash a bad image to it) 

It can be used with a J2534, a socketcan interface, or a comma panda.

You are at your own risk using this project. I am not responsible for thermonuclear war, broken timing chains, divorce, or you being sad because your EPS no longer works if something goes wrong. 

Bricking a controller beyond recovery is difficult, but not impossible. A failed flash means that controller is not going to be functional until it is recovered, Ie, a failed EPS flash means no EPS. at all. 

The flashing process is basically the following:

Start Diagnostics -> Secure Access -> Start a flash session -> reset (to bootloader) -> Secure access -> Upload Data -> Verify Data -> End Flash Session -> Reset (to application)

Starting a flash session sets a persistent flag to enter bootloader on boot.     Verification is a function where you send the controller a flash region you want checksumed, and the checksum for what you had uploaded, and it confirms/rejects that it matches. Then the flash session can be ended allowing the controller to reboot to application. most controllers will not allow ending without verification, and at least on the haldex, cutting power does not clear the flash session flag.

This means that a flash failing mid flash doesn't result in a bricked controller, merely one that is stuck in its bootloader waiting for you to finish flashing.

The bootloader lacks many identification functions you would normally use in application to verify that a controller is what you think it is to restrict flashing to only the correct binary, so recovery means skipping any of that identification or starting the flash session, and instead going straight to upload. This repo has a --recovery flag to skip those identifactions.

Do not Dumbass with that. Flashing the wrong firmware to a module will brick it.

Controllers can still be bricked by flashing garbage firmware to them. This repo validates that internal firmware checksums match the firmware, and faintly that a provided binary is probably correct for the relevant module in doing that. That is about it.  Flashing garbage firmware can still put a module in an unflashable state, IE, haldex firmware with incorrect checksums will cause a haldex to bootloop. It bootloops faster than a flash session can be started. It cannot be recovered via this repo. This repo prevents that particular oopsie, but still. Do not Dumbass.  Replacing a haldex controller is easy, replacing your EPS - not so much. 

With that said, I have flashed my bench haldex 180 times and my eps 45+ times with various patches and otherwise havent managed to brick either of them. The EPS is flashable in all of its angry states. havent tried flashing a bad checksum to it though.

If the idea of having to actually use the correct firmware binary for your hardware and the risk of bricking your EPS doesn't make sense to you, dont use this repo. Maybe at some point il make a more polished ESP based flasher dongle with a pretty UI that has safeguards etc. but this repo isnt that. 

Do what you want with this stuff, more to be released about the actual editing of these binaries eventually. maybe. This took a lot of human time. I know a lot more secrets about the EPS and haldex then the patches provided in this repo.

remember - 

# Do not Dumb

The golden rule. I will laugh at you if you flash a haldex binary to your EPS. 


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
| gs_usb / candleLight (Windows or Linux, untested) | any | `python -m pip install -r requirements-gs_usb.txt` (`python-can`, `gs_usb`, `pyusb`, `libusb-package`) |
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

0x5E steer datasets are for >3000 firmware versions. the first step if you have <3000 firmware is to well, full firmware flash. I think. need to double check the converted SGO binaries actually contain that range. 

Anything larger than one 4 KiB block is flashed sector by sector in one session:
`27 01/02 → 34 → 31 C4 → 33 C4 → 36… → 37 → 31/33 C5` for each 4 KiB sector. The
loader's erase is blocking, so one whole-range `31 C4` stalls TP2.0 until the channel
drops, and a dropped channel resets the loader's programming state. See
`EPSRe/notes/BOOT_2901_flash.md`.

### EPS patches

```bash
python -m flasher.controllers.pq_eps.patches rack_384k.bin                                   # report CRCs and known patches
python -m flasher.controllers.pq_eps.patches rack_384k.bin --patch hca-timeout-minspeed      # writes rack_384k_hca-timeout-minspeed.bin
python -m flasher.runner --module eps --input rack_384k_hca-timeout-minspeed.bin            # flash the 0x5D block
python -m flasher.controllers.pq_eps.patches rack_384k.bin out.bin --patch hca-timeout-minspeed --patch slew-20 --gains 140,140,140
```

Repeat `--patch` to combine patches. `--gains A,B,C` sets the HCA gains at
0/50/120 km/h for all three steering variants (`A,B,C/D,E,F/G,H,I` sets each
variant on its own). The patcher prints which blocks changed: 0x5D patches go
out with the 0x5D block, gains with the 0x5E dataset. If both changed, flash the
full firmware, or each block on its own.

Available patches:

| Patch | What it does | Block | Firmware |
|---|---|---|---|
| `hca-timeout-minspeed` | Zeroes the HCA disengage countdown (so HCA doesn't time out) and the HCA minimum speed | 0x5D | `8J0909144J` 3001, `8J0909144P`/`1K0909144P` 3305, `1K0909144R` 3501 |
| `slew-up-10` | HCA torque rise step (0x5D0A4) 1 -> 10, matching the fall step | 0x5D | `8J0909144P`/`1K0909144P` 3305 |
| `slew-20` | HCA rise and fall steps (0x5D0A4/0x5D0A6) 1/10 -> 20/20 | 0x5D | `8J0909144P`/`1K0909144P` 3305 |
| `hca-gain-140`, `hca-gain-160`, `--gains` | HCA speed-gain tables (Q7, 128 = 1.0x) | 0x5E | 3001 (`8J0909144J`/`1K0909144J`), 3305, `1K0909144R` 3501, and gen3 4 KiB datasets |

The two slew patches are exclusive. HCA gains are capped at 160: at the largest
HCA input, 160 gives 3.75 Nm against the rack's 3.8 Nm monitor, and tripping that
monitor latches a fault until power is cycled.


**Read-only diagnostics.** None of these unlock programming, clear faults or
write anything. Run them stationary, not while driving.

```bash
python -m flasher.runner --module eps --read-eeprom --out eps_eeprom.bin      # 1 KiB serial EEPROM
python -m flasher.runner --module eps --read-eps-faults --out eps_faults.json # stored fault slots and snapshots
```

There are also `--read-eps-motion`, `--read-eps-assist`, `--read-eps-supply`
and `--read-eps-can-config`, which sample stock measuring blocks into a JSON
file; see `python -m flasher.runner --module eps --help`.

## BCM central electronics (`--module bcm`)

**Read-only page FF dump.** Page FF (global `0x7FC000..0x7FFFFF`, 16 KiB) is
the S12X boot/vector page, which is missing from application dumps. This reads
it through the CPU-local alias the application's upload service exposes
(encoded `0x80C000..0x80FFFF`), as 256 uploads of 0x40 bytes. It checks the
identity (`8P0907063E`/`0575`), makes one seed/key attempt, and then sends
only `35`/`36`/`37`. It never downloads, erases, writes or codes. Not yet run
on hardware.

```bash
python -m flasher.runner --module bcm --read-bcm-pageff                     # into data/raw/readout/pq-bcm/
python -m flasher.runner --module bcm --read-bcm-pageff --out pageFF.bin    # exact file name
```

A directory `--out` (the default is `data/raw/readout/pq-bcm`) gets
`{part}_{sw}_pageFF_{UTC}.bin`. Next to it are a `.json` sidecar with the
SHA-256, chunk count, timing and identity before and after, and a
`.events.jsonl` request/CAN log. A failed read writes no image, only
`*_failed.json` and `*_failed.events.jsonl`, and exits non-zero. On success it
prints the absolute `.bin` path. Existing files are never overwritten.

## Adapters

`--adapter` defaults to `j2534` (the registered DLL; override with `--dll`).

```bash
python -m flasher.runner --module awd --adapter panda --bus 0 --readout --out haldex_readout
python -m flasher.runner --module awd --adapter socketcan --channel can0 --readout --out haldex_readout
python -m flasher.runner --module awd --adapter gs_usb --channel 0 --readout --out haldex_readout
```

Panda: `--serial` picks the device, `--bus 0|1|2` the CAN bus, `--baud` the
bitrate (default 500000). SocketCAN: bring the interface up at the right
bitrate yourself first; `--baud` does not apply.

gs_usb (untested): for candleLight-firmware adapters (CANable, candleLight,
CANtact and similar) without SocketCAN, which is the normal case on Windows.
`--channel` is the USB device index (default 0, in libusb scan order) and
`--baud` sets the bitrate. candleLight firmware asks Windows for the WinUSB
driver itself; if the device does not open, bind WinUSB to it with Zadig. The
adapter echoes every transmitted frame and the echoes are dropped. On Linux
the kernel `gs_usb` driver normally claims the device, so use `--adapter
socketcan` there instead.

Other useful options: `--ident-only` (just identify the module), `--yes` (skip
the `YES` prompt), `--verbose` (raw frame trace), `--log FILE`.

## Code layout

- `runner.py`: command line; picks the adapter and controller.
- `engine.py`: the shared flash and readout state machines.
- `controllers/`: one package per controller (`haldex_gen4`, `pq_eps`, and an
  untested read-only `pq_bcm`) with its addresses, security and image rules.
- `vag_protocols/`: TP2 and KWP2000.
- `j2534.py`, `socketcan_device.py`: adapter bindings. The flasher and readout
  classes take `interface="gs_usb"` (default `"socketcan"`) and a `channel`.
- `readout.py`, `traffic.py`: used by the RNS-E-Hudiy web UI (readout
  progress, and pausing other CAN traffic during a flash).

The tests live in the projects that use this package (HaldexRE and
RNS-E-Hudiy `tests/`). Only one program may use the adapter at a time; see
[AGENTS.md](AGENTS.md).
