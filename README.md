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

J2534 needs **32-bit Python** (the J2534 DLLs are 32-bit). Panda and SocketCAN
work with any Python; they need the comma.ai `panda` package or `python-can`.

All examples use `python -m flasher.runner`. Add `--dry-run` to a flash or
readout command to check the plan without touching CAN. A real flash asks you
to type `YES`.

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

The input image's checksums must be valid; a corrupted image is refused, not
repaired. The flasher adds the anti-brick patches, recalculates the checksums
and checks that the controller boots again afterwards.

**Bootlooping or stuck in the bootloader:** add `--recovery` to flash a module
that is already sitting in its CAN bootloader. If it can't even reach that,
use the UART [BSLScripts](BSLScripts/README.md).

**Offline tools:**

```bash
python -m flasher tune_320k.bin                                        # validate an image
python -m flasher.controllers.haldex_gen4.patches tune_320k.bin --verify  # check checksums
python -m flasher.controllers.haldex_gen4.patches tune_320k.bin --fix 0x30000 --out fixed.bin
```

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
partial flash unless the rack reports revision 3000 or newer. The EPS image
is never modified: the flasher only calculates the loader checksum over the
selected range.

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
