# AMIE

**A** **M**inimalist **I**nstruction **E**xtender

AMIE is a Python rework of [FRIEND](https://github.com/alexhude/FRIEND/) that focuses solely on the ARM architecture (only AArch32 and AArch64 are supported). It is both lightweight and dependency-free, and provides the most relevant and up-to-date information about the ARM system registers and instructions.

## Features

### Improved processor modules

For `MCR/MRC` and `MCRR/MRCC` instructions on AArch32, and for `MSR/MRS` and `SYS` instructions on AArch64, the system register encoding is detected and replaced by its user-friendly name in the *IDA View* subview.

<p align="center"><img src="https://i.imgur.com/OOhEgpf.gif"></p>

For `MCR/MRC` and `MSR/MRS` instructions, it also applies to the *Pseudocode* subview.

<p align="center"><img src="https://i.imgur.com/ekYV1hZ.png"></p>

### Hints for instructions and registers

Hovering over a system register in the *IDA View* subview or in the *Pseudocode* subview will display a summary (usually kept under 30 lines) of the relevant documentation page, including the bitfield when available.

<p align="center"><img src="https://i.imgur.com/GK0G8EG.png"></p>

Hovering over an instruction mnemonic in the *IDA View* subview or in the *Pseudocode* subview will also display a summary of the relevant documentation page, and the relevant assembly template when available.

<p align="center"><img src="https://i.imgur.com/S88dDBy.png"></p>

### Auto-generated resource files

The biggest difference with FRIEND is that the resource files (`aarch32.json` and `aarch64.json`) are auto-generated from the [Exploration Tools](https://developer.arm.com/products/architecture/cpu-architecture/a-profile/exploration-tools). The system registers and instructions (documentation and encodings) are extracted by a home-made script that parses the ARM-provided XML files.

## Installation

Copy the plugin file `amie.py`, and its resource files `aarch32.json` and `aarch64.json` to your plugins directory or your user plugins directory (if you want to share it between multiple IDA Pro versions). These are the default paths:

OS      | Plugins Directory                          | User Plugins Directory
--------|--------------------------------------------|-------------------------------------
Windows | `%PROGRAMFILES%\IDA 7.4\plugins`           | `%APPDATA%\Hex-Rays\IDA Pro\plugins`
Linux   | `~/ida-7.4/plugins`                        | `~/.idapro/plugins`
macOS   | `/Applications/IDA Pro 7.4/idabin/plugins` | `~/.idapro/plugins`

## Dependencies

There are no dependencies! :-)

## Improvements

Support for implementation-defined system registers is not available yet.

There is no Hex-Rays support for `MCRR/MRRC` as this is an IDA Pro limitation.

## Credits

* [alexhude](https://github.com/alexhude) for creating the [FRIEND](https://github.com/alexhude/FRIEND/) plugin;
* [gdelugre](https://github.com/gdelugre/) for creating the [ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight/) script;
* The good folks at ARM for releasing the [Exploration Tools](https://developer.arm.com/products/architecture/cpu-architecture/a-profile/exploration-tools);
* [patateqbool](https://github.com/patateqbool) and [0xpanda](https://github.com/0xpanda) for testing the plugin and reporting bugs;
* Quarkslab for allowing this release.
