# Visual analysis workflow for Ghidra

Notes on reverse-engineering workflow in Ghidra, particularly around making a project visually navigable.

Reverse engineering is visually dense. Ghidra projects can contain many functions, generated names, labels, strings, cross-references, and blocks of assembly. A simple visual workflow reduces mental load.

## Core practices

* Rename functions based on evidence.
* Use strings and cross-references to locate important behavior.
* Leave compiler/runtime helper functions alone unless they matter.
* Mark reviewed functions so they are not repeatedly reanalyzed.
* Use color-coding to separate known, unknown, suspicious, and important code.

## Example color system

| Color  | Meaning                                   |
| ------ | ----------------------------------------- |
| Green  | reviewed or understood                    |
| Yellow | needs investigation                       |
| Red    | important or suspicious behavior          |
| Blue   | main program flow                         |
| Purple | encoding, crypto, or transformation logic |

The point is not decoration. The point is reducing mental load while analyzing code.

## Related

This document is general Ghidra workflow advice. For the HiDPI launcher that makes Ghidra's UI readable on high-DPI Linux displays, see [`custom/launchers/linux-hidpi/`](../launchers/linux-hidpi/).
