### Ghidra Hexagon SLEIGH

This is a WIP implementation of the Qualcomm Hexagon "QDSP6" architecture in Ghidra SLEIGH


Supports:
- Dissassembly up to v73, all instructions supported
- Most commonly used constant extenders supported
- No broken java plugins needed
- Support for hardware loops
- Includes support for redacted System/Monitor and System/Guest instructions
- Pcode implemented for most ops, (Only a few never-seen MPY and NV instructions are missing)
- Function start recovery

Currently broken / unimplemented:
- Some immediate extensions are missing for less common ops and most duplexes


(See notes at top of `Hexagon/data/languages/skel.slaspec`) for up to date details:


### How to install
Copy `Hexagon` into `./<ghidra_root>/Ghidra/Processors/` (Confirmed to work on 11.4)
