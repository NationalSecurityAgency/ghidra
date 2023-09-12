# README

This is a modified version of Ghidra's (v10.2) assembler package for Pickled
Canary.

Changes Copyright (C) 2023 The MITRE Corporation All Rights Reserved

These changes allow for the masks and values of wildcarded operands and
suboperands to be returned after assembling. The masks and values (along with
other data) are stored in instances of the [`AssemblyOperandData`](sleigh/sem/AssemblyOperandData.java)
class, which are placed in a new field in `AssemblyResolution`.

See [Docs/assemblerCallTraceDiagram.svg](Docs/assemblerCallTraceDiagram.svg)
for the code flow of the modified assembler.

See [Docs/operandDataPopulationNew.png](Docs/operandDataPopulationNew.png) for
an overview of how the `AssemblyOperandData` class is populated.

To read about how the modified assembler works, see 
[Docs/The New Ghidra Assembler and Modifications.pdf](Docs/The New Ghidra Assembler and Modifications.pdf).
