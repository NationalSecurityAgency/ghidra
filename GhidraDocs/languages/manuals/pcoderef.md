# P-Code Reference Manual

Last updated January 16, 2026

|  |  |  |
| --- | --- | --- |
| [COPY](pcodedescription.md#copy) | [INT_ADD](pcodedescription.md#int_add) | [BOOL_OR](pcodedescription.md#bool_or) |
| [LOAD](pcodedescription.md#load) | [INT_SUB](pcodedescription.md#int_sub) | [FLOAT_EQUAL](pcodedescription.md#float_equal) |
| [STORE](pcodedescription.md#store) | [INT_CARRY](pcodedescription.md#int_carry) | [FLOAT_NOTEQUAL](pcodedescription.md#float_notequal) |
| [BRANCH](pcodedescription.md#branch) | [INT_SCARRY](pcodedescription.md#int_scarry) | [FLOAT_LESS](pcodedescription.md#float_less) |
| [CBRANCH](pcodedescription.md#cbranch) | [INT_SBORROW](pcodedescription.md#int_sborrow) | [FLOAT_LESSEQUAL](pcodedescription.md#float_lessequal) |
| [BRANCHIND](pcodedescription.md#branchind) | [INT_2COMP](pcodedescription.md#int_2comp) | [FLOAT_ADD](pcodedescription.md#float_add) |
| [CALL](pcodedescription.md#call) | [INT_NEGATE](pcodedescription.md#int_negate) | [FLOAT_SUB](pcodedescription.md#float_sub) |
| [CALLIND](pcodedescription.md#callind) | [INT_XOR](pcodedescription.md#int_xor) | [FLOAT_MULT](pcodedescription.md#float_mult) |
| [CALLOTHER](pseudo-ops.md#callother) | [INT_AND](pcodedescription.md#int_and) | [FLOAT_DIV](pcodedescription.md#float_div) |
| [RETURN](pcodedescription.md#return) | [INT_OR](pcodedescription.md#int_or) | [FLOAT_NEG](pcodedescription.md#float_neg) |
| [PIECE](pcodedescription.md#piece) | [INT_LEFT](pcodedescription.md#int_left) | [FLOAT_ABS](pcodedescription.md#float_abs) |
| [SUBPIECE](pcodedescription.md#subpiece) | [INT_RIGHT](pcodedescription.md#int_right) | [FLOAT_SQRT](pcodedescription.md#float_sqrt) |
| [POPCOUNT](pcodedescription.md#popcount) | [INT_SRIGHT](pcodedescription.md#int_sright) | [FLOAT_CEIL](pcodedescription.md#float_ceil) |
| [LZCOUNT](pcodedescription.md#lzcount) | [INT_MULT](pcodedescription.md#int_mult) | [FLOAT_FLOOR](pcodedescription.md#float_floor) |
| [INT_EQUAL](pcodedescription.md#int_equal) | [INT_DIV](pcodedescription.md#int_div) | [FLOAT_ROUND](pcodedescription.md#float_round) |
| [INT_NOTEQUAL](pcodedescription.md#int_notequal) | [INT_REM](pcodedescription.md#int_rem) | [FLOAT_NAN](pcodedescription.md#float_nan) |
| [INT_LESS](pcodedescription.md#int_less) | [INT_SDIV](pcodedescription.md#int_sdiv) | [INT2FLOAT](pcodedescription.md#int2float) |
| [INT_SLESS](pcodedescription.md#int_sless) | [INT_SREM](pcodedescription.md#int_srem) | [FLOAT2FLOAT](pcodedescription.md#float2float) |
| [INT_LESSEQUAL](pcodedescription.md#int_lessequal) | [BOOL_NEGATE](pcodedescription.md#bool_negate) | [TRUNC](pcodedescription.md#trunc) |
| [INT_SLESSEQUAL](pcodedescription.md#int_slessequal) | [BOOL_XOR](pcodedescription.md#bool_xor) | [CPOOLREF](pseudo-ops.md#cpoolref) |
| [INT_ZEXT](pcodedescription.md#int_zext) | [BOOL_AND](pcodedescription.md#bool_and) | [NEW](pseudo-ops.md#new) |
| [INT_SEXT](pcodedescription.md#int_sext) |  |  |

## A Brief Introduction to P-Code

P-code is a *register transfer language* designed for reverse engineering applications. The language
is general enough to model the behavior of many different processors. By modeling in this way, the
analysis of different processors is put into a common framework, facilitating the development of
retargetable analysis algorithms and applications.

Fundamentally, p-code works by translating individual processor instructions into a sequence of
**p-code operations** that take parts of the processor state as input and output variables
(**varnodes**). The set of unique p-code operations (distinguished by **opcode**) comprise a fairly
tight set of the arithmetic and logical actions performed by general purpose processors. The direct
translation of instructions into these operations is referred to as **raw p-code**. Raw p-code can
be used to directly emulate instruction execution and generally follows the same control-flow,
although it may add some of its own internal control-flow. The subset of opcodes that can occur in
raw p-code is described in [the section called “P-Code Operation Reference”](pcodedescription.md)
and in [the section called “Pseudo P-CODE Operations”](pseudo-ops.md), making up the bulk of this
document.

P-code is designed specifically to facilitate the construction of *data-flow* graphs for follow-on
analysis of disassembled instructions. Varnodes and p-code operators can be thought of explicitly as
nodes in these graphs. Generation of raw p-code is a necessary first step in graph construction, but
additional steps are required, which introduces some new opcodes. Two of these, **MULTIEQUAL** and
**INDIRECT**, are specific to the graph construction process, but other opcodes can be introduced
during subsequent analysis and transformation of a graph and help hold recovered data-type
relationships. All of the new opcodes are described in [the section called “Additional P-CODE
Operations”](additionalpcode.md), none of which can occur in the original raw p-code translation.
Finally, a few of the p-code operators, **CALL**, **CALLIND**, and **RETURN**, may have their input
and output varnodes changed during analysis so that they no longer match their *raw p-code* form.

The core concepts of p-code are:

### Address Space

The **address space** for p-code is a generalization of RAM. It is defined simply as an indexed
sequence of bytes that can be read and written by the p-code operations. For a specific byte, the
unique index that labels it is the byte's **address**. An address space has a name to identify it, a
size that indicates the number of distinct indices into the space, and an **endianness** associated
with it that indicates how integers and other multi-byte values are encoded into the space. A
typical processor will have a **ram** space, to model memory accessible via its main data bus, and a
**register** space for modeling the processor's general purpose registers. Any data that a processor
manipulates must be in some address space. The specification for a processor is free to define as
many address spaces as it needs. There is always a special address space, called a **constant**
address space, which is used to encode any constant values needed for p-code operations. Systems
generating p-code also generally use a dedicated **temporary** space, which can be viewed as a
bottomless source of temporary registers. These are used to hold intermediate values when modeling
instruction behavior.

P-code specifications allow the addressable unit of an address space to be bigger than just a byte.
Each address space has a **wordsize** attribute that can be set to indicate the number of bytes in a
unit. A wordsize which is bigger than one makes little difference to the representation of p-code.
All the offsets into an address space are still represented internally as a byte offset. The only
exceptions are the **LOAD** and **STORE** p-code operations. These operations read a pointer offset
that must be scaled properly to get the right byte offset when dereferencing the pointer. The
wordsize attribute has no effect on any of the other p-code operations.

### Varnode

A **varnode** is a generalization of either a register or a memory location. It is represented by
the formal triple: an address space, an offset into the space, and a size. Intuitively, a varnode is
a contiguous sequence of bytes in some address space that can be treated as a single value. All
manipulation of data by p-code operations occurs on varnodes.

Varnodes by themselves are just a contiguous chunk of bytes, identified by their address and size,
and they have no type. The p-code operations however can force one of three *type* interpretations
on the varnodes: integer, boolean, and floating-point.

* Operations that manipulate integers always interpret a varnode as a twos-complement encoding using
  the endianness associated with the address space containing the varnode.
* A varnode being used as a boolean value is assumed to be a single byte that can only take the
  value 0, for *false*, and 1, for *true*.
* Floating-point operations use the encoding expected by the processor being modeled, which varies
  depending on the size of the varnode. For most processors, these encodings are described by the
  IEEE 754 standard, but other encodings are possible in principle.

If a varnode is specified as an offset into the **constant** address space, that offset is
interpreted as a constant, or immediate value, in any p-code operation that uses that varnode. The
size of the varnode, in this case, can be treated as the size or precision available for the
encoding of the constant. As with other varnodes, constants only have a type forced on them by the
p-code operations that use them.

### P-code Operation

A **p-code operation** is the analog of a machine instruction. All p-code operations have the same
basic format internally. They all take one or more varnodes as input and optionally produce a single
output varnode. The action of the operation is determined by its **opcode**. For almost all p-code
operations, only the output varnode can have its value modified; there are no indirect effects of
the operation. The only possible exceptions are *pseudo* operations, see [the section called “Pseudo
P-CODE Operations”](pseudo-ops.md), which are sometimes necessary when there is incomplete knowledge
of an instruction's behavior.

All p-code operations are associated with the address of the original processor instruction they
were translated from. For a single instruction, a 1-up counter, starting at zero, is used to
enumerate the multiple p-code operations involved in its translation. The address and counter as a
pair are referred to as the p-code op's unique **sequence number**. Control-flow of p-code
operations generally follows sequence number order. When execution of all p-code for one instruction
is completed, if the instruction has *fall-through* semantics, p-code control-flow picks up with the
first p-code operation in sequence corresponding to the instruction at the fall-through address.
Similarly, if a p-code operation results in a control-flow branch, the first p-code operation in
sequence executes at the destination address.

The list of possible opcodes is similar to many RISC based instruction sets. The effect of each
opcode is described in detail in the following sections, and a reference table is given in [the
section called “Syntax Reference”](reference.md). In general, the size or precision of a particular
p-code operation is determined by the size of the varnode inputs or output, not by the opcode.

---

Next: [P-Code Operation Reference](pcodedescription.md)
