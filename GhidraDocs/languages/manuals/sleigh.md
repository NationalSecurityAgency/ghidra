# SLEIGH

*A Language for Rapid Processor Specification*

Last updated November 23, 2026

Originally published December 16, 2005

**Table of Contents**

* [1. Introduction to P-Code](#1-introduction-to-p-code)
  * [1.1. Address Spaces](#11-address-spaces)
  * [1.2. Varnodes](#12-varnodes)
  * [1.3. Operations](#13-operations)
* [2. Basic Specification Layout](sleigh_layout.md)
  * [2.1. Comments](sleigh_layout.md#21-comments)
  * [2.2. Identifiers](sleigh_layout.md#22-identifiers)
  * [2.3. Strings](sleigh_layout.md#23-strings)
  * [2.4. Integers](sleigh_layout.md#24-integers)
  * [2.5. White Space](sleigh_layout.md#25-white-space)
* [3. Preprocessing](sleigh_preprocessing.md)
  * [3.1. Including Files](sleigh_preprocessing.md#31-including-files)
  * [3.2. Preprocessor Macros](sleigh_preprocessing.md#32-preprocessor-macros)
  * [3.3. Conditional Compilation](sleigh_preprocessing.md#33-conditional-compilation)
* [4. Basic Definitions](sleigh_definitions.md)
  * [4.1. Endianness Definition](sleigh_definitions.md#41-endianness-definition)
  * [4.2. Alignment Definition](sleigh_definitions.md#42-alignment-definition)
  * [4.3. Space Definitions](sleigh_definitions.md#43-space-definitions)
  * [4.4. Naming Registers](sleigh_definitions.md#44-naming-registers)
  * [4.5. Bit Range Registers](sleigh_definitions.md#45-bit-range-registers)
  * [4.6. User-Defined Operations](sleigh_definitions.md#46-user-defined-operations)
* [5. Introduction to Symbols](sleigh_symbols.md)
  * [5.1. Notes on Namespaces](sleigh_symbols.md#51-notes-on-namespaces)
  * [5.2. Predefined Symbols](sleigh_symbols.md#52-predefined-symbols)
* [6. Tokens and Fields](sleigh_tokens.md)
  * [6.1. Defining Tokens and Fields](sleigh_tokens.md#61-defining-tokens-and-fields)
  * [6.2. Fields as Family Symbols](sleigh_tokens.md#62-fields-as-family-symbols)
  * [6.3. Attaching Alternate Meanings to Fields](sleigh_tokens.md#63-attaching-alternate-meanings-to-fields)
  * [6.4. Context Variables](sleigh_tokens.md#64-context-variables)
* [7. Constructors](sleigh_constructors.md)
  * [7.1. The Five Sections of a Constructor](sleigh_constructors.md#71-the-five-sections-of-a-constructor)
  * [7.2. The Table Header](sleigh_constructors.md#72-the-table-header)
  * [7.3. The Display Section](sleigh_constructors.md#73-the-display-section)
  * [7.4. The Bit Pattern Section](sleigh_constructors.md#74-the-bit-pattern-section)
  * [7.5. Disassembly Actions Section](sleigh_constructors.md#75-disassembly-actions-section)
  * [7.6. The With Block](sleigh_constructors.md#76-the-with-block)
  * [7.7. The Semantic Section](sleigh_constructors.md#77-the-semantic-section)
  * [7.8. Tables](sleigh_constructors.md#78-tables)
  * [7.9. P-code Macros](sleigh_constructors.md#79-p-code-macros)
  * [7.10. Build Directives](sleigh_constructors.md#710-build-directives)
  * [7.11. Delay Slot Directives](sleigh_constructors.md#711-delay-slot-directives)
* [8. Using Context](sleigh_context.md)
  * [8.1. Basic Use of Context Variables](sleigh_context.md#81-basic-use-of-context-variables)
  * [8.2. Local Context Change](sleigh_context.md#82-local-context-change)
  * [8.3. Global Context Change](sleigh_context.md#83-global-context-change)
* [9. P-code Tables](sleigh_ref.md)

## History

This document describes the syntax for the SLEIGH processor specification language, which was
developed for the GHIDRA project. The language that is now called SLEIGH has undergone several
redesign iterations, but it can still trace its heritage from the language SLED, from whom its name
is derived. SLED, the “Specification Language for Encoding and Decoding”, was defined by Norman
Ramsey and Mary F. Fernández in [\[3\]](#Ramsey97) as a concise way to define the translation, in
both directions, between machine instructions and their corresponding assembly statements. This
facilitated the development of architecture independent disassemblers and assemblers, such as the
New Jersey Machine-code Toolkit.

The direct predecessor of SLEIGH was an implementation of SLED for GHIDRA, which concentrated on its
reverse-engineering capabilities. The main addition of SLEIGH is the ability to provide semantic
descriptions of instructions for data-flow and decompilation analysis. This piece of SLEIGH borrowed
ideas from the Semantic Syntax Language (SSL), a specification language developed in
[\[2\]](#Cifuentes00) for the University of Queensland Binary Translator (UQBT) project by Cristina
Cifuentes, Mike Van Emmerik and Norman Ramsey.

Dr. Cristina Cifuentes' work, in general, was an important starting point for the GHIDRA decompiler.
Its design follows the basic structure layed out in her 1994 thesis "Reverse Compilation
Techniques":

* Disassembly of machine instructions and translation to an intermediate representation (IR).
* Transformation toward a high-level representation via

  * Data-flow analysis, including dead code analysis and copy propagation.
  * Control-flow analysis, using graph reducibility to achieve a structured representation.
* Back-end code generation from the transformed representation.

In keeping with her philosophy of decompilation, SLEIGH is GHIDRA's implementation of the first
step. It efficiently couples disassembly of machine instructions with the initial translation into
an IR.

**References**

\[1\] Cristina Cifuentes. *Reverse Compilation Techniques*. 1994. Ph.D. Dissertation. Queensland
University of Technology. Brisbane City, QLD, Australia.

<a name="Cifuentes00"></a>

\[2\] Cristina Cifuentes and Mike Van Emmerik. “UQBT: Adaptable Binary Translation at Low Cost”.
*Computer*. (Mar. 2000). pp. 60-66.

<a name="Ramsey97"></a>

\[3\] Norman Ramsey and Mary F. Fernández. “Specifying Representations of Machine Instructions”.
*ACM Trans. Programming Languages and Systems*. (May 1997). pp. 492-524.

## Overview

SLEIGH is a language for describing the instruction sets of general purpose microprocessors, in
order to facilitate the reverse engineering of software written for them. SLEIGH was designed for
the GHIDRA reverse engineering platform and is used to describe microprocessors with enough detail
to facilitate two major components of GHIDRA, the disassembly and decompilation engines. For
disassembly, SLEIGH allows a concise description of the translation from the bit encoding of machine
instructions to human-readable assembly language statements. Moreover, it does this with enough
detail to allow the disassembly engine to break apart the statement into the mnemonic, operands,
sub-operands, and associated syntax. For decompilation, SLEIGH describes the translation from
machine instructions into *p-code*. P-code is a Register Transfer Language (RTL), distinct from
SLEIGH, designed to specify the *semantics* of machine instructions. By *semantics*, we mean the
detailed description of how an instruction actually manipulates data, in registers and in RAM. This
provides the foundation for the data-flow analysis performed by the decompiler.

A SLEIGH specification typically describes a single microprocessor and is contained in a single
file. The term *processor* will always refer to this target of the specification.

Italics are used when defining terms and for named entities. Bold is used for SLEIGH keywords.

## 1. Introduction to P-Code

Although p-code is a distinct language from SLEIGH, because a major purpose of SLEIGH is to specify
the translation from machine code to p-code, this document serves as a primer for p-code. The key
concepts and terminology are presented in this section, and more detail is given in [Section 7.7,
“The Semantic Section”](sleigh_constructors.md#77-the-semantic-section). There is also a complete
set of tables which list syntax and descriptions for p-code operations in the Appendix.

The design criteria for p-code was to have a language that looks much like modern assembly
instruction sets but capable of modeling any general purpose processor. Code for different
processors can be translated in a straightforward manner into p-code, and then a single suite of
analysis software can be used to do data-flow analysis and decompilation. In this way, the analysis
software becomes *retargetable*, and it isn’t necessary to redesign it for each new processor being
analyzed. It is only necessary to specify the translation of the processor’s instruction set into
p-code.

So the key properties of p-code are

* The language is machine independent.
* The language is designed to model general purpose processors.
* Instructions operate on user defined registers and address spaces.
* All data is manipulated explicitly. Instructions have no indirect effects.
* Individual p-code operations mirror typical processor tasks and concepts.

SLEIGH is the language which specifies the translation from a machine instruction to p-code. It
specifies both this translation and how to display the instruction as an assembly statement.

A model for a particular processor is built out of three concepts: the *address space*, the
*varnode*, and the *operation*. These are generalizations of the computing concepts of RAM,
registers, and machine instructions respectively.

### 1.1. Address Spaces

An *address* space for p-code is a generalization of the indexed memory (RAM) that a typical
processor has access to, and it is defined simply as an indexed sequence of memory *words* that can
be read and written by p-code. In almost all cases, a *word* of the space is a *byte* (8 bits), and
we will usually use the term *byte* instead of *word*. However, see the discussion of the
**wordsize** attribute of address spaces below.

The defining characteristics of a space are its name and its size. The size of a space indicates the
number of distinct indices into the space and is usually given as the number of bytes required to
encode an arbitrary index into the space. A space of size 4 requires a 32 bit integer to specify all
indices and contains 2<sup>32</sup> bytes. The index of a byte is usually referred to as the
*offset*, and the offset together with the name of the space is called the *address* of the byte.

Any manipulation of data that p-code operations perform happens in some address space. This includes
the modeling of data stored in RAM but also includes the modeling of processor registers. Registers
must be modeled as contiguous sequences of bytes at a specific offset (see the definition of
varnodes below), typically in their own distinct address space. In order to facilitate the modeling
of many different processors, a SLEIGH specification provides complete control over what address
spaces are defined and where registers are located within them.

Typically, a processor can be modeled with only two spaces, a *ram* address space that represents
the main memory accessible to the processor via its data-bus, and a *register* address space that is
used to implement the processor’s registers. However, the specification designer can define as many
address spaces as needed.

There is one address space that is automatically defined for a SLEIGH specification. This space is
used to allocate temporary storage when the SLEIGH compiler breaks down the expressions describing
processor semantics into individual p-code operations. It is called the *unique* space. There is
also a special address space, called the *const* space, used as a placeholder for constant operands
of p-code instructions. For the most part, a SLEIGH specification doesn’t need to be aware of this
space, but it can be used in certain situations to force values to be interpreted as constants.

### 1.2. Varnodes

A *varnode* is the unit of data manipulated by p-code. It is simply a contiguous sequence of bytes
in some address space. The two defining characteristics of a varnode are

* The address of the first byte.
* The number of bytes (size).

With the possible exception of constants treated as varnodes, there is never any distinction made
between one varnode and another. They can have any size, they can overlap, and any number of them
can be defined.

Varnodes by themselves are typeless. An individual p-code operation forces an interpretation on each
varnode that it uses, as either an integer, a floating-point number, or a boolean value. In the case
of an integer, the varnode is interpreted as having a big endian or little endian encoding,
depending on the specification (see [Section 4.1, “Endianness
Definition”](sleigh_definitions.md#41-endianness-definition)). Certain instructions also distinguish
between signed and unsigned interpretations. For a signed integer, the varnode is considered to have
a standard twos complement encoding. For a boolean interpretation, the varnode must be a single byte
in size. In this special case, the zero encoding of the byte is considered a *false* value and an
encoding of 1 is a *true* value.

These interpretations only apply to the varnode for a particular operation. A different operation
can interpret the same varnode in a different way. Any consistent meaning assigned to a particular
varnode must be provided and enforced by the specification designer.

### 1.3. Operations

P-code is intended to emulate a target processor by substituting a sequence of p-code operations for
each machine instruction. Thus every p-code operation is naturally associated with the address of a
specific machine instruction, but there is usually more than one p-code operation associated with a
single machine instruction. Except in the case of branching, p-code operations have fall-through
control flow, both within and across machine instructions. For a single machine instruction, the
associated p-code operations execute from first to last. And if there is no branching, execution
picks up with the first operation corresponding to the next machine instruction.

Every p-code operation can take one or more varnodes as input and can optionally have one varnode as
output. The operation can only make a change to this *output varnode*, which is always indicated
explicitly. Because of this rule, all manipulation of data is explicit. The operations have no
indirect effects. In general, there is absolutely no restriction on what varnodes can be used as
inputs and outputs to p-code operations. The only exceptions to this are that constants cannot be
used as output varnodes and certain operations impose restrictions on the *size* of their varnode
operands.

The actual operations should be familiar to anyone who has studied general purpose processor
instruction sets. They break up into groups.

**Table 1. P-code Operations**

| Operation Category | List of Operations |
| --- | --- |
| Data Moving | `COPY, LOAD, STORE` |
| Arithmetic | `INT_ADD, INT_SUB, INT_CARRY, INT_SCARRY, INT_SBORROW, INT_2COMP, INT_MULT, INT_DIV, INT_SDIV, INT_REM, INT_SREM` |
| Logical | `INT_NEGATE, INT_XOR, INT_AND, INT_OR, INT_LEFT, INT_RIGHT, INT_SRIGHT, POPCOUNT, LZCOUNT` |
| Integer Comparison | `INT_EQUAL, INT_NOTEQUAL, INT_SLESS, INT_SLESSEQUAL, INT_LESS, INT_LESSEQUAL` |
| Boolean | `BOOL_NEGATE, BOOL_XOR, BOOL_AND, BOOL_OR` |
| Floating Point | `FLOAT_ADD, FLOAT_SUB, FLOAT_MULT, FLOAT_DIV, FLOAT_NEG, FLOAT_ABS, FLOAT_SQRT, FLOAT_NAN` |
| Floating Point Compare | `FLOAT_EQUAL, FLOAT_NOTEQUAL, FLOAT_LESS, FLOAT_LESSEQUAL` |
| Floating Point Conversion | `INT2FLOAT, FLOAT2FLOAT, TRUNC, CEIL, FLOOR, ROUND` |
| Branching | `BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, RETURN` |
| Extension/Truncation | `INT_ZEXT, INT_SEXT, PIECE, SUBPIECE` |
| Managed Code | `CPOOLREF, NEW` |

We postpone a full discussion of the individual operations until [Section 7.7, “The Semantic
Section”](sleigh_constructors.md#77-the-semantic-section).

---

Next: [2. Basic Specification Layout](sleigh_layout.md)
