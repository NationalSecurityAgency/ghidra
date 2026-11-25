# 6. Tokens and Fields

## 6.1. Defining Tokens and Fields

A *token* is one of the byte-sized pieces that make up the machine code instructions being modeled.
Instruction *fields* must be defined on top of them. A *field* is a logical range of bits within an
instruction that can specify an opcode, or an operand etc. Together tokens and fields determine the
basic interpretation of bits and how many bytes the instruction takes up. To define a token and the
fields associated with it, we use the **define token** statement.

```
define token <tokenname> ( <integer> )
  <fieldname>=(<integer>,<integer>) <attributelist>
  ...
;
```

The first part of the definition defines the name of a token and the number of bits it uses (this
must be a multiple of 8). Following this there are one or more field declarations specifying the
name of the field and the range of bits within the token making up the field. The size of a field
does *not* need to be a multiple of 8. The range is inclusive where the least significant bit in the
token is labeled 0. When defining tokens that are bigger than 1 byte, the global endianness setting
(See [Section 4.1, “Endianness Definition”](sleigh_definitions.md#41-endianness-definition)) will
affect this labeling. Although it is rarely required, it is possible to override the global
endianness setting for a specific token by appending either the qualifier **endian=little** or
**endian=big** immediately after the token name and size. For instance:

```
  define token instr ( 32 ) endian=little op0=(0,15) ...
```

The token *instr* is overridden to be little endian. This override applies to all fields defined for
the token but affects no other tokens.

After each field declaration, there can be zero or more of the following attribute keywords:

```
signed
hex
dec
```

These attributes are defined in the next section. There can be any manner of repeats and overlaps in
the fields so long as they all have different names.

## 6.2. Fields as Family Symbols

Fields are the most basic form of family symbol; they define a natural map from instruction bits to
a specific symbol as follows. We take the set of bits within the instruction as given by the field’s
defining range and treat them as an integer encoding. The resulting integer is both the display
portion and the semantic meaning of the specific symbol. The display string is obtained by
converting the integer into either a decimal or hexadecimal representation (see below), and the
integer is treated as a constant varnode in any semantic action.

The attributes of the field affect the resulting specific symbol in obvious ways. The **signed**
attribute determines whether the integer encoding should be treated as just an unsigned encoding or
if a twos-complement encoding should be used to obtain a signed integer. The **hex** or **dec**
attributes describe whether the integer should be displayed with a hexadecimal or decimal
representation. The default is hexadecimal. \[Currently the **dec** attribute is not supported\]

## 6.3. Attaching Alternate Meanings to Fields

The default interpretation of a field is probably the most natural but of course processors
interpret fields within an instruction in a wide variety of ways. The **attach** keyword is used to
alter either the display or semantic meaning of fields into the most common (and basic)
interpretations. More complex interpretations must be built up out of tables.

### 6.3.1. Attaching Registers

Probably *the* most common processor interpretation of a field is as an encoding of a particular
register. In SLEIGH this can be done with the **attach variables** statement:

```
attach variables <fieldlist> <registerlist>;
```

A *fieldlist* can be a single field identifier or a space separated list of field identifiers
surrounded by square brackets. A *registerlist* must be a square bracket surrounded and space
separated list of register identifiers as created with **define** statements (see Section [Section
4.4, “Naming Registers”](sleigh_definitions.md#44-naming-registers)). For each field in the
*fieldlist*, instead of having the display and semantic meaning of an integer, the field becomes a
look-up table for the given list of registers. The original integer interpretation is used as the
index into the list starting at zero, so a specific instruction that has all the bits in the field
equal to zero yields the first register (a specific varnode) from the list as the meaning of the
field in the context of that instruction. Note that both the display and semantic meaning of the
field are now taken from the new register.

A particular integer can remain unspecified by putting a ‘\_’ character in the appropriate position
of the register list or also if the length of the register list is less than the integer. A specific
integer encoding of the field that is unspecified like this does *not* revert to the original
semantic and display meaning. Instead this encoding is flagged as an invalid form of the
instruction.

### 6.3.2. Attaching Other Integers

Sometimes a processor interprets a field as an integer but not the integer given by the default
interpretation. A different integer interpretation of the field can be specified with an **attach
values** statement.

```
attach values <fieldlist> <integerlist>;
```

The *integerlist* is surrounded by square brackets and is a space separated list of integers. In the
same way that a new register interpretation is assigned to fields with an **attach variables**
statement, the integers in the list are assigned to each field specified in the *fieldlist*.
(Currently SLEIGH does not support unspecified positions in the list using a ‘\_’)

### 6.3.3. Attaching Names

It is possible to just modify the display characteristics of a field without changing the semantic
meaning. The need for this is rare, but it is possible to treat a field as having influence on the
display of the disassembly but having no influence on the semantics. Even if the bits of the field
do have some semantic meaning, sometimes it is appropriate to define overlapping fields, one of
which is defined to have no semantic meaning. The most convenient way to break down the required
disassembly may not be the most convenient way to break down the semantics. It is also possible to
have symbols with semantic meaning but no display meaning (see [Section 7.4.5, “Invisible
Operands”](sleigh_constructors.md#745-invisible-operands)).

At any rate we can list the display interpretation of a field directly with an **attach names**
statement.

```
attach names <fieldlist> <stringlist>;
```

The *stringlist* is assigned to each of the fields in the same manner as the **attach variables**
and **attach values** statements. A specific encoding of the field now displays as the string in the
list at that integer position. Field values greater than the size of the list are interpreted as
invalid encodings.

## 6.4. Context Variables

SLEIGH supports the concept of *context variables*. For the most part processor instructions can be
unambiguously decoded by examining only the bits of the instruction encoding. But in some cases,
decoding may depend on the state of the processor. Typically, the processor will have some set of
status flags that indicate what mode is being used to process instructions. In terms of SLEIGH, a
context variable is a *field* which is defined on top of a register rather than the instruction
encoding (token).

```
define context <contextreg>
  <fieldname>=(<integer>,<integer>) <attributelist>
  ...
;
```

Context variables are defined with a **define context** statement. The keywords must be followed by
the name of a defined register. The remaining part of the definition is nearly identical to the
normal definition of fields. Each context variable defined on this register is listed in turn,
specifying the name, the bit range, and any attributes. All the normal field attributes, **signed**,
**dec**, and **hex**, can also be used for context variables.

Context variables introduce a new, dedicated, attribute: **noflow**. By default, globally setting a
context variable affects instruction decoding from the point of the change, forward, following the
flow of the instructions, but if the variable is labeled as **noflow**, any change is limited to a
single instruction. (See [Section 8.3.1, “Context Flow”](sleigh_context.md#831-context-flow))

Once the context variable is defined, in terms of the specification syntax, it can be treated as if
it were just another field. See [Section 8, “Using Context”](sleigh_context.md), for a complete
discussion of how to use context variables.

---

Prev: [5. Introduction to Symbols](sleigh_symbols.md) \| [Home](sleigh.md) \| Next: [7.
Constructors](sleigh_constructors.md)
