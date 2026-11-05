# 2. Basic Specification Layout

A SLEIGH specification is typically contained in a single file, although see [Section 3.1,
“Including Files”](sleigh_preprocessing.md#31-including-files). The file must follow a specific
format as parsed by the SLEIGH compiler. In this section, we list the basic formatting rules for
this file as enforced by the compiler.

## 2.1. Comments

Comments start with the ‘#’ character and continue to the end of the line. Comments can appear
anywhere except the *display section* of a constructor (see [Section 7.3, “The Display
Section”](sleigh_constructors.md#73-the-display-section)) where the ‘#’ character will be
interpreted as something that should be printed in disassembly.

## 2.2. Identifiers

Identifiers are made up of letters a-z, capitals A-Z, digits 0-9 and the characters ‘.’ and ‘\_’. An
identifier can use these characters in any order and for any length, but it must not start with a
digit.

## 2.3. Strings

String literals can be used, when specifying names and when specifying how disassembly should be
printed, so that special characters are treated as literals. Strings are surrounded by the double
quote character ‘”’ and all characters in between lose their special meaning.

## 2.4. Integers

Integers are specified either in a decimal format or in a standard *C-style* hexadecimal format by
prepending the number with “0x”. Alternately, a binary representation of an integer can be given by
prepending the string of '0' and '1' characters with "0b".

```
1006789
0xF5CC5
0xf5cc5
0b11110101110011000101
```

Numbers are treated as unsigned except when used in patterns where they are treated as signed (see
[Section 7.4, “The Bit Pattern Section”](sleigh_constructors.md#74-the-bit-pattern-section)). The
number of bytes used to encode the integer when specifying the semantics of an instruction is
inferred from other parts of the syntax (see [Section 7.3, “The Display
Section”](sleigh_constructors.md#73-the-display-section)). Otherwise, integers should be thought of
as having arbitrary precision. Currently, SLEIGH stores integers internally with 64 bits of
precision.

## 2.5. White Space

White space characters include space, tab, line-feed, vertical line-feed, and carriage-return (‘ ‘,
‘\\t’, ‘\\r’, ‘\\v’, ‘\\n’). Variations in spacing have no effect on the parsing of the file except
in string literals.

---

Prev: [SLEIGH](sleigh.md) \| [Home](sleigh.md) \| Next: [3. Preprocessing](sleigh_preprocessing.md)
