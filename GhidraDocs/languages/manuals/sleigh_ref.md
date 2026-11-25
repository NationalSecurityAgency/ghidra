# 9. P-code Tables

We list all the p-code operations by name along with the syntax for invoking them within the
semantic section of a constructor definition (see [Section 7.7, “The Semantic
Section”](sleigh_constructors.md#77-the-semantic-section)), and with a description of the operator.
The terms *v0* and *v1* represent identifiers of individual input varnodes to the operation. In
terms of syntax, *v0* and *v1* can be replaced with any semantic expression, in which case the final
output varnode of the expression becomes the input to the operator. The term *spc* represents the
identifier of an address space, which is a special input to the *LOAD* and *STORE* operations. The
identifier of any address space can be used.

This table lists all the operators for building semantic expressions. The operators are listed in
order of precedence, highest to lowest.

<a name="syntaxref.htmltable"></a>

**Table 5. Semantic Expression Operators and Syntax**

| P-code Name | SLEIGH Syntax | Description |
| --- | --- | --- |
| `SUBPIECE` | `v0:2`<br>`v0(2)` | The least significant n bytes of v0. Truncate least significant n bytes of v0. Most significant bytes may be truncated depending on result size. |
| `POPCOUNT` | `popcount(v0)` | Count the number of 1 bits in v0. |
| `LZCOUNT` | `lzcount(v0)` | Count the number of leading 0 bits in v0. |
| `(simulated)` | `v0[6,1]` | Extract a range of bits from v0, putting result in a minimum number of bytes. The bracketed numbers give respectively, the least significant bit and the number of bits in the range. |
| `LOAD` | `* v1`<br>`*[spc]v1`<br>`*:2 v1`<br>`*[spc]:2 v1` | Dereference v1 as pointer into default space. Optionally specify space to load from and size of data in bytes. |
| `BOOL_NEGATE` | `!v0` | Negation of boolean value v0. |
| `INT_NEGATE` | `~v0` | Bitwise negation of v0. |
| `INT_2COMP` | `-v0` | Twos complement of v0. |
| `FLOAT_NEG` | `f- v0` | Additive inverse of v0 as a floating-point number. |
| `INT_MULT` | `v0 * v1` | Integer multiplication of v0 and v1. |
| `INT_DIV` | `v0 / v1` | Unsigned division of v0 by v1. |
| `INT_SDIV` | `v0 s/ v1` | Signed division of v0 by v1. |
| `INT_REM` | `v0 % v1` | Unsigned remainder of v0 modulo v1. |
| `INT_SREM` | `v0 s% v1` | Signed remainder of v0 modulo v1. |
| `FLOAT_DIV` | `v0 f/ v1` | Division of v0 by v1 as floating-point numbers. |
| `FLOAT_MULT` | `v0 f* v1` | Multiplication of v0 and v1 as floating-point numbers. |
| `INT_ADD` | `v0 + v1` | Addition of v0 and v1 as integers. |
| `INT_SUB` | `v0 - v1` | Subtraction of v1 from v0 as integers. |
| `FLOAT_ADD` | `v0 f+ v1` | Addition of v0 and v1 as floating-point numbers. |
| `FLOAT_SUB` | `v0 f- v1` | Subtraction of v1 from v0 as floating-point numbers. |
| `INT_LEFT` | `v0 << v1` | Left shift of v0 by v1 bits. |
| `INT_RIGHT` | `v0 >> v1` | Unsigned (logical) right shift of v0 by v1 bits. |
| `INT_SRIGHT` | `v0 s>> v1` | Signed (arithmetic) right shift of v0 by b1 bits. |
| `INT_SLESS` | `v0 s< v1`<br>`v1 s> v0` | True if v0 is less than v1 as a signed integer. |
| `INT_SLESSEQUAL` | `v0 s<= v1`<br>`v1 s>= v0` | True if v0 is less than or equal to v1 as a signed integer. |
| `INT_LESS` | `v0 < v1`<br>`v1 > v0` | True if v0 is less than v1 as an unsigned integer. |
| `INT_LESSEQUAL` | `v0 <= v1`<br>`v1 >= v0` | True if v0 is less than or equal to v1 as an unsigned integer. |
| `FLOAT_LESS` | `v0 f< v1`<br>`v1 f> v0` | True if v0 is less than v1 viewed as floating-point numbers. |
| `FLOAT_LESSEQUAL` | `v0 f<= v1`<br>`v1 f>= v0` | True if v0 is less than or equal to v1 as floating-point. |
| `INT_EQUAL` | `v0 == v1` | True if v0 equals v1. |
| `INT_NOTEQUAL` | `v0 != v1` | True if v0 does not equal v1. |
| `FLOAT_EQUAL` | `v0 f== v1` | True if v0 equals v1 viewed as floating-point numbers. |
| `FLOAT_NOTEQUAL` | `v0 f!= v1` | True if v0 does not equal v1 viewed as floating-point numbers. |
| `INT_AND` | `v0 & v1` | Bitwise Logical And of v0 with v1. |
| `INT_XOR` | `v0 ^ v1` | Bitwise Exclusive Or of v0 with v1. |
| `INT_OR` | `v0 \| v1` | Bitwise Logical Or of v0 with v1. |
| `BOOL_XOR` | `v0 ^^ v1` | Exclusive-Or of booleans v0 and v1. |
| `BOOL_AND` | `v0 && v1` | Logical-And of booleans v0 and v1. |
| `BOOL_OR` | `v0 \|\| v1` | Logical-Or of booleans v0 and v1. |
| `INT_ZEXT` | `zext(v0)` | Zero extension of v0. |
| `INT_SEXT` | `sext(v0)` | Sign extension of v0. |
| `INT_CARRY` | `carry(v0,v1)` | True if adding v0 and v1 would produce an unsigned carry. |
| `INT_SCARRY` | `scarry(v0,v1)` | True if adding v0 and v1 would produce a signed carry. |
| `INT_SBORROW` | `sborrow(v0,v1)` | True if subtracting v1 from v0 would produce a signed borrow. |
| `FLOAT_NAN` | `nan(v0)` | True if v0 is not a valid floating-point number (NaN). |
| `FLOAT_ABS` | `abs(v0)` | Absolute value of v0 as floating point number. |
| `FLOAT_SQRT` | `sqrt(v0)` | Square root of v0 as floating-point number. |
| `INT2FLOAT` | `int2float(v0)` | Floating-point representation of v0 viewed as an integer. |
| `FLOAT2FLOAT` | `float2float(v0)` | Copy of floating-point number v0 with more or less precision. |
| `TRUNC` | `trunc(v0)` | Signed integer obtained by truncating v0. |
| `FLOAT_CEIL` | `ceil(v0)` | Nearest integer greater than v0. |
| `FLOAT_FLOOR` | `floor(v0)` | Nearest integer less than v0. |
| `FLOAT_ROUND` | `round(v0)` | Nearest integer to v0. |
| `CPOOLREF` | `cpool(v0,...)` | Access value from the constant pool. |
| `NEW` | `newobject(v0)` | Allocate object of type described by v0. |
| `CALLOTHER` | `ident(v0,...)` | User defined operator *ident*, with functional syntax. |

The following table lists the basic forms of a semantic statement.

**Table 6. Basic Statements and Associated Operators**

| P-code Name | SLEIGH Syntax | Description |
| --- | --- | --- |
| `COPY, other` | `v0 = v1;` | Assignment of v1 to v0. |
| `STORE` | `*v0 = v1`<br>`*[spc]v0 = v1;`<br>`*:4 v0 = v1;`<br>`*[spc]:4 v0 = v1;` | Store v1 in default space using v0 As pointer. Optionally specify space to store in and size of data in bytes. |
| `CALLOTHER` | `ident(v0,...);` | Invoke user-defined operation ident as a standalone statement, with no output. |
|  | `v0[8,1] = v1;` | Fill a bit range within v0 using v1, leaving the rest of v0 unchanged. |
|  | `ident(v0,...);` | Invoke the macro named *ident*. |
|  | `build ident;` | Execute the p-code to build operand *ident*. |
|  | `delayslot(1);` | Execute the p-code for the following instruction. |

The following table lists the branching operations and the statements which invoke them.

<a name="branchref.htmltable"></a>

**Table 7. Branching Statements**

| P-code Name | SLEIGH Syntax | Description |
| --- | --- | --- |
| `BRANCH` | `goto v0;` | Branch execution to address of v0. |
| `CBRANCH` | `if (v0) goto v1;` | Branch execution to address of v1 if v0 equals 1 (true). |
| `BRANCHIND` | `goto [v0];` | Branch execution to v0 viewed as an offset in current space. |
| `CALL` | `call v0;` | Branch execution to address of v0. Hint that branch is subroutine call. |
| `CALLIND` | `call [v0];` | Branch execution to v0 viewed as an offset in current space. Hint that branch is subroutine call. |
| `RETURN` | `return [v0];` | Branch execution to v0 viewed as an offset in current space. Hint that branch is a subroutine return. |

---

Prev: [8. Using Context](sleigh_context.md) \| [Home](sleigh.md)
