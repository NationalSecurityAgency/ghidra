# Syntax Reference

| Name | Syntax | Description |
| --- | --- | --- |
| COPY | `v0 = v1;` | Copy v1 into v0. |
| LOAD | `* v1`<br>`*[spc]v1`<br>`*:2 v1`<br>`*[spc]:2 v1` | Dereference v1 as pointer into default space. Optionally specify a space to load from and size of data in bytes. |
| STORE | `*v0 = v1;`<br>`*[spc]v0 = v1;`<br>`*:4 v0 = v1;`<br>`*[spc]:4 v0 = v1;` | Store in v1 in default space using v0 as pointer. Optionally specify space to store in and size of data in bytes. |
| BRANCH | `goto v0;` | Branch execution to address of v0. |
| CBRANCH | `if (v0) goto v1;` | Branch execution to address of v1 if v0 equals 1 (true). |
| BRANCHIND | `goto [v0];` | Branch execution to value in v0 viewed as an offset into the current space. |
| CALL | `call v0;` | Branch execution to address of v0. Hint that the branch is a subroutine call. |
| CALLIND | `call [v0];` | Branch execution to value in v0 viewed as an offset into the current space. Hint that the branch is a subroutine call. |
| RETURN | `return [v0];` | Branch execution to value in v0 viewed as an offset into the current space. Hint that the branch is a subroutine return. |
| PIECE | `<na>` | Concatenate two varnodes into a single varnode. |
| SUBPIECE | `v0:2` | The least significant n bytes of v0. |
| SUBPIECE | `v0(2)` | All but the least significant n bytes of v0. |
| POPCOUNT | `popcount(v0)` | Count 1 bits in v0. |
| LZCOUNT | `lzcount(v0)` | Counts the number of leading zero bits in v0. |
| INT_EQUAL | `v0 == v1` | True if v0 equals v1. |
| INT_NOTEQUAL | `v0 != v1` | True if v0 does not equal v1. |
| INT_LESS | `v0 < v1`<br>`v1 > v0` | True if v0 is less than v1 as an unsigned integer. |
| INT_SLESS | `v0 s< v1`<br>`v1 s> v0` | True if v0 is less than v1 as a signed integer. |
| INT_LESSEQUAL | `v0 <= v1`<br>`v1 >= v0` | True if v0 is less than or equal to v1 as an unsigned integer. |
| INT_SLESSEQUAL | `v0 s<= v1`<br>`v1 s>= v0` | True if v0 is less than or equal to v1 as a signed integer. |
| INT_ZEXT | `zext(v0)` | Zero extension of v0. |
| INT_SEXT | `sext(v0)` | Sign extension of v0. |
| INT_ADD | `v0 + v1` | Addition of v0 and v1 as integers. |
| INT_SUB | `v0 - v1` | Subtraction of v1 from v0 as integers. |
| INT_CARRY | `carry(v0,v1)` | True if adding v0 and v1 would produce an unsigned carry. |
| INT_SCARRY | `scarry(v0,v1)` | True if adding v0 and v1 would produce an signed carry. |
| INT_SBORROW | `sborrow(v0,v1)` | True if subtracting v1 from v0 would produce a signed borrow. |
| INT_2COMP | `-v0` | Twos complement of v0. |
| INT_NEGATE | `~v0` | Bitwise negation of v0. |
| INT_XOR | `v0 ^ v1` | Bitwise Exclusive Or of v0 with v1. |
| INT_AND | `v0 & v1` | Bitwise Logical And of v0 with v1. |
| INT_OR | `v0 \| v1` | Bitwise Logical Or of v0 with v1. |
| INT_LEFT | `v0 << v1` | Left shift of v0 by v1 bits. |
| INT_RIGHT | `v0 >> v1` | Unsigned (logical) right shift of v0 by v1 bits. |
| INT_SRIGHT | `v0 s>> v1` | Signed (arithmetic) right shift of v0 by v1 bits. |
| INT_MULT | `v0 * v1` | Integer multiplication of v0 and v1. |
| INT_DIV | `v0 / v1` | Unsigned division of v0 by v1. |
| INT_REM | `v0 % v1` | Unsigned remainder of v0 modulo v1. |
| INT_SDIV | `v0 s/ v1` | Signed division of v0 by v1. |
| INT_SREM | `v0 s% v1` | Signed remainder of v0 modulo v1. |
| BOOL_NEGATE | `!v0` | Negation of boolean value v0. |
| BOOL_XOR | `v0 ^^ v1` | Exclusive-Or of booleans v0 and v1. |
| BOOL_AND | `v0 && v1` | Logical-And of booleans v0 and v1. |
| BOOL_OR | `v0 \|\| v1` | Logical-Or of booleans v0 and v1. |
| FLOAT_EQUAL | `v0 f== v1` | True if v0 equals v1 viewed as floating-point numbers. |
| FLOAT_NOTEQUAL | `v0 f!= v1` | True if v0 does not equal v1 viewed as floating-point numbers. |
| FLOAT_LESS | `v0 f< v1`<br>`v1 f> v0` | True if v0 is less than v1 viewed as floating-point numbers. |
| FLOAT_LESSEQUAL | `v0 f<= v1`<br>`v1 f>= v0` | True if v0 is less than or equal to v1 viewed as floating-point numbers. |
| FLOAT_ADD | `v0 f+ v1` | Addition of v0 and v1 as floating-point numbers. |
| FLOAT_SUB | `v0 f- v1` | Subtraction of v1 from v0 as floating-point numbers. |
| FLOAT_MULT | `v0 f* v1` | Multiplication of v0 and v1 as floating-point numbers. |
| FLOAT_DIV | `v0 f/ v1` | Division of v0 by v1 as floating-point numbers. |
| FLOAT_NEG | `f- v0` | Additive inverse of v0 as a floating-point number. |
| FLOAT_ABS | `abs(v0)` | Absolute value of v0 as a floating-point number. |
| FLOAT_SQRT | `sqrt(v0)` | Square root of v0 as a floating-point number. |
| FLOAT_CEIL | `ceil(v0)` | Nearest integral floating-point value greater than v0, viewed as a floating-point number. |
| FLOAT_FLOOR | `floor(v0)` | Nearest integral floating-point value less than v0, viewed as a floating-point number. |
| FLOAT_ROUND | `round(v0)` | Nearest integral floating-point to v0, viewed as a floating-point number. |
| FLOAT_NAN | `nan(v0)` | True if v0 is not a valid floating-point number (NaN). |
| INT2FLOAT | `int2float(v0)` | Floating-point representation of v0 viewed as an integer. |
| FLOAT2FLOAT | `float2float(v0)` | Copy of floating-point number v0 with more or less precision. |
| TRUNC | `trunc(v0)` | Signed integer obtained by truncating v0 viewed as a floating-point number. |
| CPOOLREF | `cpool(v0,...)` | Obtain constant pool value. |
| NEW | `newobject(v0)`<br>`newobject(v0,v1)` | Allocate an object or an array of objects. |
| MULTIEQUAL | `<na>` | Compiler phi-node: values merging from multiple control-flow paths. |
| INDIRECT | `<na>` | Indirect effect from input varnode to output varnode. |
| CAST | `<na>` | Copy from input to output. A hint that the underlying datatype has changed. |
| PTRADD | `<na>` | Construct a pointer to an element from a pointer to the start of an array and an index. |
| PTRSUB | `<na>` | Construct a pointer to a field from a pointer to a structure and an offset. |
| INSERT | `<na>` | Insert a value as a bit-range into a varnode |
| EXTRACT | `<na>` | Extract a bit-range from a varnode |

---

Prev: [Additional P-CODE Operations](additionalpcode.md) \| [Home](pcoderef.md)
