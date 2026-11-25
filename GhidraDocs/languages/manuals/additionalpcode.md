# Additional P-CODE Operations

The following opcodes are not generated as part of the raw translation of a machine instruction into
p-code operations, so none of them can be used in a processor specification. But, they may be
introduced at a later stage by various analysis algorithms.

## MULTIEQUAL

| Parameters | Description |
| --: | --- |
| input0 | Varnode to merge from first basic block. |
| input1 | Varnode to merge from second basic block. |
| \[...\] | Varnodes to merge from additional basic blocks. |
| output | Merged varnode for basic block containing op. |

**Semantic statement**

Cannot be explicitly coded.

This operation represents a copy from one or more possible locations. From the compiler theory
concept of Static Single Assignment form, this is a **phi-node**. Each input corresponds to a
control-flow path flowing into the basic block containing the **MULTIEQUAL**. The operator copies a
particular input into the output varnode depending on what path was last executed. All inputs and
outputs must be the same size.

## INDIRECT

| Parameters |  | Description |
| --: | --- | --- |
| input0 |  | Varnode on which output may depend. |
| input1 | (**special**) | Code iop of instruction causing effect. |
| output |  | Varnode containing result of effect. |

**Semantic statement**

Cannot be explicitly coded.

An **INDIRECT** operator copies input0 into output, but the value may be altered in an indirect way
by the operation referred to by input1. The varnode input1 is not part of the machine state but is
really an internal reference to a specific p-code operator that may be affecting the value of the
output varnode. A special address space indicates input1's use as an internal reference encoding. An
**INDIRECT** op is a placeholder for possible indirect effects (such as pointer aliasing or missing
code) when data-flow algorithms do not have enough information to follow the data-flow directly.
Like the **MULTIEQUAL**, this op is used for generating Static Single Assignment form.

A constant varnode (zero) for input0 is used by analysis to indicate that the output of the
**INDIRECT** is produced solely by the p-code operation producing the indirect effect, and there is
no possibility that the value existing prior to the operation was used or preserved.

## PTRADD

| Parameters |  | Description |
| --: | --- | --- |
| input0 |  | Varnode containing pointer to an array. |
| input1 |  | Varnode containing integer index. |
| input2 | (**constant**) | Constant varnode indicating element size. |
| output |  | Varnode result containing pointer to indexed array entry. |

**Semantic statement**

Cannot be explicitly coded.

This operator serves as a more compact representation of the pointer calculation, input0 + input1 \*
input2, but also indicates explicitly that input0 is a reference to an array data-type. Input0 is a
pointer to the beginning of the array, input1 is an index into the array, and input2 is a constant
indicating the size of an element in the array. As an operation, **PTRADD** produces the pointer
value of the element at the indicated index in the array and stores it in output.

## PTRSUB

| Parameters | Description |
| --: | --- |
| input0 | Varnode containing pointer to structure. |
| input1 | Varnode containing integer offset to a subcomponent. |
| output | Varnode result containing pointer to the subcomponent. |

**Semantic statement**

Cannot be explicitly coded.

A **PTRSUB** performs the simple pointer calculation, input0 + input1, but also indicates explicitly
that input0 is a reference to a structured data-type and one of its subcomponents is being accessed.
Input0 is a pointer to the beginning of the structure, and input1 is a byte offset to the
subcomponent. As an operation, **PTRSUB** produces a pointer to the subcomponent and stores it in
output.

## CAST

| Parameters | Description |
| --: | --- |
| input0 | Varnode containing value to be copied. |
| output | Varnode result of copy. |

**Semantic statement**

Cannot be explicitly coded.

A **CAST** performs identically to the **COPY** operator but also indicates that there is a forced
change in the data-types associated with the varnodes at this point in the code. The value input0 is
strictly copied into output; it is not a conversion cast. This operator is intended specifically for
when the value doesn't change but its interpretation as a data-type changes at this point.

## INSERT

| Parameters |  | Description |
| --: | --- | --- |
| input0 |  | Varnode where the value will be inserted. |
| input1 |  | Integer varnode containing the value to insert. |
| position | (**constant**) | Constant indicating the bit position to insert at. |
| size | (**constant**) | Constant indicating the number of bits to insert. |
| output |  | Varnode result containing input0 with input1 inserted. |

**Semantic statement**

Cannot be explicitly coded.

An **INSERT** operation takes the least significant *size* bits from input1 and inserts them into
input0, overwriting a range of bits of the same size, but leaving any other bits in input0
unchanged.

The least significant bit of the overwritten range is given by *position*, where bits in index0 are
labeled from least significant to most significant, starting at 0. The value obtained after this
overwriting is returned as output. Varnodes input0 and output must be the same size and are intended
to be the same varnode. The values *position* and *size* must be constants. The value *size* must be
not be bigger than the varnode input1, and *size* + *position* must not be bigger than the varnode
input0.

This operation is never generated as raw p-code, even though it is equivalent to SLEIGH **bitrange**
syntax such as input0\[10,1\] = input1.

## ZPULL

| Parameters |  | Description |
| --: | --- | --- |
| input0 |  | Varnode to extract a value from. |
| position | (**constant**) | Constant indicating the bit position to extract from. |
| size | (**constant**) | Constant indicating the number of bits to extract. |
| output |  | Varnode containing the extracted value as an unsigned integer. |

**Semantic statement**

Cannot be explicitly coded.

A **ZPULL** operation extracts *size* bits from input0 and returns them as an unsigned integer value
in output, zero extending the bits to the size of output.

The *position* indicates the least significant bit in the range being extracted, with the bits in
input0 labeled from least to most significant, starting at 0. The varnodes input0 and output can be
different size. The values *position* and *size* must be constants. The value *size* must not be
bigger than the varnode output, and *size* + *position* must not be bigger than the varnode input0.

**ZPULL** is never generated as raw p-code, even though it is equivalent to SLEIGH **bitrange**
syntax such as output = input0\[10,1\].

## SPULL

| Parameters |  | Description |
| --: | --- | --- |
| input0 |  | Varnode to extract a value from. |
| position | (**constant**) | Constant indicating the bit position to extract from. |
| size | (**constant**) | Constant indicating the number of bits to extract. |
| output |  | Varnode containing the extracted value as a signed integer |

**Semantic statement**

Cannot be explicitly coded.

An **SPULL** operation extracts *size* bits from input0 and returns them as a signed integer value
in output. The value is sign extended to the size of output, duplicating the most significant
extracted bit.

The *position* indicates the least significant bit in the range being extracted, with the bits in
input0 labeled from least to most significant, starting at 0. The varnodes input0 and output can be
different size. The values *position* and *size* must be constants. The value *size* must not be
bigger than the varnode output, and *size* + *position* must not be bigger than the varnode input0.

**SPULL** is never generated as raw p-code.

---

Prev: [Pseudo P-CODE Operations](pseudo-ops.md) \| [Home](pcoderef.md) \| Next: [Syntax
Reference](reference.md)
