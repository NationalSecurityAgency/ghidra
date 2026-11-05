# Pseudo P-CODE Operations

Practical analysis systems need to be able to describe operations, whose exact effect on a machine's
memory state is not fully modeled. P-code allows for this by defining a small set of *pseudo*
operators. Such an operator is generally treated as a placeholder for some, possibly large, sequence
of changes to the machine state. In terms of analysis, either the operator is just carried through
as a black-box or it serves as a plug-in point for operator substitution or other specially tailored
transformation. Pseudo operators may violate the requirement placed on other p-code operations that
all effects must be explicit.

## CALLOTHER

| Parameters |  | Description |
| --: | --- | --- |
| input0 | (**special**) | Constant ID of user-defined op to perform. |
| input1 |  | First parameter of user-defined op. |
| ... |  | Additional parameters of user-defined op. |
| \[output\] |  | Optional output of user-defined op. |

**Semantic statement**

```
userop(input1, ... );
output = userop(input1,...);
```

This is a placeholder for (a family of) user-definable p-code instructions. It allows p-code
instructions to be defined with semantic actions that are not fully specified. Machine instructions
that are too complicated or too esoteric to fully implement can use one or more **CALLOTHER**
instructions as placeholders for their semantics.

The first input parameter input0 is a constant ID assigned by the specification to a particular
semantic action. Depending on how the specification defines the action associated with the ID, the
**CALLOTHER** instruction can take an arbitrary number of input parameters and optionally have an
output parameter. Exact details are processor and specification dependent. Ideally, the output
parameter is determined by the input parameters, and no variable is affected except the output
parameter. But this is no longer a strict requirement, side-effects are possible. Analysis should
generally treat these instructions as a “black-box” which still have normal data-flow and can be
manipulated symbolically.

## CPOOLREF

| Parameters |  | Description |
| --: | --- | --- |
| input0 |  | Varnode containing pointer offset to object. |
| input1 | (**special**) | Constant ID indicating type of value to return. |
| ... |  | Additional parameters describing value to return. |
| output |  | Varnode to contain requested size, offset, or address. |

**Semantic statement**

```
output = cpool(input0,input1);
```

This operator returns specific run-time dependent values from the *constant pool*. This is a concept
for object-oriented instruction sets and other managed code environments, where some details about
how instructions behave can be deferred until run-time and are not directly encoded in the
instruction. The **CPOOLREF** operator acts a query to the system to recover this type of
information. The first parameter is a pointer to a specific object, and subsequent parameters are
IDs or other special constants describing exactly what value is requested, relative to the object.
The canonical example is requesting a method address given just an ID describing the method and a
specific object, but **CPOOLREF** can be used as a placeholder for recovering any important value
the system knows about. Details about this instruction, in terms of emulation and analysis, are
necessarily architecture dependent.

## NEW

| Parameters | Description |
| --: | --- |
| input0 | Varnode containing class reference |
| \[input1\] | If present, varnode containing count of objects to allocate. |
| output | Varnode to contain pointer to allocated memory. |

**Semantic statement**

```
output = new(input0);
```

This operator allocates memory for an object described by the first parameter and returns a pointer
to that memory. This is used to model object-oriented instruction sets where object allocation is an
atomic operation. Exact details about how memory is affected by a **NEW** operation is generally not
modeled in these cases, so the operator serves as a placeholder to allow analysis to proceed.

---

Prev: [P-Code Operation Reference](pcodedescription.md) \| [Home](pcoderef.md) \| Next: [Additional
P-CODE Operations](additionalpcode.md)
