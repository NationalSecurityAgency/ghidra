# 8. Using Context

For most practical specifications, the disassembly and semantic meaning of an instruction can be
determined by looking only at the bits in the encoding of that instruction. SLEIGH syntax reflects
this fact as every constructor or attached register is ultimately decided by examining *fields*, the
syntactic representation of these instruction bits. In some cases however, the instruction encoding
itself may not be enough. Additional information, which we refer to as *context*, may be necessary
to fully resolve the meaning of the instruction.

In truth, almost every modern processor has multiple modes of operation, where the exact
interpretation of instructions may depend on that mode. Typical examples include distinguishing
between a 16-bit mode and a 32-bit mode, or between a big endian mode or a little endian mode. But
for the specification designer, these are of little consequence because most software for such a
processor will run in only one mode without ever changing it. The designer need only pick the most
popular or most important mode for his projects and design to that. If there is in fact software
that runs under a different mode, the other mode can be described in a separate specification.

However, for certain processors or software, the need to distinguish between different
interpretations of the same instruction encoding, based on context, may be a crucial part of the
disassembly and analysis process. There are two typical situations where this becomes necessary.

* The processor supports two (or more) separate instruction sets. The set to use is usually
  determined by special bits in a status register, and a single piece of software frequently
  switches between these modes.
* The processor supports instructions that temporarily affect the execution of the immediately
  following instruction(s). For example, many processors support hardware *loop* instructions that
  automatically cause the following instructions to repeat without an explicit instruction causing
  the branching and loop counting.

SLEIGH solves these problems by introducing *context variables*. The syntax for defining these
symbols was described in [Section 6.4, “Context Variables”](sleigh_tokens.md#64-context-variables).
As mentioned there, the easiest and most common way to use a context variable is as just another
field to use in our bit patterns. It gives us the extra information we need to distinguish between
different instructions whose encodings are otherwise the same.

## 8.1. Basic Use of Context Variables

Suppose a processor supports the use of two different sets of registers in its main addressing mode,
based on the setting of a status bit which can be changed dynamically. If an instruction is executed
with this bit cleared, then one set of registers is used, and if the bit is set, the other registers
are used. The instructions otherwise behave identically.

```
define endian=big;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 r2 r3 r4 r5 r6 r7 ];
define register offset=0x100 size=4 [ s0 s1 s2 s3 s4 s5 s6 s7 ];
define register offset=0x200 size=4 [ statusreg ]; # define context bits (if defined, size must be multiple of 4-bytes)

define token instr(16)
  op=(10,15) rreg1=(7,9) sreg1=(7,9) imm=(0,6)
;
define context statusreg
  mode=(3,3)
;
attach variables [ rreg1 ] [ r0 r1 r2 r3 r4 r5 r6 r7 ];
attach variables [ sreg1 ] [ s0 s1 s2 s3 s4 s5 s6 s7 ];

Reg1: rreg1 is mode=0 & rreg1 { export rreg1; }
Reg1: sreg1 is mode=1 & sreg1 { export sreg1; }

:addi Reg1,#imm  is op=1 & Reg1 & imm { Reg1 = Reg1 + imm; }
```

In this example the symbol *Reg1* uses the 3 bits (7,9) to select one of eight registers. If the
context variable *mode* is set to 0, it selects an *r* register, through the *rreg1* field. If
*mode* is set to 1 on the other hand, an *s* register is selected instead via *sreg1*. The *addi*
instruction (encoded as 0x0590 for example) can disassemble in one of two ways.

```
addi r3,#0x10
```
*or*
```
addi s3,#0x10
```

This is the same behavior as if *mode* were defined as a field instead of a context variable, except
that there is nothing in the instruction encoding itself which indicates which of the two forms will
be chosen. An engine doing the disassembly will have global state associated with the *mode*
variable that will make the final decision about which form to generate. The setting of this state
is (at least partially) out of the control of SLEIGH, although see the following sections.

## 8.2. Local Context Change

SLEIGH can make direct modifications to context variables through statements in the disassembly
action section of a constructor. The left-hand side of an assignment statement in this section can
be a context variable, see [Section 7.5.2, “General Actions and Pattern
Expressions”](sleigh_constructors.md#752-general-actions-and-pattern-expressions). Because the
result of this assignment is calculated in the middle of the instruction disassembly, the change in
value of the context variable can potentially affect any remaining parsing for that instruction. A
modal variable is being added to what was otherwise a stateless grammar, a common technique in many
practical parsing engines.

Any assignment statement changing a context variable is immediately executed upon the successful
match of the constructor containing the statement and can be used to guide the parsing of the
constructor's operands. We introduce two more instructions to the example specification from the
previous section.

```
:raddi Reg1,#imm is op=2 & Reg1 & imm [ mode=0; ] {
    Reg1 = Reg1 + imm;
}
:saddi Reg1,#imm is op=3 & Reg1 & imm [ mode=1; ] {
    Reg1 = Reg1 + imm;
}
```

Notice that both new constructors modify the context variable *mode*. The raddi instruction sets
mode to 0 and effectively guarantees that an *r* register will be produced by the disassembly.
Similarly, the *saddi* instruction can force an *s* register. Both are in contrast to the *addi*
instruction, which depends on a global state. The changes to *mode* made by these instructions only
persist for parsing of that single instruction. For any following instructions, if the matching
constructors use *mode*, its value will have reverted to its original global state. The same holds
for any context variable modified with this syntax. If an instruction needs to permanently modify
the state of a context variable, the designer must use constructions described in [Section 8.3,
“Global Context Change”](#83-global-context-change).

Clearly, the behavior of the above example could be easily replicated without using context
variables at all and having the selection of a register set simply depend directly on the *op*
field. But, with more complicated addressing modes, local modification of context variables can
drastically reduce the complexity and size of a specification.

At the point where a modification is made to a context variable, the specification designer has the
guarantee that none of the operands of the constructor have been evaluated yet, so if their matching
depends on this context variable, they will be affected by the change. In contrast, the matching of
any ancestor constructor cannot be affected. Other constructors, which are not direct ancestors or
descendants, may or may not be affected by the change, depending on the order of evaluation. It is
usually best not to depend on this ordering when designing the specification, with the possible
exception of orderings which are guaranteed by **build** directives.

## 8.3. Global Context Change

It is possible for an instruction to attempt a permanent change to a context variable, which would
then affect the parsing of other instructions, by using the **globalset** directive in a disassembly
action. As mentioned in the previous section, context variables have an associated global state,
which can be used during constructor matching. A complete model for this state is, unfortunately,
outside the scope of SLEIGH. The disassembly engine has to make too many decisions about what is
getting disassembled and what assumptions are being made to give complete control of the context to
SLEIGH. Because of this caveat, SLEIGH syntax for making permanent context changes should be viewed
as a suggestion to the disassembly engine.

For processors that support multiple modes, there are typically specific instructions that switch
between these modes. Extending the example from the previous sections, we add two instructions to
the specification for permanently switching which register set is being used.

```
:rmode is op=32 & rreg1=0 & imm=0
       [ mode=0; globalset(inst_next,mode); ]
{}
:smode is op=33 & rreg1=0 & imm=0
       [ mode=1; globalset(inst_next,mode); ]
{}
```

The register set is, as before, controlled by the *mode* variable, and as with a local change to
context, the variable is assigned to inside the square brackets. The *rmode* instruction sets *mode*
to 0, in order to select *r* registers via *rreg1*, and *smode* sets *mode* to 1 in order to select
*s* registers. As is described in [Section 8.2, “Local Context Change”](#82-local-context-change),
these assignments by themselves cause only a local context change. However, the subsequent
**globalset** directives make the change persist outside of the instructions themselves. The
**globalset** directive takes two parameters, the second being the particular context variable being
changed. The first parameter indicates the first address where the new context takes effect. In the
example, the expectation is that a mode change affects any subsequent instructions. So the first
parameter to **globalset** here is *inst_next*, indicating that the new value of *mode* begins at
the next address.

### 8.3.1. Context Flow

A global change to context that affects instruction decoding is typically open-ended. I.e. once the
mode switching instruction is executed, a permanent change is made to the run-time processor state,
and all future instruction decoding is affected, until another mode switch is encountered. In terms
of SLEIGH by default, the effect of a **globalset** directive follows *flow*. Starting from the
address specified in the directive, the change in context follows the control-flow of the
instructions, through branches and calls, until an execution path terminates or another context
change is encountered.

Flow following behavior can be overridden by adding the **noflow** attribute to the definition of
the context field. (See [Section 6.4, “Context Variables”](sleigh_tokens.md#64-context-variables))
In this case, a **globalset** directive only affects the context of a single instruction at the
specified address. Subsequent instructions retain their original context. This can be useful in a
variety of situations but is typically used to let one instruction alter the behavior, not
necessarily the decoding, of the following instruction. In the example below, an indirect branch
instruction jumps through a link register *lr*. If the previous instruction moves the program
counter in to *lr*, it communicates this to the branch instruction through the *LRset* context
variable so that the branch can be interpreted as a return, rather than a generic indirect branch.

```
define context contextreg
  LRset = (1,1) noflow  # 1 if the instruction before was a mov lr,pc
;
  ...
mov lr,pc  is opcode=34 & lr & pc
           [ LRset=1; globalset(inst_next,LRset); ] { lr = pc; }
  ...
blr        is opcode=35 & reg=15 & LRset=0 { goto [lr]; }
blr        is opcode=35 & reg=15 & LRset=1 { return [lr]; }
```

An alternative to the **noflow** attribute is to simply issue multiple directives within a single
constructor, so an explicit end to a context change can be given. The value of the variable exported
to the global state is the one in effect at the point where the directive is issued. Thus, after one
**globalset**, the same context variable can be assigned a different value, followed by another
**globalset** for a different address.

Because context in SLEIGH is controlled by a disassembly process, there are some basic caveats to
the use of the **globalset** directive. With *flowing* context changes, there is no guarantee of
what global state will be in effect at a particular address. During disassembly, at any given point,
the process may not have uncovered all the relevant directives, and the known directives may not
necessarily be consistent. In general, for most processors, the disassembly at a particular address
is intended to be absolute. So given enough information, it should be possible to make a definitive
determination of what the context is at a certain address, but there is no guarantee. It is up to
the disassembly process to fully determine where context changes begin and end and what to do if
there are conflicts.

---

Prev: [7. Constructors](sleigh_constructors.md) \| [Home](sleigh.md) \| Next: [9. P-code
Tables](sleigh_ref.md)
