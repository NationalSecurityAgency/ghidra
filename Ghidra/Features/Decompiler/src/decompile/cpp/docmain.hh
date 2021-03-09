/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/** \mainpage Decompiler Analysis Engine

  \section toc Table of Contents

     - \ref overview
     - \ref capabilities
     - \ref design
     - \ref workflow
     - \ref ghidraimpl
     - \subpage sleigh
     - \subpage coreclasses
     - \subpage termrewriting

  \section overview Overview

  Welcome to the \b Decompiler \b Analysis \b Engine. It is a
  complete library for performing automated data-flow analysis
  on software, starting from the binary executable. This
  documentation is geared toward understanding the source code
  and starts with a brief discussion of the libraries capabilities
  and moves immediately into the design of the decompiler and
  the main code workflow.

  The library provides its own Register
  Transfer Language (RTL), referred to internally as \b p-code,
  which is designed specifically for reverse engineering
  applications.  The disassembly of processor specific machine-code
  languages, and subsequent translation into \b p-code, forms
  a major sub-system of the decompiler. There is a processor
  specification language, referred to as \b SLEIGH, which is
  dedicated to this translation task, and there is a corresponding
  section in the documentation for the classes and methods used
  to implement this language in the library (See \subpage sleigh).
  This piece of the code can be built as a standalone binary
  translation library, for use by other applications.

  For getting up to speed quickly on the details of the source
  and the decompiler's main data structures,
  there is a specific documentation page describing the core
  classes and methods.

  Finally there is a documentation page summarizing the
  simplification rules used in the core decompiler analysis.

  \section capabilities Capabilities

  \section design Design

  The main design elements of the decompiler come straight
  from standard \e Compiler \e Theory data structures and
  algorithms.  This should come as no surprise, as both
  compilers and decompilers are concerned with translating
  from one coding language to another.  They both follow a
  general work flow:

     - Parse/tokenize input language.
     - Build abstract syntax trees in an intermediate language.
     - Manipulate/optimize syntax trees.
     - Map intermediate language to output language constructs.
     - Emit final output language encoding.

  With direct analogs to (forward engineering) compilers, the
  decompiler uses:

     - A Register Transfer Language (RTL) referred to as \b p-code.
     - Static Single Assignment (SSA) form.
     - Basic blocks and Control Flow Graphs.
     - Term rewriting rules.
     - Dead code elimination.
     - Symbol tables and scopes.

  Despite these similarities, the differences between a
  decompiler and a compiler are substantial and run throughout
  the entire process. These all stem from the fact that, in
  general, descriptive elements and the higher-level
  organization of a piece of code can only be explicitly
  expressed in a high-level language.  So the decompiler,
  working with a low-level language as input, can only infer
  this information.

  The features mentioned above all have a decompiler specific
  slant to them, and there are other tasks that the decompiler
  must perform that have no real analog with a compiler.
  These include:

     - Variable merging  (vaguely related to register coloring)
     - Type propagation
     - Control flow structuring
     - Function prototype recovery
     - Expression recovery

  \section workflow Main Work Flow

  Here is an outline of the decompiler work flow.

     -# \ref step0
     -# \ref step1
     -# \ref step2
     -# \ref step3
     -# \ref step4
     -# \ref step5
         - \ref step5a
         - Adjust p-code in special situations.
         - \ref step5b
         - \ref step5c
         - \ref step5d
         - \ref step5e
         - \ref step5f
     -# \ref step6
     -# \ref step7
     -# \ref step8
     -# \ref step9
     -# \ref step10
     -# \ref step11
     -# \ref step12
     -# \ref step13
     -# \ref step14

  \subsection step0 Specify Entry Point
  
  The user specifies a starting address for a particular function.

  \subsection step1 Generate Raw P-code

  The p-code generation engine is called \b SLEIGH. Based on a
  processor specification file, it maps binary encoded
  machine instructions to sequences of p-code operations.
  P-code operations are generated for a single machine
  instruction at a specific address.  The control flow
  through these p-code operations is followed to determine
  if control falls through, or if there are jumps or calls.
  A work list of new instruction addresses is kept and is
  continually revisited until there are no new instructions.
  After the control flow is traced, additional changes may
  be made to the p-code.

    -# PIC constructions are checked for, now that the
       extent of the function is known.  If a call is to a
       location that is still within the function, the call
       is changed to a jump.
    -# Functions which are marked as inlined are filled in
       at this point, before basic blocks are generated.
       P-code for the inlined function is generated
       separately and control flow is carefully set up to
       link it in properly.

   \subsection step2 Generate Basic Blocks and the CFG

   Basic blocks are generated on the p-code instructions
   (\e not the machine instructions) and a control flow graph
   of these basic blocks is generated.  Control flow is
   normalized so that there is always a unique start block
   with no other blocks falling into it.  In the case of
   subroutines which have branches back to their very first
   machine instruction, this requires the creation of an
   empty placeholder start block that flows immediately into
   the block containing the p-code for the first instruction.

   \subsection step3 Inspect Sub-functions

      -# Addresses of direct calls are looked up in the
         database and any parameter information is
         recovered.
      -# If there is information about an indirect call,
         parameter information can be filled in and the
         indirect call can be changed to a direct call.
      -# Any call for which no prototype is found has a
         default prototype set for it.
      -# Any global or default prototype recovered at this
         point can be overridden locally.

   \subsection step4 Adjust/Annotate P-code

     -# The context database is searched for known values of
        memory locations coming into the function.  These
        are implemented by inserting p-code \b COPY
        instructions that assign the correct value to the
        correct memory location at the beginning of the
        function.
     -# The recovered prototypes may require that extra
        p-code is injected at the call site so that certain
        actions of the call are explicit to the analysis
        engine.
     -# Other p-code may be inserted to indicate changes a
        call makes to the stack pointer.  Its possible that
        the change to the stack pointer is unknown. In this
        case \b INDIRECT p-code instructions are inserted to
        indicate that the state of the stack pointer is
        unknown at that point, preparing for the extrapop
        action.
     -# For each p-code call instruction, extra inputs are
        added to the instruction either corresponding to a
        known input for that call, or in preparation for the
        prototype recovery actions.  If the (potential)
        function input is located on the stack, a temporary
        is defined for that input and a full p-code \b LOAD
        instruction, with accompanying offset calculation,
        is inserted before the call to link the input with
        the (currently unknown) stack offset. Similarly
        extra outputs are added to the call instructions
        either representing a known return value, or in
        preparation for parameter recovery actions.
     -# Each p-code \b RETURN instruction for the current
        function is adjusted to hide the use of the return
        address and to add an input location for the return
        value. The return value is considered an input to
        the \b RETURN instruction.

   \subsection step5 The Main Simplification Loop

     \subsubsection step5a Generate SSA Form

     This is very similar to forward engineering
     algorithms. It uses a fairly standard phi-node
     placement algorithm based on the control flow dominator
     tree and the so-called dominance frontier.  A standard
     renaming algorithm is used for the final linking of
     variable defs and uses.  The decompiler has to take
     into account partially overlapping variables and guard
     against various aliasing situations, which are
     generally more explicit to a compiler.  The decompiler
     SSA algorithm also works incrementally. Many of the
     stack references in a function cannot be fully resolved
     until the main term rewriting pass has been performed
     on the register variables.  Rather than leaving stack
     references as associated \b LOAD s and \b STORE s, when
     the references are finally discovered, they are
     promoted to full variables within the SSA tree. This
     allows full copy propagation and simplification to
     occur with these variables, but it often requires 1 or
     more additional passes to fully build the SSA tree.
     Local aliasing information and aliasing across
     subfunction calls can be annotated in the SSA structure
     via \b INDIRECT p-code operations, which holds the
     information that the output of the \b INDIRECT is derived
     from the input by some indirect (frequently unknown)
     effect.

     \subsubsection step5b Eliminate Dead Code

     Dead code elimination is essential to the decompiler
     because a large percentage of machine instructions have
     side-effects on machine state, such as the setting of
     flags, that are not relevant to the function at a
     particular point in the code.  Dead code elimination is
     complicated by the fact that its not always clear what
     variables are temporary, locals, or globals.  Also,
     compilers frequently map smaller (1-byte or 2-byte)
     variables into bigger (4-byte) registers, and
     manipulation of these registers may still carry around
     left over information in the upper bytes.  The
     decompiler detects dead code down to the bit, in order
     to appropriately truncate variables in these
     situations.

     \subsubsection step5c Propagate Local Types

     The decompiler has to infer high-level type information
     about the variables it analyzes, as this kind of
     information is generally not present in the input
     binary.  Some information can be gathered about a
     variable, based on the instructions it is used in (i.e.
     if it is used in a floating point instruction).  Other
     information about type might be available from header
     files or from the user.  Once this is gathered, the
     preliminary type information is allowed to propagate
     through the syntax trees so that related types of other
     variables can be determined.

     \subsubsection step5d Perform Term Rewriting

     The bulk of the interesting simplifications happen in
     this section.  Following Formal Methods style term
     rewriting, a long list of rules are applied to the
     syntax tree. Each rule matches some potential
     configuration in a portion of the syntax tree, and
     after the rule matches, it specifies a sequence of edit
     operations on the syntax tree to transform it.  Each
     rule can be applied repeatedly and in different parts
     of the tree if necessary.  So even a small set of rules
     can cause a large transformation. The set of rules in
     the decompiler is extensive and is tailored to specific
     reverse engineering needs and compiler constructs.  The
     goal of these transformations is not to optimize as a
     compiler would, but to simplify and normalize for
     easier understanding and recognition by human analysts
     (and follow on machine processing).  Typical examples
     of transforms include: copy propagation, constant
     propagation, collecting terms, cancellation of
     operators and other algebraic simplifications, undoing
     multiplication and division optimizations, commuting
     operators, ....

     \subsubsection step5e Adjust Control Flow Graph

     The decompiler can recognize
        - unreachable code
        - unused branches
        - empty basic blocks
        - redundant predicates
        - ...
     
     It will remove branches or blocks in order to
     simplify the control flow.

     \subsubsection step5f Recover Control Flow Structure

     The decompiler recovers higher-level control flow
     objects like loops, \b if/\b else blocks, and \b switch
     statements.  The entire control flow of the function is
     built up hierarchically with these objects, allowing it
     to be expressed naturally in the final output with the
     standard control flow constructs of the high-level
     language.  The decompiler recognizes common high-level
     unstructured control flow idioms, like \e break, and can
     use node-splitting in some situations to undo compiler
     flow optimizations that prevent a structured
     representation.

  \subsection step6 Perform Final P-code Transformations

  During the main simplification loop, many p-code
  operations are normalized in specific ways for the term
  rewriting process that aren't necessarily ideal for the
  final output. This phase does transforms designed to
  enhance readability of the final output.  A simple example
  is that all subtractions (\b INT_SUB) are normalized to be an
  addition on the twos complement in the main loop. This
  phase would convert any remaining additions of this form
  back into a subtraction operation.

  \subsection step7 Exit SSA Form and Merge Low-level Variables (phase 1)

  The static variables of the SSA form need to be merged
  into complete high-level variables.  The first part of
  this is accomplished by formally exiting SSA form.  The
  SSA phi-nodes and indirects are eliminated either by
  merging the input and output variables or inserting extra
  \b COPY operations.  Merging must guard against a high-level
  variable holding different values (in different memory
  locations) at the same time.  This is similar to register
  coloring in compiler design.

  \subsection step8 Determine Expressions and Temporary Variables

  A final determination is made of what the final output
  expressions are going to be, by determining which
  variables in the syntax tree will be explicit and which
  represent temporary variables.  Certain terms must
  automatically be explicit, such as constants, inputs,
  etc. Other variables are forced to be explicit because
  they are read too many times or because making it implicit
  would propagate another variable too far.  Any variables
  remaining are marked implicit.

  \subsection step9 Merge Low-level Variables (phase 2)

  Even after the initial merging of variables in phase 1,
  there are generally still too many for normal C code.  So
  the decompiler does additional, more speculative merging.
  It first tries to merge the inputs and outputs of copy
  operations, and then the inputs and outputs of more
  general operations.  And finally, merging is attempted on
  variables of the same type. Each potential merge is
  subject to register coloring restrictions.

  \subsection step10 Add Type Casts

  Type casts are added to the code so that the final output
  will be syntactically legal.

  \subsection step11 Establish Function's Prototype

  The register/stack locations being used to pass parameters
  into the function are analyzed in terms of the parameter
  passing convention being used so that appropriate names
  can be selected and the prototype can be printed with the
  input variables in the correct order.

  \subsection step12 Select Variable Names

  The high-level variables, which are now in their final
  form, have names assigned based on any information
  gathered from their low-level elements and the symbol
  table.  If no name can be identified from the database, an
  appropriate name is generated automatically.

  \subsection step13 Do Final Control Flow Structuring

   -# Order separate components
   -# Order switch cases
   -# Determine which unstructured jumps are breaks
   -# Stick in labels for remaining unstructured jumps

  \subsection step14 Emit Final C Tokens

  Following the recovered function prototype, the recovered
  control flow structure, and the recovered expressions, the
  final C tokens are generated.  Each token is annotated
  with its syntactic meaning, for later syntax
  highlighting. And most tokens are also annotated with the
  address of the machine instruction with which they are
  most closely associated.  This is the basis for the
  machine/C code cross highlighting capability.  The tokens
  are passed through a standard Oppen pretty-printing
  algorithm to determine the final line breaks and
  indenting.


*/
