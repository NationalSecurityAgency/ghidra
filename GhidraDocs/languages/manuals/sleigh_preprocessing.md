# 3. Preprocessing

SLEIGH provides support for simple file inclusion, macros, and other basic preprocessing functions.
These are all invoked with directives that start with the ‘@’ character, which must be the first
character in the line.

## 3.1. Including Files

In general a single SLEIGH specification is contained in a single file, and the compiler is invoked
on one file at a time. Multiple files can be put together for one specification by using the
**@include** directive. This must appear at the beginning of the line and is followed by the path
name of the file to be included, enclosed in double quotes.

`@include "example.slaspec"`

Parsing proceeds as if the entire line is replaced with the contents of the indicated file. Multiple
inclusions are possible, and the included files can have their own **@include** directives.

## 3.2. Preprocessor Macros

SLEIGH allows simple (unparameterized) macro definitions and expansions. A macro definition occurs
on one line and starts with the **@define** directive. This is followed by an identifier for the
macro and then a string to which the macro should expand. The string must either be a proper
identifier itself or surrounded with double quotes. The macro can then be expanded with typical
“\$(identifier)” syntax at any other point in the specification following the definition.

```
@define ENDIAN "big"
  ...
define endian=$(ENDIAN);
```

This example defines a macro identified as *ENDIAN* with the string “big”, and then expands the
macro in a later SLEIGH statement. Macro definitions can also be made from the command line and in
the “.spec” file, allowing multiple specification variations to be derived from one file. SLEIGH
also has an **@undef** directive which removes the definition of a macro from that point on in the
file.

`@undef ENDIAN`

## 3.3. Conditional Compilation

SLEIGH supports several directives that allow conditional inclusion of parts of a specification,
based on the existence of a macro, or its value. The lines of the specification to be conditionally
included are bounded by one of the **@if...** directives described below and at the bottom by the
**@endif** directive. If the condition described by the **@if...** directive is true, the bounded
lines are evaluated as part of the specification, otherwise they are skipped. Nesting of these
directives is allowed: a second **@if...** **@endif** pair can occur inside an initial **@if** and
**@endif**.

### 3.3.1. @ifdef and @ifndef

The **@ifdef** directive is followed by a macro identifier and evaluates to true if the macro is
defined. The **@ifndef** directive is similar except it evaluates to true if the macro identifier is
*not* defined.

```
@ifdef ENDIAN
define endian=$(ENDIAN);
@else
define endian=little;
@endif
```

This directive can only take a single identifier as an argument, any other form is flagged as an
error. For logically combining a test of whether a macro is defined with other tests, use the
**defined** operator in an **@if** or **@elif** directive (See below).

### 3.3.2. @if

The **@if** directive is followed by a boolean expression with macros as the variables and strings
as the constants. Comparisons between macros and strings are currently limited to string equality or
inequality. But individual comparisons can be combined arbitrarily using parentheses and the boolean
operators ‘&&’, ‘||’, and ‘^^’. These represent a *logical and*, a *logical or*, and a *logical
exclusive-or* operation respectively. It is possible to test whether a particular macro is defined
within the boolean expression for an **@if** directive, by using the **defined** operator. This
exists as a keyword and a functional operator only within a preprocessor boolean expression. The
**defined** keyword takes as argument a macro identifier, and it evaluates to true if the macro is
defined.

```
@if defined(X_EXTENSION) || (VERSION == "5")
  ...
@endif
```

### 3.3.3. @else and @elif

An **@else** directive splits the lines bounded by an **@if** directive and an **@endif** directive
into two parts. The first part is included in the processing if the initial **@if** directive
evaluates to true, otherwise the second part is included.

The **@elif** directive splits the bounded lines up as with **@else**, but the second part is
included only if the previous **@if** was false and the condition specified in the **@elif** itself
is true. Between one **@if** and **@endif** pair, there can be multiple **@elif** directives, but
only one **@else**, which must occur after all the **@elif** directives.

```
@if PROCESSOR == “mips”
@ define ENDIAN “big”
@elif ((PROCESSOR==”x86”)&&(OS!=”win”))
@ define ENDIAN “little”
@else
@ define ENDIAN “unknown”
@endif
```

---

Prev: [2. Basic Specification Layout](sleigh_layout.md) \| [Home](sleigh.md) \| Next: [4. Basic
Definitions](sleigh_definitions.md)
