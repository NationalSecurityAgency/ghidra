# Evaluating Matches and Transferring Information

Summarizing what we've created over the last few sections, we now have:
1. A stripped executable (``postgres``).
1. A Ghidra project containing some object files *with debug information*[^1] used to build that executable.
1. A BSim database of containing the BSim signatures of the object files.

[^1]: Having debug information isn't necessary to use BSim (as we've seen in a previous exercise), but it is convenient.

We now demonstrate using BSim to help reverse engineer ``postgres``.
While doing this, we'll showcase some of the features available in the decompiler diff view.  

## Exercise: Exploring the Highlights

Import and analyze the stripped `postgres` executable into the tutorial project, then perform the following steps:

1. Select all functions in `postgres` via Ctrl-A in the Listing.
1. Perform a BSim query of the database ``example``.
    - **Note:** We use the results of this query in the following few exercises. 
    If don't close the BSim search results window, you won't have to issue the query again.
1. Sort the rows by confidence and find the row with ``grouping_planner`` as the matching function.
The corresponding function in `postgres` should have a default name. 
1. Examine this match in the side-by-side decompiler view.
Note that the matching function has better data type information due to the debug information.
1. Q: Why does the placement of the `double` argument between the functions?
  <details><summary>Answer</summary> Floating point values and integer/pointer values are passed in separate sets registers.
  Neither ordering is wrong since both are consistent with the instructions of the function.
  The debug info records a specific signature (and ordering) for the function, which Ghidra applies.
  In the version without debug information, the decompiler used heuristics to determine the function's signature.</details>

For matches with a fair number of differences, the decompiler diff panel can get pretty colorful.
Furthermore, as you click around, tokens will gain and lose highlight of various colors.
It's worth giving a brief explanation of when highlighting happens and what the different colors mean.
Some terminology: if you click on a token in a decompiler panel, that token becomes the *focused token*.

The colors:

- Blue is used to highlight differences between the two functions.
- Pink is used to highlight the focused token and its match.
- Lavender is used to highlight the focused token when it does not have a match.
- Orange is used to highlight the focused token when it is ineligible for match.
Certain tokens, such as whitespace tokens or tokens used in variable declarations, are never assigned matching tokens.

## Exercise: Locking and Unlocking Scrolling


Before moving on, experiment with locking and unlocking scrolling.

## Exercise: Comparing Callees

The token matching algorithm matches a function call in one program to a function call in another by considering the data flow into and out of the ``CALL`` instruction, but it does not do anything with the bodies of the callees.
However, given a matched pair of calls, you can bring up a new comparison window and compare their bodies manually.

Ctrl f in left view
FUN_
find something





## Exercise: Transferring Signatures

1. Transfer the signatures to the queried function via either:
    - The `Apply Function Signature to Other Side` action in the diff window.
    - The `Apply Function Names, Namespaces, and Signatures` action in the BSim Search Results window.

**Warning**: You should be absolutely certain that the datatypes are the same before applying signatures.
If there have been any changes to a datatype's definition, you could end up bringing incorrect datatypes into a program, even using BSim matches with 1.0 similarity.

# Exercise: Multiple Comparisons





In the next section, we discuss the Executable Results table.


Next Section: [Executable-level Results](BSimTutorial_Exe_Results.md)