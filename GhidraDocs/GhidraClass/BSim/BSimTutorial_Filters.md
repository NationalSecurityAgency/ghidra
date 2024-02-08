# BSim Filters

There are a number of filters that can be applied to BSim queries, involving names, architectures, compilers, ingest dates, user-defined executable categories, and other attributes.

Filters be can applied *server-side* or *client-side*.
Server-side filters affect the query results sent to Ghidra from a BSim server and can be applied using the **Filters** drop-down in the BSim Search dialog.
Client-side filters apply to the BSim Search results table and can be added and removed at will using the **Filter Results** icon ![Filter Results](images/exec.png).
However, to "undo" a server-side filter, you have to issue another BSim query without the filter.



## Exercise: Filters

1. Select all functions in ``postgres`` and bring up the BSim Search dialog.
1. Apply an **Executable name does not equal** filter with ``demangler_gnu_v2_41`` as the name to exclude.
1. Perform the query and verify ``demangler_gnu_v2_41`` is not in the list of executables with matches.
1. Using the **Search Info** icon ![Search Info](images/information.png) in the BSim Search Results toolbar, you can see the server-side filters applied to the query.
Verify that this information is correct.
1. Using the **Filter Results** icon ![Filter Results](images/exec.png), you can apply client-side filters to the query results. Experiment with applying and removing some client-side filters.

Next Section: [Scripting and Visualization](BSimTutorial_Scripting.md)