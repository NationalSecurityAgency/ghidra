# Overview Queries

An **Overview Query** queries a BSim database for the number of matches to each 
function in an executable. The matching functions themselves are not returned. 
Similarity and Confidence thresholds apply to an Overview query, but the 
"Matches per Function" bound does not.

To perform an Overview Query, select `BSim -> Perform Overview...` from the Code
Browser.

## Exercise 1: Hit Counts and Self-Similarities

1. Perform an Overview query on `postgres` using the default query bounds.  You should see
the following result:
![](./images/overview_window.png)
1. Sort the table by the "Hit Count" column in ascending order.  Typically, the functions with the largest hit counts will have low self-similarity. Verify that that is the case for this table. 
1. Q: Examine the functions with the highest hit count.  Why are there so many matches, and 
why do they all have the same BSim feature vector?
    - <details><summary>A:</summary>  These functions simply return constants. BSim feature vectors
incorporate the fact that varnode is constant but do not incorporate the specific value.</details>

## Exercise 2: Selections and Queries

Using the hit count column, it is possible to exclude functions with large numbers of matches.

1. In the Overview Table, select all functions whose hit count is 5 or less.
1. Right-click on the selection and perform the `Search Selected Functions` action.  Sort the
query results by `Function Count` and verify that `demangler_gnu_v2_33_1` is far down the list.

## Exercise 3: Vector Hashes

Suppose `foo` and `bar` have the same number of hits in the Overview table.  There are two
possibilities:
- `foo` and `bar` have distinct feature vectors which happen to have the same number of matches.
- `foo` and `bar` have the same feature vector.

An optional column, `Vector Hash`, can be used to distinguish between these two cases.

1. Enable the `Vector Hash` Column in the Overview Table.
1. Sort the hit count column in ascending order, (multi)sort the Self Significance column in 
descending order, then (multi)sort the Vector Hash column in ascending order.
1. Q: What are the first functions in the table with the same vector hash?
    - <details><summary>A:</summary> `ts_headline_json_byid_opt` and `ts_headline_jsob_byid_opt`
    </details>
1. Examine the decompiled code of these two functions and verify that they should have identical
BSim vectors.










Next Section: [Queries and Filters](BSimTutorial_Filters.md)