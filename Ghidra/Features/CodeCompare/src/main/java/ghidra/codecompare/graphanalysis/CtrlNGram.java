/* ###
 * IP: GHIDRA
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
package ghidra.codecompare.graphanalysis;

/**
 * N-gram hash on the control-flow graph rooted at specific node {@link CtrlVertex}.
 * The n-gram depth is the maximum number of (backward) edge traversals from the root
 * node to any other node involved in the hash.  The n-gram weight is the total number of
 * nodes involved in the hash.   The n-gram sorts with bigger weights first so that
 * n-grams involving more nodes are paired first.
 */
public class CtrlNGram {
	int weight;				// The number of nodes involved in this hash
	int depth;				// The maximum distance between nodes in this n-gram set
	int hash;				// The hash
	CtrlVertex root;		// The root node of the n-gram

	/**
	 * Construct a control-flow n-gram.
	 * @param node is the root control-flow node from which the n-gram is computed
	 * @param weight is the number of nodes involved in computing the n-gram
	 * @param depth is the maximum distance between nodes involved in the n-gram
	 * @param hash is the hash value for the n-gram
	 */
	public CtrlNGram(CtrlVertex node, int weight, int depth, int hash) {
		this.depth = depth;
		this.weight = weight;
		this.hash = hash;
		this.root = node;
	}

	/**
	 * Compare the hash of this n-gram with another.  The weight and depth of the hashes must also
	 * be equal.  The node(s) underlying the n-gram may be different.
	 * @param other is the other n-gram
	 * @return true if the hashes are the same
	 */
	public boolean equalHash(CtrlNGram other) {
		if (other == null) {
			return false;
		}
		// Compare just the hash data
		if (weight == other.weight && depth == other.depth && hash == other.hash) {
			return true;
		}
		return false;
	}

	/**
	 * Check if this and another n-gram are rooted in different control-flow graphs
	 * @param other is the other n-gram to compare
	 * @return true if the n-grams are from different graphs
	 */
	public boolean graphsDiffer(CtrlNGram other) {
		return (root.graph.side != other.root.graph.side);
	}

}
