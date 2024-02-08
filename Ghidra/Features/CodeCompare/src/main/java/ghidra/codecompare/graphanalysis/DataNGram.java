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
 * Sortable n-gram hash on the data-flow graph rooted at specific node {@link DataVertex}.
 * The n-gram depth is the maximum number of (backward) edge traversals from the root
 * node to any other node involved in the hash.  The n-gram weight is the total number of
 * nodes involved in the hash.   The n-gram sorts with bigger weights first so that
 * n-grams involving more nodes are paired first.
 */
public class DataNGram implements Comparable<DataNGram> {
	int weight;			// The number of nodes involved in this hash
	int depth;			// The maximum distance between nodes in this n-gram set
	int hash;			// The hash
	DataVertex root;	// The root node of the n-gram

	/**
	 * Construct a data-flow n-gram.
	 * @param node is the root data-flow node from which the n-gram is computed
	 * @param weight is the number of data-flow nodes involved in the n-gram
	 * @param depth is the maximum distance between nodes involved in the n-gram
	 * @param hash is the hash value for the n-gram
	 */
	public DataNGram(DataVertex node, int weight, int depth, int hash) {
		this.depth = depth;
		this.weight = weight;
		this.hash = hash;
		this.root = node;
	}

	@Override
	public int compareTo(DataNGram other) {
		if (this.weight > other.weight) {			// Sort so that bigger weights come first
			return -1;
		}
		else if (this.weight < other.weight) {
			return 1;
		}

		if (this.depth > other.depth) {				// Sort on depth
			return -1;
		}
		else if (this.depth < other.depth) {
			return 1;
		}

		if (this.hash > other.hash) {				// Then sort on hash
			return -1;
		}
		else if (this.hash < other.hash) {
			return 1;
		}

		if (this.root.uid > other.root.uid) {		// For equivalent hashes, sort based on the node id
			return -1;
		}
		else if (this.root.uid < other.root.uid) {
			return 1;
		}

		// Finally, sort on the graph owning the root node
		return other.root.graph.side.compareTo(this.root.graph.side);
	}

	/**
	 * Compare the hash of this n-gram with another.  The weight and depth of the hashes must also
	 * be equal.  The node(s) underlying the n-gram may be different.
	 * @param other is the other n-gram
	 * @return true if the hashes are the same
	 */
	public boolean equalHash(DataNGram other) {
		if (other == null) {
			return false;
		}
		// Compare just hash data
		if (this.weight == other.weight && this.depth == other.depth && this.hash == other.hash) {
			return true;
		}
		return false;
	}

	/**
	 * Check if this and another n-gram are rooted in different data-flow graphs
	 * @param other is the other n-gram to compare
	 * @return true if the n-grams are from different graphs
	 */
	public boolean graphsDiffer(DataNGram other) {
		if (this.root.graph != other.root.graph) {
			return true;
		}
		return false;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("d=").append(depth);
		buffer.append(" h=").append(hash);
		buffer.append(" w=").append(weight);
		buffer.append(" vert=").append(root.uid);
		return buffer.toString();
	}

}
