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

import java.util.ArrayList;

import ghidra.program.model.pcode.*;

/**
 * A node in the data-flow graph of a function as produced by the Decompiler, represented by EITHER
 * a Varnode or PcodeOp.  A node stores references to immediate incoming nodes (sources) and immediate
 * outgoing nodes (sinks).  The node also stores hashes of n-grams involving this node, where
 * an n-gram is a set of adjacent nodes out to a depth of n.
 */
public class DataVertex {

	int uid;								// Unique identifying integer
	PcodeOpAST op;							// The underlying PcodeOp (or null)
	VarnodeAST vn;							// The underlying Varnode (or null)
	DataGraph graph;						// The containing graph
	ArrayList<DataVertex> sources;			// Nodes with an incoming edge
	ArrayList<DataVertex> sinks;			// Nodes with an outgoing edge
	ArrayList<DataNGram> ngrams;			// A list of n-grams (hashes of nearest neighbors) rooted at this node
	int passComplete;						// Last pass for which this node was evaluated
	boolean paired;							// Found a match for this node

	/**
	 * Construct node from a PcodeOp
	 * @param myOp is the PcodeOp
	 * @param myGraph is the graph owning the node
	 * @param uniqueID is a unique id to assign to the node
	 */
	public DataVertex(PcodeOpAST myOp, DataGraph myGraph, int uniqueID) {
		op = myOp;
		vn = null;
		commonConstructor(myGraph, uniqueID);
	}

	/**
	 * Construct node from a Varnode
	 * @param myVn is the Varnode
	 * @param myGraph is the graph owning the node
	 * @param uniqueID is a unique id to assign to the node
	 */
	public DataVertex(VarnodeAST myVn, DataGraph myGraph, int uniqueID) {
		vn = myVn;
		op = null;
		commonConstructor(myGraph, uniqueID);
	}

	/**
	 * Initialize internals of the node. Allocate storage for edges and n-grams.
	 * @param myGraph is the graph owning the node
	 * @param uniqueID is a unique id to assign to the node
	 */
	private void commonConstructor(DataGraph myGraph, int uniqueID) {
		uid = uniqueID * 2 + myGraph.side.getValue();
		graph = myGraph;
		sources = new ArrayList<DataVertex>();
		sinks = new ArrayList<DataVertex>();
		ngrams = new ArrayList<DataNGram>();
		int hash = depthZeroHash();
		ngrams.add(new DataNGram(this, 1, 0, hash));
		paired = false;
		passComplete = -1;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("uid=").append(uid).append(' ');
		if (op != null) {
			for (int i = 0; i < sinks.size(); ++i) {
				buffer.append('[').append(sinks.get(i).uid).append("] = ");
			}
			buffer.append(op.getMnemonic());
			for (int i = 0; i < sources.size(); ++i) {
				buffer.append(" [").append(sources.get(i).uid).append(']');
			}
		}
		else {
			buffer.append(vn.toString());
		}
		return buffer.toString();
	}

	/**
	 * Mark this node as disconnected from its graph.
	 * Clear any incoming or outgoing edges to/from this node.
	 * Clear the ngrams
	 */
	void collapse() {
		sinks.clear();
		sources.clear();
		ngrams.clear();
	}

	@Override
	public int hashCode() {
		return uid;
	}

	/**
	 * Compute a hash of the meta-data associated with the node, not including edges.
	 * This is effectively a 0-gram of the node, collecting data about the node itself but
	 * nothing about its neighbors.  The hash for PcodeOp nodes, is just the opcode.  For
	 * Varnodes, the hash collects info about the size and the type of Varnode (local, global, constant).
	 * @return the hash
	 */
	private int depthZeroHash() {
		int encoding = 0;										// Initialize
		if (op != null) {
			if (op.getOpcode() == PcodeOp.PTRSUB) {				// Replace PTRSUBs with INT_ADDs
				encoding = PcodeOp.INT_ADD;
			}
			else {
				encoding = op.getOpcode();
			}
			encoding |= 0xc0000000;								// Bits indicating a PcodeOp specifically
		}
		else {
			VarnodeAST node = vn;
			//For Varnodes, the encoding needs to know whether the node is global or local and what
			// size is allocated to it.
			int ramCode = (graph.ramCaring ? 1 : 0) * (node.isPersistent() ? 1 : 0);
			int constCode = (node.isConstant() ? 1 : 0);
			int size = node.getSize();
			if (graph.sizeCollapse && size > 4) {		// If sizeCollapse is on, treat sizes larger then 4 bytes
				size = 4;						// the same as a size of 4
			}
			int sizeCode = ((size << 4) >> 4);	// Make top 4 bits are clear

			encoding |= (ramCode << 29);
			encoding |= (constCode << 28);
			encoding |= sizeCode;
			encoding |= (1 << 31);
			if (graph.constCaring && graph.isConstantNonPointer(node)) {
				// Only hash an exact constant value if it doesn't look like a pointer
				return Pinning.hashTwo(encoding, (int) node.getOffset());
			}
		}
		return Pinning.hashTwo(encoding, 0);	// Hash the collected info
	}

	/**
	 * Compute and store a new n-gram by combining existing (n-1)-grams from sources. 
	 * @param index is the index of the current, already computed, (n-1)-gram to recurse on
	 */
	void nextNGramSource(int index) {
		int nextSize = 1;
		DataNGram zeroGram = ngrams.get(0);			// 0-gram for this node
		int finalHash;
		if (isCommutative()) {							// Commutative nodes have indistinguishable sources.
			finalHash = 0;
			for (DataVertex neighbor : sources) {
				DataNGram gram = neighbor.ngrams.get(index);	// Immediate neighbor (n-1)-gram
				finalHash += gram.hash;					// Combine hashes using a commutative operation
				nextSize += gram.weight;				// Running tally of number of nodes in hash
			}
			finalHash = Pinning.hashTwo(zeroGram.hash, finalHash);
		}
		else {
			finalHash = zeroGram.hash;
			for (DataVertex neighbor : sources) {
				DataNGram gram = neighbor.ngrams.get(index);	// Immedate neighbor (n-1)-gram
				finalHash = Pinning.hashTwo(finalHash, gram.hash);	// Hash in, in order
				nextSize += gram.weight;				// Running tally of number of nodes in hash
			}
		}

		ngrams.add(new DataNGram(this, nextSize, ngrams.size(), finalHash));
	}

	/**
	 * @return true if this node represents a PcodeOp (as opposed to a Varnode) in the data-flow
	 */
	public boolean isOp() {
		return (op != null);
	}

	/**
	 * @return true if this node has been removed from its DataGraph
	 */
	public boolean isCollapsed() {
		return (ngrams.size() == 0);
	}

	/**
	 * Is the underlying node a PcodeOp which takes commutative inputs?
	 * @return true if the PcodeOp is commutative
	 */
	public boolean isCommutative() {
		if (op == null) {
			return false;
		}
		int opc = op.getOpcode();
		if (opc == PcodeOp.MULTIEQUAL) {
			return true;		// For purposes of Pinning algorithm, treat MULTIEQUAL as commutative
		}
		return PcodeOp.isCommutative(opc);
	}
}
