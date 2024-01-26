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

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.codecompare.graphanalysis.Pinning.Side;
import ghidra.program.model.pcode.*;

/**
 * A data-flow graph of a function for computing n-grams {@link DataNGram} that can be matched
 * with another function.  The graph mirrors the HighFunction data-flow graph but unifies
 * a Varnode and PcodeOp into a single node type (DataVertex) that can have n-grams attached.
 * This graph can be modified relative to HighFunction to facilitate matching.
 */
public class DataGraph {

	/**
	 * Helper class for associating a DataVertex with another DataVertex.
	 * To distinguish multiple things associated with one DataVertex, an optional
	 * slot indicates through which input slot the association is made.
	 */
	public static class Associate {
		DataVertex node;			// The vertex having associations
		int slot;					// The input slot through which the association is made

		public Associate(DataVertex n, int sl) {
			node = n;
			slot = sl;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof Associate)) {
				return false;
			}
			Associate other = (Associate) obj;
			if (node.uid != other.node.uid) {
				return false;
			}
			if (slot != other.slot) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			int val = node.hashCode();
			val = val * 31 + slot;
			return val;
		}
	}

	Side side;							// Which of two functions being compared
	HighFunction hfunc;					// The data-flow graph from the decompiler being mirrored
	ArrayList<DataVertex> nodeList;		// Vertices in this graph
	Map<PcodeOpAST, DataVertex> opToVert;	// Map from PcodeOps to corresponding DataVertex
	Map<VarnodeAST, DataVertex> vnToVert;	// Map from Varnodes to corresponding DataVertex
	Map<Associate, ArrayList<DataVertex>> associates;	// Vertices that should get matched together
	boolean constCaring;					// True if constant values are factored into n-gram hashes
	boolean ramCaring;					// True if local/global is factored into n-gram hashes
	boolean sizeCollapse;				// True if big Varnodes are hashed as if they were 4 bytes
	int pointerSize;					// Number of bytes in a (default) pointer
	long pointerMin;					// Minimum offset to consider a pointer

	/**
	 * Construct the data-flow graph, given a HighFunction.  Configuration parameters for later
	 * n-gram generation is given.
	 * @param side is 0 or 1 indicating which of the two functions being compared
	 * @param hfunc is the decompiler produced HighFunction
	 * @param constCaring is true if n-grams should take into account exact constant values
	 * @param ramCaring is true if n-grams should distinguish between local and global variables
	 * @param castCollapse is true if CAST operations should not be included in n-gram calculations
	 * @param sizeCollapse is true if variable sizes larger than 4 should be treated as size 4
	 */
	public DataGraph(Side side, HighFunction hfunc, boolean constCaring, boolean ramCaring,
			boolean castCollapse, boolean sizeCollapse) {
		this.side = side;
		this.constCaring = constCaring;
		this.ramCaring = ramCaring;
		this.sizeCollapse = sizeCollapse;

		pointerSize = hfunc.getFunction().getProgram().getDefaultPointerSize();
		pointerMin = (pointerSize < 3) ? 0xff : 0xffff;
		ArrayList<DataVertex> ptrsubs = new ArrayList<>();
		ArrayList<DataVertex> casts = new ArrayList<>();

		//Initialize the data inside.
		this.nodeList = new ArrayList<>();
		this.hfunc = hfunc;
		this.opToVert = new HashMap<>();
		this.vnToVert = new HashMap<>();
		this.associates = new HashMap<>();

		int uidCounter = 0;										// Counter for assigning unique ids
		// Bring in all the Varnodes as vertices
		Iterator<VarnodeAST> vnIter = this.hfunc.locRange();
		while (vnIter.hasNext()) {
			VarnodeAST currentVn = vnIter.next();
			if (currentVn.getDef() == null) {
				if (currentVn.hasNoDescend()) {
					continue;
				}
			}
			DataVertex temp = new DataVertex(currentVn, this, uidCounter++);
			this.nodeList.add(temp);
			this.vnToVert.put(currentVn, temp);
		}
		// Bring in all the PcodeOps as vertices
		Iterator<PcodeOpAST> opIter = this.hfunc.getPcodeOps();
		while (opIter.hasNext()) {
			PcodeOpAST currentOp = opIter.next();
			DataVertex temp = new DataVertex(currentOp, this, uidCounter++);
			this.nodeList.add(temp);
			this.opToVert.put(currentOp, temp);
			if (currentOp.getOpcode() == PcodeOp.PTRSUB) {
				ptrsubs.add(temp);
			}
			if (currentOp.getOpcode() == PcodeOp.CAST) {
				casts.add(temp);
			}
		}

		// Add edges to graph
		opIter = this.hfunc.getPcodeOps();
		while (opIter.hasNext()) {
			PcodeOpAST op = opIter.next();
			DataVertex node = this.opToVert.get(op);
			for (int i = 0; i < op.getNumInputs(); i++) {
				DataVertex sourceNode = this.vnToVert.get(op.getInput(i));
				if (sourceNode != null) {
					node.sources.add(sourceNode);
					sourceNode.sinks.add(node);
				}
			}
			DataVertex sinkNode = this.vnToVert.get(op.getOutput());
			if (sinkNode != null) {
				node.sinks.add(sinkNode);
				sinkNode.sources.add(node);
			}
		}

		eliminatePtrsubs(ptrsubs);

		if (castCollapse) {
			eliminateCasts(casts);
		}
	}

	/**
	 * @return the HighFunction this data-flow graph was generated from
	 */
	public HighFunction getHighFunction() {
		return hfunc;
	}

	/**
	 * Determine if the given Varnode is a constant and not a pointer.
	 * A constant is only considered a pointer if it has the size of a pointer and
	 * the constant value is not too "small".
	 * @param vn is the Varnode to check
	 * @return true if the constant is constant and not a pointer
	 */
	public boolean isConstantNonPointer(Varnode vn) {
		if (!vn.isConstant()) {
			return false;
		}
		if (vn.getSize() != pointerSize) {
			return true;
		}
		long off = vn.getOffset();
		return (off >= 0 && off <= pointerMin);
	}

	/**
	 * If a PTRSUB operation represents a &DAT_#, its input (a constant) is propagated forward
	 * to everything reading the PTRSUB, and the PTRSUB is eliminated.
	 * @param ptrsubs is the list of PTRSUB vertices
	 */
	private void eliminatePtrsubs(ArrayList<DataVertex> ptrsubs) {
		for (DataVertex subop : ptrsubs) {
			DataVertex in0Node = subop.sources.get(0);
			if (in0Node.vn.isConstant() && (in0Node.vn.getOffset() == 0)) {
				DataVertex in1Node = subop.sources.get(1);
				DataVertex outNode = subop.sinks.get(0);
				in1Node.sinks.clear();
				replaceNodeInOutEdges(outNode, in1Node);
				in0Node.collapse();
				subop.collapse();
				outNode.collapse();
				makeAssociation(subop, outNode, in1Node, 0);	// Attach subop and outNode -> in1Node
			}
		}
	}

	/**
	 * CAST operations are isolated in the graph and either:
	 *    - The input replaces reads of the output, and the output is eliminated, OR
	 *    - The output is redefined by defining PcodeOp op of the input, and the input is eliminated.
	 * @param casts is the list of CAST vertices
	 */
	private void eliminateCasts(ArrayList<DataVertex> casts) {
		for (DataVertex castNode : casts) {

			DataVertex in = castNode.sources.get(0);
			DataVertex out = castNode.sinks.get(0);
			DataVertex assoc = null;
			int assocSlot = 0;
			if (out.sinks.size() == 1) {
				assoc = out.sinks.get(0);		// Preferred node to associate with is the reading op
				// Generate distinguishing slot for associate based on input slot CAST feeds into
				for (assocSlot = 0; assocSlot < assoc.sources.size(); ++assocSlot) {
					if (assoc.sources.get(assocSlot) == out) {
						break;
					}
				}
			}

			boolean outCast = true;
			if ((out.sinks.size() == 1 && out.vn.isUnique()) || in.sources.size() == 0) {
				outCast = false;
			}

			if (outCast) {
				// PcodeOp defining CAST input, now defines CAST output
				// input is isolated
				DataVertex topOp = in.sources.get(0);
				topOp.sinks.clear();
				out.sources.clear();
				topOp.sinks.add(out);
				out.sources.add(topOp);
				in.collapse();
				if (assoc == null) {
					assoc = out;
				}
				makeAssociation(castNode, in, assoc, assocSlot);
			}
			else {
				// CAST input becomes input to descendants of CAST output
				// output is isolated
				removeInEdge(castNode, 0);
				replaceNodeInOutEdges(out, in);
				out.collapse();
				if (assoc == null) {
					assoc = in;
				}
				makeAssociation(castNode, out, assoc, assocSlot);
			}
			castNode.collapse();
		}
	}

	/**
	 * Populate n-gram lists for every node.
	 * @param numNGrams is the number of n-grams to generate per node
	 */
	public void makeNGrams(int numNGrams) {
		for (int i = 0; i < numNGrams - 1; ++i) {
			for (DataVertex node : nodeList) {
				if (node.isCollapsed()) {
					continue;					// Don't hash if disconnected from graph
				}
				node.nextNGramSource(i);		// Construct (n+1)-gram from existing n-gram
			}
		}
	}

	/**
	 * Make an association between an (op,var) node pair that has been removed from the graph, with
	 * a node that remains in the graph.
	 * @param op is the operation node being removed
	 * @param var is the variable node being removed
	 * @param assoc is the node to associate with
	 * @param assocSlot is other distinguishing info about the association (incoming slot)
	 */
	private void makeAssociation(DataVertex op, DataVertex var, DataVertex assoc, int assocSlot) {
		Associate key = new Associate(assoc, assocSlot);
		ArrayList<DataVertex> assocList = associates.get(key);
		if (assocList == null) {
			assocList = new ArrayList<>();
			associates.put(key, assocList);
		}
		assocList.add(op);
		assocList.add(var);
	}

	/**
	 * All out edges of the given node, become out edges of a replacement node. 
	 * @param node is the given node
	 * @param replacement is the node receiving the new out edges
	 */
	private void replaceNodeInOutEdges(DataVertex node, DataVertex replacement) {
		for (DataVertex outNode : node.sinks) {
			for (int i = 0; i < outNode.sources.size(); i++) {
				if (outNode.sources.get(i) == node) {
					outNode.sources.set(i, replacement);
				}
			}
			replacement.sinks.add(outNode);
		}
		node.sinks = new ArrayList<>();
	}

	/**
	 * Remove an edge between the given node and one of its inputs.
	 * @param node is the given node
	 * @param inEdge is the input edge
	 */
	private void removeInEdge(DataVertex node, int inEdge) {
		DataVertex inNode = node.sources.get(inEdge);
		int outEdge;
		for (outEdge = 0; outEdge < inNode.sinks.size(); ++outEdge) {
			if (inNode.sinks.get(outEdge) == node) {
				break;
			}
		}
		node.sources.remove(inEdge);
		inNode.sinks.remove(outEdge);
	}

	/**
	 * Dump a string representation of the data-flow graph.
	 * @param writer is the stream to write the string to
	 * @throws IOException for problems with the stream
	 */
	public void dump(Writer writer) throws IOException {
		for (DataVertex vertex : nodeList) {
			writer.append(vertex.toString());
			writer.append('\n');
		}
	}
}
