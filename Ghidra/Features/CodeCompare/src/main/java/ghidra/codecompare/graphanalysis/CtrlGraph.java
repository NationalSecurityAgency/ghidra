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

import java.util.*;

import ghidra.codecompare.graphanalysis.Pinning.Side;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;

/**
 * A control-flow graph of a function for computing n-grams (CtrlNGram) that can be matched
 * with another function.  It mirrors the control-flow graph in HighFunction, but vertices,
 * CtrlVertex, can have control-flow specific n-grams attached.
 */
public class CtrlGraph {

	Side side;					// Which of the two functions being compared
	HighFunction hfunc;			// The control-flow graph from the decompiler being mirrored
	Map<PcodeBlockBasic, CtrlVertex> blockToVertex;	// Map from PcodeBlockBasic to corresponding CtrlVertex
	ArrayList<CtrlVertex> nodeList;		// The list of nodes (basic blocks) in the graph

	/**
	 * Construct the control-flow graph, given a HighFunction.
	 * @param side is 0 or 1 indicating which of the two functions being compared
	 * @param hfunct is the decompiler produced HighFunction
	 */
	public CtrlGraph(Side side, HighFunction hfunct) {
		this.side = side;
		this.hfunc = hfunct;
		this.nodeList = new ArrayList<>();
		this.blockToVertex = new HashMap<>();
		ArrayList<PcodeBlockBasic> blockList = this.hfunc.getBasicBlocks();

		// Create the vertices from basic blocks
		int uidCounter = 0;
		for (PcodeBlockBasic curBlock : blockList) {
			CtrlVertex temp = new CtrlVertex(curBlock, uidCounter++, this);
			this.blockToVertex.put(curBlock, temp);
			this.nodeList.add(temp);
		}

		// Make the edges of the graph
		for (PcodeBlockBasic curBlock : blockList) {
			CtrlVertex curVert = this.blockToVertex.get(curBlock);
			for (int i = 0; i < curBlock.getOutSize(); i++) {
				PcodeBlockBasic neighborBlock = (PcodeBlockBasic) curBlock.getOut(i);
				CtrlVertex neighborVert = this.blockToVertex.get(neighborBlock);
				neighborVert.sources.add(curVert);
				curVert.sinks.add(neighborVert);
			}
		}
	}

	/**
	 * For every node in the graph, clear calculated n-grams.
	 */
	public void clearNGrams() {
		for (CtrlVertex node : nodeList) {
			node.clearNGrams();
		}
	}

	/**
	 * Add extra distinguishing color to the 0-gram of each control-flow vertex.
	 */
	public void addEdgeColor() {
		for (CtrlVertex vert : nodeList) {
			vert.addEdgeColor();
		}
	}

	/**
	 * Populate n-gram lists for every node.  We generate two types of n-grams.  One walking
	 * back from the root through sources, and the other walking forward from the root through sinks.
	 * @param numNGrams is the number of n-grams to generate per node
	 */
	public void makeNGrams(int numNGrams) {
		int sourceSize = (numNGrams - 1) / 2 + 1;
		for (int i = 0; i < sourceSize; ++i) {
			for (CtrlVertex node : nodeList) {
				node.nextNGramSource(i);		// Construct (n+1)-gram from existing n-gram	
			}
		}
		for (CtrlVertex node : nodeList) {
			node.nextNGramSink(0);				// Produces index = (sourceSize + 1)
		}
		for (int i = sourceSize + 1; i < numNGrams - 1; ++i) {
			for (CtrlVertex node : nodeList) {
				node.nextNGramSink(i);
			}
		}
	}
}
