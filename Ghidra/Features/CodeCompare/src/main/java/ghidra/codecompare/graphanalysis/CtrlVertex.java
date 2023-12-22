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

import ghidra.program.model.pcode.PcodeBlockBasic;

/**
 * A basic block in the control-flow graph of a function as produced by the Decompiler.
 * A node stores references to immediate incoming nodes (sources).  The node also stores hashes of n-grams
 * {@link CtrlNGram} involving this node, where an n-gram is a set of adjacent nodes out to a depth of n.
 */
public class CtrlVertex {
	private PcodeBlockBasic block;				// Underlying basic block from the decompiler
	int uid;									// A unique id
	ArrayList<CtrlVertex> sources;				// List of blocks flowing into this block
	ArrayList<CtrlVertex> sinks;				// List of blocks this block flows into
	ArrayList<CtrlNGram> ngrams;				// A list of n-grams (hashes of nearest neighbors)
	CtrlGraph graph;							// The control-flow graph owning this node

	/**
	 * Construct a control-flow vertex from a basic block.
	 * @param blk is the basic block
	 * @param id is a unique id to assign to the node
	 * @param grph is the graph that the node is part of
	 */
	public CtrlVertex(PcodeBlockBasic blk, int id, CtrlGraph grph) {
		this.block = blk;
		this.uid = id * 2 + grph.side.getValue();
		this.sources = new ArrayList<>();
		this.sinks = new ArrayList<>();
		this.ngrams = new ArrayList<>();
		int hash = depthZeroHash(0);
		ngrams.add(new CtrlNGram(this, 1, 0, hash));
		this.graph = grph;
	}

	/**
	 * Compute a hash of the meta-data associated with the node, not including edges.
	 * This is effectively a 0-gram of the node.  It hashes info about the number of in
	 * and out edges to this node, but nothing else specific about neighbors.
	 * @param flavor is an extra context specific value to be included in the hash
	 * @return the hash
	 */
	int depthZeroHash(int flavor) {
		int encoding = 1;									// Initialize
		encoding = Pinning.hashTwo(encoding, block.getInSize());
		encoding = Pinning.hashTwo(encoding, block.getOutSize());
		encoding = Pinning.hashTwo(encoding, flavor);
		return encoding;
	}

	/**
	 * Compute and store a new n-gram by combining existing (n-1)-grams from sources. 
	 * @param index is the index of the current, already computed, (n-1)-gram to recurse on
	 */
	void nextNGramSource(int index) {
		int nextSize = 1;
		int masterSourceHash = 0;
		for (CtrlVertex neighbor : sources) {				// Assemble hashes from sources
			CtrlNGram gram = neighbor.ngrams.get(index);
			masterSourceHash += gram.hash;						// Combine neighbors (n-1)-gram
			nextSize += gram.weight;					// Running tally of the number of nodes in the hash
		}

		int nextEntry = ngrams.get(0).hash;
		nextEntry = Pinning.hashTwo(nextEntry, masterSourceHash);
		ngrams.add(new CtrlNGram(this, nextSize, ngrams.get(index).depth + 1, nextEntry));
	}

	/**
	 * Compute and store a new n-gram by combining existing (n-1)-grams from sinks. 
	 * @param index is the index of the current, already computed, (n-1)-gram to recurse on
	 */
	void nextNGramSink(int index) {
		int nextSize = 1;
		int masterSourceHash = 0xfabcd;					// Starting value to distinguish sinks
		for (CtrlVertex neighbor : sinks) {				// Assemble hashes from sources
			CtrlNGram gram = neighbor.ngrams.get(index);
			masterSourceHash += gram.hash;						// Combine neighbors (n-1)-gram
			nextSize += gram.weight;					// Running tally of the number of nodes in the hash
		}

		int nextEntry = ngrams.get(0).hash;
		nextEntry = Pinning.hashTwo(nextEntry, masterSourceHash);
		ngrams.add(new CtrlNGram(this, nextSize, ngrams.get(index).depth + 1, nextEntry));
	}

	/**
	 * Add some additional color to the 0-gram hash for this node.
	 * If the node has exactly 1 incoming edge, hash in the index of that edge,
	 * i.e. the position of that edge within the last of sink edges of the parent vertex.
	 * This distinguishes the node as either the true or false action after a conditional branch, or
	 * by associating the node with a particular case of a switch branch.
	 */
	void addEdgeColor() {
		if (sources.size() == 1) {
			CtrlNGram zeroGram = ngrams.get(0);
			CtrlVertex src = sources.get(0);
			int edgeColor;
			for (edgeColor = 0; edgeColor < src.sinks.size(); ++edgeColor) {
				if (src.sinks.get(edgeColor) == this) {
					break;
				}
			}
			zeroGram.hash = Pinning.hashTwo(zeroGram.hash, edgeColor);
		}
	}

	/**
	 * Remove everything except the 0-gram
	 */
	public void clearNGrams() {
		while (ngrams.size() > 1) {
			ngrams.remove(ngrams.size() - 1);
		}
	}

	/**
	 * Recompute the 0-gram, adding some additional salt to the hash
	 * @param flavor is the salt value to add
	 */
	public void setZeroGram(int flavor) {
		int hash = depthZeroHash(flavor);
		ngrams.get(0).hash = hash;
	}

	@Override
	public String toString() {
		String result = Integer.toString(uid);
		return result;
	}
}
