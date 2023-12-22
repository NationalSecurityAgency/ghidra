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
import java.util.Map.Entry;

import generic.hash.SimpleCRC32;
import generic.stl.Pair;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Pinning {

	private static final int NGRAM_DEPTH = 24;		// The (default) n-gram depth

	private DataGraph graphLeft;					// Data-flow graph of the LEFT side function
	private DataGraph graphRight;					// Data-flow graph of the RIGHT side function
	private CtrlGraph cgraphLeft;					// Control-flow graph of the LEFT side function
	private CtrlGraph cgraphRight;					// Control-flow graph of the RIGHT side function
	private Map<DataVertex, DataVertex> pinMap;		// Map from LEFT side (data-flow) vertices to RIGHT side vertices
	private ArrayList<DataNGram> fragments;			// n-grams of data-flow vertices, in preparation for matching
	private int pass;								// Current pass being evaluated
	private Comparator<DataCtrl> compareHashes;		// Comparator for CtrlNGram sort
	private Comparator<DataCtrl> compareWithinBlock;	// Comparator for sorting within a basic block

	/**
	 * Labels for the two functions being compared by the Pinning algorithm 
	 */
	public static enum Side {
		LEFT(0), RIGHT(1);

		private int value;			// Value for uid encodings

		private Side(int val) {
			value = val;
		}

		/**
		 * @return the integer encoding of the side
		 */
		public int getValue() {
			return value;
		}
	}

	/**
	 * A data-flow vertex linked with an underlying control-flow n-gram.
	 */
	public static class DataCtrl {
		DataVertex dataVertex;			// The data-flow vertex
		CtrlNGram ctrlNGram;			// An n-gram of an underlying control-flow vertex

		public DataCtrl(DataVertex data, CtrlNGram ctrl) {
			dataVertex = data;
			ctrlNGram = ctrl;
		}

		/**
		 * Sort by control-flow n-gram, then by side.
		 * Within this group, sort by block (multiple blocks can have the same hash),
		 * then by PcodeOp order within the block.
		 */
		public static class CompareWithinBlock implements Comparator<DataCtrl> {
			@Override
			public int compare(DataCtrl o0, DataCtrl o1) {
				int hash0 = o0.ctrlNGram.hash;
				int hash1 = o1.ctrlNGram.hash;
				if (hash0 < hash1) {
					return -1;
				}
				if (hash0 > hash1) {
					return 1;
				}
				CtrlVertex o0Block = o0.ctrlNGram.root;
				CtrlVertex o1Block = o1.ctrlNGram.root;
				int res = o0Block.graph.side.compareTo(o1Block.graph.side);
				if (res != 0) {
					return res;
				}
				if (o0Block.uid < o1Block.uid) {
					return -1;
				}
				if (o0Block.uid > o1Block.uid) {
					return 1;
				}
				PcodeOp op0 = o0.dataVertex.isOp() ? o0.dataVertex.op : o0.dataVertex.vn.getDef();
				PcodeOp op1 = o1.dataVertex.isOp() ? o1.dataVertex.op : o1.dataVertex.vn.getDef();
				int order0 = op0.getSeqnum().getOrder();
				int order1 = op1.getSeqnum().getOrder();
				if (order0 < order1) {
					return -1;
				}
				if (order0 > order1) {
					return 1;
				}
				return 0;
			}

		}

		/**
		 * Sort by control-flow hash, then by control-flow uid.
		 * Higher weight, then higher depth, hashes come first.
		 */
		public static class CompareHashes implements Comparator<DataCtrl> {

			@Override
			public int compare(DataCtrl o1, DataCtrl o2) {
				CtrlNGram o1gram = o1.ctrlNGram;
				CtrlNGram o2gram = o2.ctrlNGram;
				if (o1gram.weight != o2gram.weight) {
					return (o1gram.weight < o2gram.weight) ? 1 : -1;	// Bigger weight first
				}
				if (o1gram.depth != o2gram.depth) {
					return (o1gram.depth < o2gram.depth) ? 1 : -1;		// Bigger depth first
				}
				if (o1gram.hash != o2gram.hash) {
					return (o1gram.hash < o2gram.hash) ? -1 : 1;
				}
				int res = o1gram.root.graph.side.compareTo(o2gram.root.graph.side);
				if (res != 0) {
					return res;
				}
				if (o1gram.root.uid != o2gram.root.uid) {
					return (o1gram.root.uid < o2gram.root.uid) ? -1 : 1;
				}
				return 0;
			}

		}
	}

	/**
	 * Construct a pinning between two HighFunction
	 * @param hfuncLeft is the (LEFT side) HighFunction
	 * @param hfuncRight is the (RIGHT side) HighFunction
	 * @param ngramDepth is the number of n-grams to generate per node
	 * @param constCaring is true if the pinning should take into account exact constant values
	 * @param ramCaring is true if the pinning should distinguish between local and global variables
	 * @param castCollapse is true if CAST operations should be ignored in the pinning
	 * @param sizeCollapse is true if variable sizes larger than 4 should be treated as size 4
	 * @param breakSym is true if symmetries should be paired arbitrarily
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException if the user cancels the task
	 */
	public Pinning(HighFunction hfuncLeft, HighFunction hfuncRight, int ngramDepth,
			boolean constCaring, boolean ramCaring, boolean castCollapse, boolean sizeCollapse,
			boolean breakSym, TaskMonitor monitor) throws CancelledException {

		compareHashes = new DataCtrl.CompareHashes();
		compareWithinBlock = new DataCtrl.CompareWithinBlock();
		pinMap = new HashMap<>();

		graphLeft =
			new DataGraph(Side.LEFT, hfuncLeft, constCaring, ramCaring, castCollapse, sizeCollapse);
		graphRight = new DataGraph(Side.RIGHT, hfuncRight, constCaring, ramCaring, castCollapse,
			sizeCollapse);
		// Control-flow graphs are used to break ties when matching data-flow
		cgraphLeft = new CtrlGraph(Side.LEFT, hfuncLeft);
		cgraphRight = new CtrlGraph(Side.RIGHT, hfuncRight);

		// Compute n-gram hashes
		graphLeft.makeNGrams(ngramDepth);
		graphRight.makeNGrams(ngramDepth);
		cgraphLeft.makeNGrams(ngramDepth);
		cgraphRight.makeNGrams(ngramDepth);

		makeFragments();		// Put data-flow hashes in sorted list for matching
		doPinning(ngramDepth, breakSym, monitor);
	}

	/**
	 * Update control-flow n-grams with matching info from previous passes, to help
	 * distinguish between similar nodes.
	 * @param ngramDepth is the maximum depth of n-gram being to generate
	 */
	private void updateCtrlHashes(int ngramDepth) {

		cgraphLeft.clearNGrams();
		cgraphRight.clearNGrams();
		HashSet<CtrlVertex> seen = new HashSet<>();
		// Recalculate (some) control-flow 0-grams, based on matching data-flow in them
		for (DataVertex node : pinMap.keySet()) {
			if (!node.isOp()) {
				continue;
			}
			CtrlVertex cnode = dataToCtrl(node);
			if (!seen.contains(cnode)) {
				CtrlVertex csidekick = dataToCtrl(pinMap.get(node));
				seen.add(cnode);
				int flavor = cnode.uid;			// Flavor to add to the 0-grams
				cnode.setZeroGram(flavor);		// Recompute 0-gram	
				csidekick.setZeroGram(flavor);	// with matching flavor
			}
		}

		cgraphLeft.makeNGrams(ngramDepth);		// Recompute all n-grams, recursively including new 0-grams
		cgraphRight.makeNGrams(ngramDepth);
	}

	/**
	 * Go back through data-flow vertices that were collapsed out of the original graphs.
	 * Each collapsed DataVertex is associated to an uncollapsed vertex. If an uncollapsed vertex
	 * has a match in the other graph also with associated collapsed vertices, we attempt
	 * to pair the two sets of collapsed vertices, just based on PcodeOp opcodes.
	 */
	private void pinAssociates() {
		DataGraph.Associate associate1 = new DataGraph.Associate(null, 0);
		for (Entry<DataGraph.Associate, ArrayList<DataVertex>> entry : graphLeft.associates
				.entrySet()) {
			ArrayList<DataVertex> side0 = entry.getValue();
			associate1.node = pinMap.get(entry.getKey().node);
			if (associate1.node == null) {
				continue;
			}
			associate1.slot = entry.getKey().slot;
			ArrayList<DataVertex> side1 = graphRight.associates.get(associate1);
			if (side1 == null) {
				continue;
			}
			if (side0.size() != side1.size() || side0.size() > 4) {
				continue;
			}
			boolean matching = true;
			for (int i = 0; i < side0.size(); i += 2) {
				DataVertex op0 = side0.get(i);
				DataVertex op1 = side1.get(i);
				if (op0.op.getOpcode() != op1.op.getOpcode()) {
					matching = false;
					break;
				}
			}
			if (matching) {
				for (int i = 0; i < side0.size(); ++i) {
					DataVertex v0 = side0.get(i);
					DataVertex v1 = side1.get(i);
					if (v0.paired || v1.paired) {
						continue;
					}
					establishMatch(v0, v1);
				}
			}
		}
	}

	/**
	 * Creates the sorted list of n-gram hashes used to decide which nodes will get pinned.
	 */
	private void makeFragments() {
		fragments = new ArrayList<>();
		for (int side = 0; side < 2; side++) {						// Collect n-grams from both sides
			DataGraph graph = (side == 0 ? graphLeft : graphRight);
			for (DataVertex node : graph.nodeList) {				// for all data-flow vertices
				for (int d = 0; d < node.ngrams.size(); d++) {		// and for every possible depth
					fragments.add(node.ngrams.get(d));				// into one list
				}
			}
		}

		// Sort the list by weight and hash so that possible matches are adjacent
		Collections.sort(fragments);
	}

	/**
	 * Given a list of more than 2 DataNGrams with matching hash, try to distinguish the underlying
	 * DataVertex objects by comparing CtrlNGrams associated with each DataVertex through its
	 * containing CtrlVertex.  If DataVertex pairs can be distinguished, they are added to pinMap.
	 * @param matchList is the list of matching DataNGrams
	 * @param useOrder is true if block order should be used to break ties
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException if the user cancels the task
	 */
	private void breakTieWithCtrlFlow(ArrayList<DataNGram> matchList, boolean useOrder,
			TaskMonitor monitor) throws CancelledException {
		DataNGram current = matchList.get(0);
		if (current.weight <= 1) {
			return;					// Don't try to break ties on low weight n-grams
		}
		ArrayList<DataCtrl> cfragsList = new ArrayList<>();

		// Create the list of control-flow n-grams, and set up a way to get back to the original DataVertex
		for (int j = 0; j < matchList.size(); j++) {
			monitor.checkCancelled();
			DataVertex tiedVertex = matchList.get(j).root;

			// Mark the vertex as having been analyzed this pass.  This prevents additional
			// rounds of tie breaking on the same set of nodes for lower depth n-grams.  I.e.,
			// if vertices are indistinguishable at this depth, they will continue to be
			// indistinguishable at lower depths.
			tiedVertex.passComplete = pass;

			// The vertex is guaranteed to have at least 1 source, as the weight > 1
			DataVertex opVertex = (current.root.isOp() ? tiedVertex : tiedVertex.sources.get(0));
			CtrlVertex ctiedVertex = dataToCtrl(opVertex);
			for (int d = 0; d < ctiedVertex.ngrams.size(); d++) {
				CtrlNGram nGram = ctiedVertex.ngrams.get(d);
				DataCtrl temp = new DataCtrl(tiedVertex, nGram);		// Tie CtrlNGram to tiedVertex
				cfragsList.add(temp);
			}
		}

		cfragsList.sort(compareHashes);		// Sort list so that identical n-grams are adjacent
		int j = 0;
		while (j < cfragsList.size()) {
			if (monitor.isCancelled()) {
				return;
			}
			DataCtrl ccurrent = cfragsList.get(j);
			if (ccurrent.dataVertex.paired) {		// If we've already paired DataVertex
				j++;
				continue;							// Don't look at it again
			}

			int jbar = j + 1;
			while (jbar < cfragsList.size()) {	// Iterate to the first n-gram whose hash doesn't match
				DataCtrl cfuture = cfragsList.get(jbar);
				if (!ccurrent.ctrlNGram.equalHash(cfuture.ctrlNGram)) {
					break;
				}
				jbar++;
			}

			if (jbar - j == 2) {					// Exactly 2 matching n-gram hashes. Possible pair.
				DataCtrl cnext = cfragsList.get(j + 1);
				if (ccurrent.ctrlNGram.graphsDiffer(cnext.ctrlNGram)) {
					DataVertex temp0 = ccurrent.dataVertex;
					DataVertex temp1 = cnext.dataVertex;
					ngramPinner(temp0, temp1, current.depth);
				}
			}
			else if (useOrder && jbar - j > 2) {
				breakTieUsingOrder(cfragsList, j, jbar, current);
			}
			j = jbar;

		}
	}

	/**
	 * Test if a range of vertices that have a matching data n-gram and a matching control-flow n-gram
	 * occur within a single pair of basic blocks.  There must be an equal number of vertices
	 * in one basic block on the LEFT and in one on the RIGHT.   Additionally, the vertices must
	 * either have no output edges or be MULTIEQUAL op nodes.
	 * @param frags is the list of vertices associated with control-flow n-grams
	 * @param start is the start of the matching range
	 * @param stop is the end of the matching range
	 * @return true if the vertices occur within a single pair of basic blocks and can be paired
	 */
	private static boolean isBlockPair(ArrayList<DataCtrl> frags, int start, int stop) {
		int leftCount = 0;
		int rightCount = 0;
		int leftUid = -1;
		int rightUid = -1;
		for (int i = start; i < stop; ++i) {
			DataCtrl frag = frags.get(i);
			DataVertex vert = frag.dataVertex;
			if (!vert.sinks.isEmpty() &&
				(!vert.isOp() || vert.op.getOpcode() != PcodeOp.MULTIEQUAL)) {
				// Nodes must be terminal roots of data-flow or MULTIEQUAL ops
				return false;
			}
			CtrlVertex cvert = frag.ctrlNGram.root;
			if (cvert.graph.side == Side.LEFT) {
				leftCount += 1;
				if (leftCount == 1) {
					leftUid = cvert.uid;
				}
				else if (leftUid != cvert.uid) {
					return false;		// More than one block on LEFT side
				}
			}
			else {
				rightCount += 1;
				if (rightCount == 1) {
					rightUid = cvert.uid;
				}
				else if (rightUid != cvert.uid) {
					return false;		// More than one block on RIGHT side
				}
			}
		}
		return (leftCount == rightCount);
	}

	/**
	 * Given a range of vertices with identical data n-grams and associated control-flow n-grams,
	 * test if they all occur in 1 basic block (pair).  If they can, match the vertices
	 * in the order they occur within the basic block.  The new paired vertices are added to the pinMap.
	 * @param frags is the list of vertices with associated control-flow n-grams
	 * @param start is the start of the matching range
	 * @param stop is the end of the matching range
	 * @param firstNGram is the matching data n-gram
	 */
	private void breakTieUsingOrder(ArrayList<DataCtrl> frags, int start, int stop,
			DataNGram firstNGram) {

		if (isBlockPair(frags, start, stop)) {
			List<DataCtrl> subList = frags.subList(start, stop);
			subList.sort(compareWithinBlock);
			int size = (stop - start) / 2;
			for (int i = 0; i < size; ++i) {
				ngramPinner(subList.get(i).dataVertex, subList.get(i + size).dataVertex,
					firstNGram.depth);
			}
		}
	}

	/**
	 * Starting at the given index in fragment, the main n-gram list, collect all n-grams
	 * with the same hash.  The matching n-grams are passed back in matchList.
	 * Any n-gram whose weight is less than the minWeight threshold is skipped, as
	 * is any n-gram whose underlying DataVertex is already paired or ruled out.
	 * @param i is the given starting index
	 * @param matchList will contain exactly the list of matching n-grams being passed back
	 * @param minWeight is the minimum weight threshold for n-grams
	 * @return the index advanced to the next unexamined slot
	 */
	private int collectEqualHash(int i, ArrayList<DataNGram> matchList, int minWeight) {
		DataNGram first = null;
		matchList.clear();
		for (;;) {
			if (i >= fragments.size()) {
				return i;
			}
			first = fragments.get(i);
			i += 1;
			if (first.weight < minWeight) {
				if (!first.root.isOp() || first.root.op.getOpcode() != PcodeOp.CALL) {
					continue;
				}
			}
			if (!first.root.paired && first.root.passComplete < pass) {
				break;
			}
		}
		matchList.add(first);
		for (;;) {
			if (i >= fragments.size()) {
				return i;
			}
			DataNGram gram = fragments.get(i);
			if (!first.equalHash(gram)) {
				break;
			}
			i += 1;
			if (!gram.root.paired && gram.root.passComplete < pass) {
				matchList.add(gram);
			}
		}
		return i;
	}

	/**
	 * Pair the two given data-flow vertices.
	 * @param left is the LEFT side vertex
	 * @param right is the RIGHT side vertex
	 */
	private void establishMatch(DataVertex left, DataVertex right) {
		pinMap.put(left, right);
		left.paired = true;
		right.paired = true;
	}

	/**
	 * Do one pass of the pinning algorithm.  The n-gram list is run through once.  For each set of
	 * n-grams with matching hashes, if there are exactly 2, the associated data-flow vertices are paired. 
	 * If there are more then 2,  we attempt to "break the tie" by associating control-flow n-grams to
	 * the subset of data-flow vertices and pairing these.
	 * @param minWeight is the weight threshold for considering an n-gram in the list for matching
	 * @param useOrder is true if block and operand order should be used to break ties
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException if the user cancels the task
	 */
	private void pinMain(int minWeight, boolean useOrder, TaskMonitor monitor)
			throws CancelledException {
		int i = 0;										// The main index into fragments, the n-gram list
		monitor.setMessage("Pinning all...");
		monitor.setIndeterminate(false);
		monitor.initialize(fragments.size());
		ArrayList<DataNGram> matchList = new ArrayList<>();
		while (i < fragments.size()) {
			if (i % 1000 == 0) {
				monitor.setProgress(i);
			}
			i = collectEqualHash(i, matchList, minWeight);

			if (matchList.size() == 2) {					// Exactly 2 matching n-grams. Possible pair.
				DataNGram gram0 = matchList.get(0);
				DataNGram gram1 = matchList.get(1);
				if (gram0.graphsDiffer(gram1)) {			// Check that one n-gram comes from each side
					DataVertex left = gram0.root.graph.side == Side.LEFT ? gram0.root : gram1.root;
					DataVertex right =
						gram0.root.graph.side == Side.RIGHT ? gram0.root : gram1.root;
					ngramPinner(left, right, gram0.depth);	// Pin the match and everything above it
				}
			}
			else if (matchList.size() > 2) {				// More then 2 matching n-grams
				breakTieWithCtrlFlow(matchList, useOrder, monitor);
				if (useOrder) {
					matchViaOperator(matchList);
				}
			}
		}
	}

	/**
	 * Run the full pinning algorithm.  Continue doing passes over the n-gram list until no
	 * further pairs are found.
	 * @param nGramDepth is the maximum depth of n-gram to use
	 * @param breakSym is true if a symmetry breaking pass should be performed at the end
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException if the user cancels the task
	 */
	private void doPinning(int nGramDepth, boolean breakSym, TaskMonitor monitor)
			throws CancelledException {
		pass = 0;
		pinMain(2, false, monitor);				// First pass, using weight threshold of 2
		cgraphLeft.addEdgeColor();				// Try to distinguish control-flow nodes further
		cgraphRight.addEdgeColor();
		boolean checkForTies = true;
		while (checkForTies) {				// Continue until no further pairs are found
			pass += 1;
			int lastPinSize = pinMap.size();
			updateCtrlHashes(nGramDepth);
			pinMain(0, false, monitor);
			checkForTies = (lastPinSize != pinMap.size());
		}
		if (breakSym) {
			checkForTies = true;
			while (checkForTies) {
				pass += 1;
				int lastPinSize = pinMap.size();
				pinMain(0, true, monitor);		// Use block and operand order to break ties
				checkForTies = (lastPinSize != pinMap.size());
			}
		}
		pinAssociates();					// Try to pair nodes in the original graph that were collapsed out
	}

	/**
	 * Pin the given pair of data-flow vertices, then recursively try to pin vertices
	 * by following the immediate incoming data-flow edge.  The pair is made for a specific n-gram
	 * depth.  Recursive pairing stops at any point where n-grams don't match up to this depth.
	 * Edges into commutative PcodeOp nodes are also disambiguated with n-gram hashes up to this depth.
	 * @param left is the LEFT side data-flow vertex to pair
	 * @param right is the RIGHT side data-flow vertex to pair
	 * @param depth is the specific n-gram depth for the pair
	 */
	private void ngramPinner(DataVertex left, DataVertex right, int depth) {

		if (depth < 0 || left == null || left.paired || right.paired) {
			return;
		}

		establishMatch(left, right);		// Formally pair the vertices

		boolean goForIt;

		if (left.isCommutative()) {		// Nodes whose incoming edges must be disambiguated
			if (left.op.getOpcode() != PcodeOp.MULTIEQUAL) {
				DataVertex left0 = left.sources.get(0);
				DataVertex left1 = left.sources.get(1);
				DataVertex right0 = right.sources.get(0);
				DataVertex right1 = right.sources.get(1);
				int lasty = left.ngrams.size() - 1;

				if (left0.ngrams.get(lasty).hash == left1.ngrams.get(lasty).hash ||
					right0.ngrams.get(lasty).hash == right1.ngrams.get(lasty).hash) {
					return;
				}

			}
			for (DataVertex srcLeft : left.sources) {		// For each incoming edge of the LEFT side vertex
				if (srcLeft.paired) {
					continue;
				}
				for (DataVertex srcRight : right.sources) {	// Search for a matching edge on RIGHT side
					if (srcRight.paired) {
						continue;
					}
					goForIt = true;
					for (int i = 0; i < Math.max(1, depth); i++) {	// n-grams must match up to given depth
						if (srcLeft.ngrams.get(i).hash != srcRight.ngrams.get(i).hash) {
							goForIt = false;
							break;
						}
					}
					if (goForIt) {			// If all hashes match for the two edges, pair them
						// Try to extend depth of matching hashes before pairing the edges
						int newDepth = Math.max(depth - 1, 0);
						while (-1 < newDepth && newDepth < srcLeft.ngrams.size() && srcLeft.ngrams
								.get(newDepth).hash == srcRight.ngrams.get(newDepth).hash) {
							newDepth++;
						}
						ngramPinner(srcLeft, srcRight, newDepth - 1);	// Recursively match these edges
						break;
					}
				}
			}
		}
		else {					// Edges are paired in order
			if (left.sources.size() == right.sources.size()) {
				for (int n = 0; n < left.sources.size(); n++) {

					DataVertex srcLeft = left.sources.get(n);
					DataVertex srcRight = right.sources.get(n);
					goForIt = true;
					for (int i = 0; i < Math.max(1, depth); i++) {	// n-grams must match up to given depth
						if (srcLeft.ngrams.get(i).hash != srcRight.ngrams.get(i).hash) {
							goForIt = false;
							break;
						}
					}
					if (goForIt) {			// If all hashes match for the two edges, pair them
						// Try to extend depth of matching hashes before pairing edges
						int i = Math.max(depth - 1, 0);
						while (-1 < i && i < srcLeft.ngrams.size() &&
							srcLeft.ngrams.get(i).hash == srcRight.ngrams.get(i).hash) {
							i++;
						}
						ngramPinner(srcLeft, srcRight, i - 1);			// Recursively match these edges
					}
				}
			}
		}
	}

	/**
	 * Given a data-flow representing a PcodeOp, return the control-flow vertex containing the PcodeOp.
	 * @param node is the data-flow vertex
	 * @return the containing control-flow vertex
	 */
	private CtrlVertex dataToCtrl(DataVertex node) {
		PcodeBlockBasic parent = node.op.getParent();
		CtrlGraph whichGraph = (node.graph == graphLeft ? cgraphLeft : cgraphRight);
		return whichGraph.blockToVertex.get(parent);
	}

	/**
	 * Find the RIGHT side Varnode matching the given LEFT side Varnode.
	 * The LEFT and RIGHT sides are determined by the order HighFunctions are given to the constructor.
	 * @param vnLeft is the given Varnode from LEFT side
	 * @return the matching Varnode from RIGHT side or null
	 */
	public VarnodeAST findMatch(Varnode vnLeft) {
		DataVertex vertLeft = graphLeft.vnToVert.get(vnLeft);
		if (vertLeft == null) {
			return null;
		}
		DataVertex vertRight = pinMap.get(vertLeft);
		if (vertRight != null) {
			return vertRight.vn;
		}
		return null;
	}

	/**
	 * Find the RIGHT side PcodeOp matching the given LEFT side PcodeOp.
	 * The LEFT and RIGHT sides are determined by the order HighFunctions are given to the constructor.
	 * @param opLeft is the given PcodeOp from LEFT side
	 * @return the matching PcodeOp from RIGHT side or null
	 */
	public PcodeOpAST findMatch(PcodeOp opLeft) {
		DataVertex vertLeft = graphLeft.opToVert.get(opLeft);
		if (vertLeft == null) {
			return null;
		}
		DataVertex vertRight = pinMap.get(vertLeft);
		if (vertRight != null) {
			return vertRight.op;
		}
		return null;
	}

	/**
	 * Determine if a token should be be filtered from match display.
	 * Some tokens like "," and " " may be attached to matchable operations but can
	 * clutter the display if they are highlighted for a match.
	 * @param token is the specific token to check
	 * @return true if the token should not be highlighted as part of a match
	 */
	private boolean filterToken(ClangToken token) {
		String text = token.getText();
		if (text.length() == 0) {
			return true;
		}
		if (text.length() == 1) {
			char c = text.charAt(0);
			if (c == ' ' || c == ',') {
				return true;
			}
		}

		if (token instanceof ClangTypeToken) {
			return true;
		}
		return false;
	}

	/**
	 * Build a TokenBin for every DataVertex on both sides. Pair a TokenBin with its match,
	 * if its underlying DataVertex is paired.
	 * @param leftTokenGp are the tokens for LEFT side
	 * @param rightTokenGp are the tokens for RIGHT side
	 * @return a single list of LEFT side TokenBins then RIGHT side TokenBins
	 */
	public ArrayList<TokenBin> buildTokenMap(ClangTokenGroup leftTokenGp,
			ClangTokenGroup rightTokenGp) {

		HashMap<Pair<DataVertex, DataVertex>, TokenBin> lvertToBin = new HashMap<>();
		HashMap<Pair<DataVertex, DataVertex>, TokenBin> rvertToBin = new HashMap<>();

		for (int side = 0; side < 2; side++) {
			// side == 0: set up the left side
			// side == 1: set up the right side
			ClangTokenGroup tokGp = (side == 0 ? leftTokenGp : rightTokenGp);
			DataGraph graph = (side == 0 ? graphLeft : graphRight);
			HashMap<Pair<DataVertex, DataVertex>, TokenBin> vertToBin =
				(side == 0 ? lvertToBin : rvertToBin);

			ArrayList<ClangNode> nodes = new ArrayList<>();
			tokGp.flatten(nodes);
			for (ClangNode node : nodes) {
				if (node instanceof ClangToken tok) {
					if (filterToken(tok)) {
						continue;
					}
					VarnodeAST vn = (VarnodeAST) DecompilerUtils.getVarnodeRef(tok);
					PcodeOpAST op = (PcodeOpAST) tok.getPcodeOp();

					DataVertex opNode = graph.opToVert.get(op);
					DataVertex vnNode = graph.vnToVert.get(vn);
					Pair<DataVertex, DataVertex> nodePair = new Pair<>(opNode, vnNode);

					if (!vertToBin.containsKey(nodePair)) {
						vertToBin.put(nodePair, new TokenBin(graph.getHighFunction()));
					}
					vertToBin.get(nodePair).add(tok);
				}
			}
		}

		// Match a TokenBin if its underlying DataVertex is paired
		ArrayList<TokenBin> highBins = new ArrayList<>();
		for (Pair<DataVertex, DataVertex> lNodePair : lvertToBin.keySet()) {
			TokenBin lbin = lvertToBin.get(lNodePair);
			DataVertex lkey = lNodePair.first;
			DataVertex lval = lNodePair.second;
			DataVertex rkey = null;
			DataVertex rval = null;
			if (lkey != null && lkey.paired) {
				rkey = pinMap.get(lkey);
			}
			if (lval != null && lval.paired) {
				rval = pinMap.get(lval);
			}

			if (((lkey == null) != (rkey == null)) || ((lval == null) != (rval == null))) {
				continue;
			}
			if ((rkey == null && rval == null) || (lkey == null && lval == null)) {
				continue;
			}

			Pair<DataVertex, DataVertex> rNodePair = new Pair<>(rkey, rval);
			if (rvertToBin.containsKey(rNodePair)) {
				TokenBin rbin = rvertToBin.get(rNodePair);
				lbin.sidekick = rbin;
				rbin.sidekick = lbin;
			}
		}

		// Put everything into the final list
		lvertToBin.remove(new Pair<DataVertex, DataVertex>(null, null));
		rvertToBin.remove(new Pair<DataVertex, DataVertex>(null, null));
		highBins.addAll(lvertToBin.values());
		highBins.addAll(rvertToBin.values());

		return highBins;
	}

	/**
	 * Dump a string representation of pinning data structures (for debugging).
	 * @param writer is the stream to write the string to.
	 * @throws IOException for problems writing to the stream
	 */
	public void dump(Writer writer) throws IOException {
		graphLeft.dump(writer);
		graphRight.dump(writer);
//		for (DataNGram vertex : fragments) {
//			writer.append(vertex.toString());
//			writer.append("\n");
//		}
		for (DataVertex vertex : graphLeft.nodeList) {
			DataVertex match = pinMap.get(vertex);
			if (match != null) {
				writer.append("match ");
				writer.append(Integer.toString(vertex.uid));
				writer.append(" to ");
				writer.append(Integer.toString(match.uid));
				writer.append("\n");
			}
		}
	}

	/**
	 * Match data-flow between two HighFunctions. The matching algorithm is performed immediately.
	 * The resulting Pinning object can be queried for matches via
	 *   - findMatch(Varnode) or
	 *   - findMatch(PcodeOp)
	 * 
	 * ClangToken matches can be calculated by calling buildTokenMap().
	 * @param hfuncLeft is the LEFT side function
	 * @param hfuncRight is the RIGHT side function
	 * @param matchConstantsExactly is true if (small) constant values should be forced to match
	 * @param sizeCollapse is true if variable sizes larger than 4 should be treated as size 4
	 * @param breakSym is true if code symmetries should be ordered arbitrarily so they can be paired
	 * @param monitor is the TaskMonitor
	 * @return the populated Pinning object
	 * @throws CancelledException if the user cancels the task
	 */
	public static Pinning makePinning(HighFunction hfuncLeft, HighFunction hfuncRight,
			boolean matchConstantsExactly, boolean sizeCollapse, boolean breakSym,
			TaskMonitor monitor) throws CancelledException {

		boolean matchRamSpace = true;
		boolean castCollapse = true;
		// Make the pinning, the map from the data graph of hfuncLeft to that of hfuncRight.
		Pinning pin = new Pinning(hfuncLeft, hfuncRight, NGRAM_DEPTH, matchConstantsExactly,
			matchRamSpace, castCollapse, sizeCollapse, breakSym, monitor);

		return pin;
	}

	/**
	 * Try to pair vertices that are inputs to the same commutative operator.
	 * Reaching here, the vertices could not be distinguished by any other method, so
	 * we order the vertices based on their input slot to the operator.
	 * @param ngrams is the set of matching n-grams
	 */
	private void matchViaOperator(ArrayList<DataNGram> ngrams) {
		DataNGram firstNGram = ngrams.get(0);
		for (DataNGram ngram : ngrams) {
			DataVertex vertLeft = ngram.root;
			if (vertLeft.graph.side != Side.LEFT) {
				continue;
			}
			for (int j = 0; j < vertLeft.sinks.size(); ++j) {
				DataVertex opVertLeft = vertLeft.sinks.get(j);
				if (!opVertLeft.isOp() || !opVertLeft.isCommutative() || !opVertLeft.paired) {
					continue;
				}
				DataVertex opVertRight = pinMap.get(opVertLeft);
				if (opVertLeft.sources.size() != opVertRight.sources.size()) {
					continue;
				}
				for (int i = 0; i < opVertLeft.sources.size(); ++i) {
					DataVertex tVertLeft = opVertLeft.sources.get(i);
					DataVertex tVertRight = opVertRight.sources.get(i);
					if (tVertLeft.paired || tVertRight.paired) {
						continue;
					}
					int index = tVertLeft.ngrams.size() - 1;
					if (!tVertLeft.ngrams.get(index).equalHash(firstNGram)) {
						continue;
					}
					if (!tVertRight.ngrams.get(index).equalHash(firstNGram)) {
						continue;
					}
					ngramPinner(tVertLeft, tVertRight, firstNGram.depth);
				}
			}
		}
	}

	/**
	 * The function we use to hash two integers into one. Used in multiple places in the pinning algorithm.
	 * @param first is the first integer to hash
	 * @param second is the second integer
	 * @return the hash of the two integers
	 */
	static int hashTwo(int first, int second) {
		int result = 0;
		for (int i = 0; i < 4; i++) {
			result = SimpleCRC32.hashOneByte(result, first >> i * 8);
		}
		for (int i = 0; i < 4; i++) {
			result = SimpleCRC32.hashOneByte(result, second >> i * 8);
		}
		return result;
	}
}
