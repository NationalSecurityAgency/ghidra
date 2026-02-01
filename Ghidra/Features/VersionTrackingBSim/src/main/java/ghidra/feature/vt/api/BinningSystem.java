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
package ghidra.feature.vt.api;

import java.util.*;

import generic.lsh.*;
import generic.lsh.vector.HashEntry;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Container for FunctionNodes so that nodes that are "near" each other
 * (meaning the nodes' feature vectors have high cosine-similarity)
 * can be discovered.  As nodes are added, they are distributed across
 * bins, where similar nodes tend to be placed into the same bins.
 */
class BinningSystem {
	private final int L;			// Number of distinct binnings

	private int[][] partitionIdentities;
	private TreeMap<Integer, TreeSet<FunctionNode>>[] binSys;

	/**
	 * Construct a container that holds the FunctionNodes.  If model is not null, then the FunctionNodes will be indexed
	 * @param model is the particular configuration model to use for this
	 */
	@SuppressWarnings("unchecked")
	public BinningSystem(LSHMemoryModel model) {
		int k = model.getK();											// k = #of hyperplanes comprising the each binning.
		L = KandL.memoryModelToL(model);
		this.partitionIdentities = new int[L][];
		this.binSys = new TreeMap[L];									// A system of L binnings.
		Random random = new Random(23);
		for (int ii = 0; ii < L; ++ii) {
			this.partitionIdentities[ii] = new int[k];
			for (int jj = 0; jj < k; ++jj) {
				this.partitionIdentities[ii][jj] = random.nextInt();
			}
			this.binSys[ii] = new TreeMap<Integer, TreeSet<FunctionNode>>();
		}
	}

	/**
	 * Add a list of {@link FunctionNode} objects into the bins
	 * @param iter is an iterator over the raw FunctionNodes to add
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException for user cancellation of the correlator
	 */
	public void add(Iterator<FunctionNode> iter, TaskMonitor monitor) throws CancelledException {

		while (iter.hasNext()) {
			FunctionNode node = iter.next();
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (node.getVector() == null) {
				continue;
			}
			int[] features = getBinIds(node);
			for (int ii = 0; ii < features.length; ++ii) {
				TreeSet<FunctionNode> list = binSys[ii].get(features[ii]);
				if (list == null) {
					list = new TreeSet<FunctionNode>();
					binSys[ii].put(features[ii], list);
				}
				list.add(node);
			}
		}
	}

	/**
	 * Returns the union of all the bins containing the exemplar FunctionNode.
	 * These nodes are likely to similar to the exemplar, but need secondary testing.
	 * @param node is the exemplar
	 * @return a set of FunctionNodes
	 */
	public Set<FunctionNode> lookup(FunctionNode node) {
		TreeSet<FunctionNode> result = new TreeSet<FunctionNode>();
		int[] features = getBinIds(node);
		for (int ii = 0; ii < features.length; ++ii) {
			TreeSet<FunctionNode> list = binSys[ii].get(features[ii]);
			if (list != null) {
				result.addAll(list);
			}
		}
		return result;
	}

	/**
	 * Given a node, calculate the binId for each binning in this system
	 * @param node is the FunctionNode to label
	 * @return an array of ids
	 */
	private int[] getBinIds(FunctionNode node) {
		if (node.getVector() == null) {
			return null;
		}
		int[] result = new int[L];
		HashEntry[] entries = node.getVector().getEntries();
		for (int ii = 0; ii < L; ++ii) {
			int hash = Partition.hash(partitionIdentities[ii], entries);
			result[ii] = hash;
		}
		return result;
	}
}
