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
package ghidra.feature.vt.api.correlator.program;

import java.util.*;

import generic.DominantPair;
import generic.lsh.Partition;
import generic.lsh.vector.HashEntry;
import generic.lsh.vector.LSHCosineVectorAccum;
import ghidra.util.task.TaskMonitor;

class LSHMultiHash<P> {
	private final int L;

	private int[][] partitionIdentities;
	private HashMap<Integer, HashSet<DominantPair<P, LSHCosineVectorAccum>>>[] maps;

	@SuppressWarnings("unchecked")
	LSHMultiHash(final int k, final int L) {
		this.partitionIdentities = new int[L][];
		this.maps = new HashMap[L];
		Random random = new Random(23);
		for (int ii = 0; ii < L; ++ii) {
			this.partitionIdentities[ii] = new int[k];
			for (int jj = 0; jj < k; ++jj) {
				this.partitionIdentities[ii][jj] = random.nextInt();
			}
			this.maps[ii] = new HashMap<>();
		}
		this.L = L;
	}

	synchronized void add(DominantPair<P, LSHCosineVectorAccum> entry) {
		int[] hashes = hashes(entry.second);
		for (int ii = 0; ii < hashes.length; ++ii) {
			HashSet<DominantPair<P, LSHCosineVectorAccum>> list = maps[ii].get(hashes[ii]);
			if (list == null) {
				list = new HashSet<>();
				maps[ii].put(hashes[ii], list);
			}
			list.add(entry);
		}
	}

	public synchronized void add(List<DominantPair<P, LSHCosineVectorAccum>> coll,
			TaskMonitor monitor) {
		monitor.setIndeterminate(false);
		monitor.initialize(coll.size());

		for (DominantPair<P, LSHCosineVectorAccum> entry : coll) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);
			if (entry.second == null) {
				continue;
			}
			int[] hashes = hashes(entry.second);
			for (int ii = 0; ii < hashes.length; ++ii) {
				HashSet<DominantPair<P, LSHCosineVectorAccum>> list = maps[ii].get(hashes[ii]);
				if (list == null) {
					list = new HashSet<>();
					maps[ii].put(hashes[ii], list);
				}
				list.add(entry);
			}
		}
	}

	public synchronized void add(Map<P, LSHCosineVectorAccum> map, TaskMonitor monitor) {
		monitor.setIndeterminate(false);
		monitor.initialize(map.size());

		for (Map.Entry<P, LSHCosineVectorAccum> entry : map.entrySet()) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);
			if (entry.getValue() == null) {
				continue;
			}
			int[] hashes = hashes(entry.getValue());
			for (int ii = 0; ii < hashes.length; ++ii) {
				HashSet<DominantPair<P, LSHCosineVectorAccum>> list = maps[ii].get(hashes[ii]);
				if (list == null) {
					list = new HashSet<>();
					maps[ii].put(hashes[ii], list);
				}
				list.add(
					new DominantPair<>(entry.getKey(), entry.getValue()));
			}
		}
	}

	Set<DominantPair<P, LSHCosineVectorAccum>> lookup(LSHCosineVectorAccum vector) {
		HashSet<DominantPair<P, LSHCosineVectorAccum>> result =
			new HashSet<>();
		int[] hashes = hashes(vector);
		for (int ii = 0; ii < hashes.length; ++ii) {
			HashSet<DominantPair<P, LSHCosineVectorAccum>> list = maps[ii].get(hashes[ii]);
			if (list != null) {
				result.addAll(list);
			}
		}
		return result;
	}

	private int[] hashes(LSHCosineVectorAccum vector) {
		vector.doFinalize();
		int[] result = new int[L];
		HashEntry[] values = vector.getEntries();
		for (int ii = 0; ii < L; ++ii) {
			int hash = Partition.hash(partitionIdentities[ii], values);
			result[ii] = hash;
		}
		return result;
	}
}
