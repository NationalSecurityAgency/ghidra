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
package ghidra.machinelearning.functionfinding;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a utility class for generating random subsets of an {@link AddressSetView}.  
 */
public class RandomSubsetUtils {

	private RandomSubsetUtils() {
		//utility class
	}

	/**
	 * This method generates a random subset of size {@code k} of {@code addresses}.
	 * <p>
	 * The parameter {@code k} can be of type {@code long}, but you will probably run out of heap
	 * space for large values.
	 * 
	 * @param addresses addresses
	 * @param k size of random subset to generate
	 * @param monitor monitor
	 * @return random subset of size k
	 * @throws CancelledException if monitor is canceled
	 */
	public static AddressSet randomSubset(AddressSetView addresses, long k, TaskMonitor monitor)
			throws CancelledException {
		List<Long> sortedRandom = generateRandomIntegerSubset(addresses.getNumAddresses(), k);
		Collections.sort(sortedRandom);
		AddressSet randomAddresses = new AddressSet();
		AddressIterator iter = addresses.getAddresses(true);
		int addressesAdded = 0;
		int addressesVisited = 0;
		int listIndex = 0;
		while (iter.hasNext() && addressesAdded < k) {
			monitor.checkCancelled();
			Address addr = iter.next();
			if (sortedRandom.get(listIndex) == addressesVisited) {
				randomAddresses.add(addr);
				addressesAdded += 1;
				listIndex += 1;
			}
			addressesVisited += 1;
		}
		return randomAddresses;
	}

	/**
	 * Generates of random subset of size {@code k} of the set [0,1,...n-1] by generating
	 * a random permutation 
	 * @param n size of set (must be >= 0)
	 * @param k size of random subset (must be >= 0)
	 * @return list of indices of elements in random subset
	 */
	public static List<Long> generateRandomIntegerSubset(long n, long k) {
		if (n < 0) {
			throw new IllegalArgumentException("n cannot be negative");
		}
		if (k < 0) {
			throw new IllegalArgumentException("k cannot be negative");
		}
		if (n < k) {
			throw new IllegalArgumentException(
				"size of subset (" + k + ") cannot be larger than size of set (" + n + ")");
		}
		Map<Long, Long> permutation = new HashMap<>();
		for (long i = 0; i < k; ++i) {
			swap(permutation, i, ThreadLocalRandom.current().nextLong(i, n));
		}
		List<Long> random = new ArrayList<>();
		for (long i = 0; i < k; i++) {
			random.add(permutation.getOrDefault(i, i));
		}
		return random;
	}

	/**
	 * Updates a Map<Long,Long> treated as a permutation p to produce a new permutation p'
	 * such that p'(i) = p(j) and p'(j) = p(i).  For i not in the keySet of the map, it is
	 * assumed that p(i) = i.
	 * @param permutation permutation map
	 * @param i index
	 * @param j index
	 */
	public static void swap(Map<Long, Long> permutation, long i, long j) {
		if (i == j) {
			return;
		}
		long ith = permutation.getOrDefault(i, i);
		long jth = permutation.getOrDefault(j, j);
		permutation.put(i, jth);
		permutation.put(j, ith);
	}

}
