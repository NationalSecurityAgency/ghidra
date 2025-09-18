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

import ghidra.pcodeCPort.utils.MutableLong;
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
	public static AddressSet randomSubset(AddressSetView addresses, long k,
			TaskMonitor monitor) throws CancelledException {
		long[] sortedRandom = generateRandomIntegerSubset(addresses.getNumAddresses(), k);
		Arrays.sort(sortedRandom);
		AddressSet randomAddresses = new AddressSet();

		long addressesVisited = 0;
		int listIndex = 0;
		for (AddressRange range : addresses) {
			long rangeEnd = addressesVisited + range.getLength();
			for (; listIndex < k; listIndex++) {
				monitor.checkCancelled();
				long next = sortedRandom[listIndex];
				if (next >= rangeEnd) {
					// Next address is outside of this range
					break;
				}
				Address addr = range.getMinAddress().add(next - addressesVisited);
				randomAddresses.add(addr);
			}
			if (listIndex == k) {
				break;
			}
			addressesVisited += range.getLength();
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
	public static long[] generateRandomIntegerSubset(long n, long k) {
		if (n < 0) {
			throw new IllegalArgumentException("n cannot be negative");
		}
		if (k < 0) {
			throw new IllegalArgumentException("k cannot be negative");
		}
		if (k > Integer.MAX_VALUE) {
			// Could probably just switch k to an int. Since we were using ArrayList before
			// that was already going to blow up if k > Integer.MAX_VALUE
			throw new IllegalArgumentException("k cannot exceed bounds of integer");
		}
		if (n < k) {
			throw new IllegalArgumentException(
				"size of subset (" + k + ") cannot be larger than size of set (" + n + ")");
		}

		Map<Long, MutableLong> permutation = new HashMap<>();

		for (long i = 0; i < k; i++) {
			swap(permutation, i, ThreadLocalRandom.current().nextLong(i, n));
		}

		long[] random = new long[(int) k];

		for (int i = 0; i < k; i++) {
			random[i] =
				permutation.computeIfAbsent(Long.valueOf(i), key -> new MutableLong(key)).get();
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
	public static void swap(Map<Long, MutableLong> permutation, long i, long j) {
		if (i == j) {
			return;
		}
		MutableLong ith = permutation.computeIfAbsent(i, key -> new MutableLong(key));
		MutableLong jth = permutation.computeIfAbsent(j, key -> new MutableLong(key));
		long temp = ith.get();
		ith.set(jth.get());
		jth.set(temp);
	}

}
