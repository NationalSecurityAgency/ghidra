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
package ghidra.features.base.memsearch.combiner;

import java.util.*;
import java.util.function.BiFunction;

import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.program.model.address.Address;

/**
 * An enum of search results "combiners". Each combiner determines how to combine two sets of
 * memory search results. The current or existing results is represented as the "A" set and the
 * new search is represented as the "B" set.
 */
public enum Combiner {
	REPLACE("New", Combiner::replace),
	UNION("Add To", Combiner::union),
	INTERSECT("Intersect", Combiner::intersect),
	XOR("Xor", Combiner::xor),
	A_MINUS_B("A-B", Combiner::subtract),
	B_MINUS_A("B-A", Combiner::reverseSubtract);

	private String name;
	private BiFunction<List<MemoryMatch>, List<MemoryMatch>, Collection<MemoryMatch>> function;

	private Combiner(String name,
			BiFunction<List<MemoryMatch>, List<MemoryMatch>, Collection<MemoryMatch>> function) {
		this.name = name;
		this.function = function;
	}

	public String getName() {
		return name;
	}

	public Collection<MemoryMatch> combine(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		return function.apply(matches1, matches2);
	}

	private static Collection<MemoryMatch> replace(List<MemoryMatch> matches1,
			List<MemoryMatch> matches2) {

		return matches2;
	}

	private static Collection<MemoryMatch> union(List<MemoryMatch> matches1,
			List<MemoryMatch> matches2) {

		Map<Address, MemoryMatch> matches1Map = createMap(matches1);
		for (MemoryMatch match2 : matches2) {
			Address address = match2.getAddress();
			MemoryMatch match1 = matches1Map.get(address);
			if (match1 == null || match2.getLength() > match1.getLength()) {
				matches1Map.put(address, match2);
			}
		}
		return matches1Map.values();
	}

	private static Collection<MemoryMatch> intersect(List<MemoryMatch> matches1,
			List<MemoryMatch> matches2) {

		List<MemoryMatch> intersection = new ArrayList<>();
		Map<Address, MemoryMatch> matches1Map = createMap(matches1);

		for (MemoryMatch match2 : matches2) {
			Address address = match2.getAddress();
			MemoryMatch match1 = matches1Map.get(address);
			if (match1 != null) {
				MemoryMatch best = match2.getLength() > match1.getLength() ? match2 : match1;
				intersection.add(best);
			}
		}
		return intersection;
	}

	private static List<MemoryMatch> xor(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		List<MemoryMatch> results = new ArrayList<>();
		results.addAll(subtract(matches1, matches2));
		results.addAll(subtract(matches2, matches1));
		return results;
	}

	private static Collection<MemoryMatch> subtract(List<MemoryMatch> matches1,
			List<MemoryMatch> matches2) {

		Map<Address, MemoryMatch> matches1Map = createMap(matches1);

		for (MemoryMatch match2 : matches2) {
			Address address = match2.getAddress();
			matches1Map.remove(address);
		}
		return matches1Map.values();
	}

	private static Collection<MemoryMatch> reverseSubtract(List<MemoryMatch> matches1,
			List<MemoryMatch> matches2) {
		return subtract(matches2, matches1);
	}

	private static Map<Address, MemoryMatch> createMap(List<MemoryMatch> matches) {
		Map<Address, MemoryMatch> map = new HashMap<>();
		for (MemoryMatch result : matches) {
			map.put(result.getAddress(), result);
		}
		return map;
	}

}
