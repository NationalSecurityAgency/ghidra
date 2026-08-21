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

import ghidra.features.base.memsearch.matcher.SearchData;
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
	private BiFunction<List<MemoryMatch<SearchData>>, List<MemoryMatch<SearchData>>, Collection<MemoryMatch<SearchData>>> function;

	private Combiner(String name,
			BiFunction<List<MemoryMatch<SearchData>>, List<MemoryMatch<SearchData>>, Collection<MemoryMatch<SearchData>>> function) {
		this.name = name;
		this.function = function;
	}

	public boolean isMerge() {
		return this != REPLACE;
	}

	public String getName() {
		return name;
	}

	public Collection<MemoryMatch<SearchData>> combine(List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {
		return function.apply(matches1, matches2);
	}

	private static Collection<MemoryMatch<SearchData>> replace(
			List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {

		return matches2;
	}

	private static Collection<MemoryMatch<SearchData>> union(List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {

		Map<Address, MemoryMatch<SearchData>> matches1Map = createMap(matches1);
		for (MemoryMatch<SearchData> match2 : matches2) {
			Address address = match2.getAddress();
			MemoryMatch<SearchData> match1 = matches1Map.get(address);
			if (match1 == null || match2.getLength() > match1.getLength()) {
				matches1Map.put(address, match2);
			}
		}
		return matches1Map.values();
	}

	private static Collection<MemoryMatch<SearchData>> intersect(
			List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {

		List<MemoryMatch<SearchData>> intersection = new ArrayList<>();
		Map<Address, MemoryMatch<SearchData>> matches1Map = createMap(matches1);

		for (MemoryMatch<SearchData> match2 : matches2) {
			Address address = match2.getAddress();
			MemoryMatch<SearchData> match1 = matches1Map.get(address);
			if (match1 != null) {
				MemoryMatch<SearchData> best =
					match2.getLength() > match1.getLength() ? match2 : match1;
				intersection.add(best);
			}
		}
		return intersection;
	}

	private static List<MemoryMatch<SearchData>> xor(List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {
		List<MemoryMatch<SearchData>> results = new ArrayList<>();
		results.addAll(subtract(matches1, matches2));
		results.addAll(subtract(matches2, matches1));
		return results;
	}

	private static Collection<MemoryMatch<SearchData>> subtract(
			List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {

		Map<Address, MemoryMatch<SearchData>> matches1Map = createMap(matches1);

		for (MemoryMatch<SearchData> match2 : matches2) {
			Address address = match2.getAddress();
			matches1Map.remove(address);
		}
		return matches1Map.values();
	}

	private static Collection<MemoryMatch<SearchData>> reverseSubtract(
			List<MemoryMatch<SearchData>> matches1,
			List<MemoryMatch<SearchData>> matches2) {
		return subtract(matches2, matches1);
	}

	private static Map<Address, MemoryMatch<SearchData>> createMap(
			List<MemoryMatch<SearchData>> matches) {
		Map<Address, MemoryMatch<SearchData>> map = new HashMap<>();
		for (MemoryMatch<SearchData> result : matches) {
			map.put(result.getAddress(), result);
		}
		return map;
	}

}
