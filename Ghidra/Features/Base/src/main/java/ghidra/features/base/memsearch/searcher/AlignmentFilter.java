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
package ghidra.features.base.memsearch.searcher;

import java.util.function.Predicate;

/**
 * Search filter that can test a search result and determine if that result is at an address
 * whose offset matches the given alignment (i.e. its offset is a multiple of the alignment value)
 */
public class AlignmentFilter implements Predicate<MemoryMatch> {

	private int alignment;

	public AlignmentFilter(int alignment) {
		this.alignment = alignment;
	}

	@Override
	public boolean test(MemoryMatch match) {
		return match.getAddress().getOffset() % alignment == 0;
	}
}
