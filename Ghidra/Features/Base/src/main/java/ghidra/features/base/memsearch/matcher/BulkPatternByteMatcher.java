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
package ghidra.features.base.memsearch.matcher;

import java.util.ArrayList;
import java.util.List;

import ghidra.util.bytesearch.*;

/**
 * {@link ByteMatcher} that uses a BulkPatternSearcher to simultaneously search for multiple
 * byte patterns.
 *
 * @param <T> the specific pattern type
 */
public class BulkPatternByteMatcher<T extends BytePattern> implements ByteMatcher<T> {

	private BulkPatternSearcher<T> matcher;

	/**
	 * Constructor
	 * @param patterns the list of patterns that this byte matcher will simultaneously search for
	 */
	public BulkPatternByteMatcher(List<T> patterns) {
		matcher = new BulkPatternSearcher<T>(patterns);
	}

	@Override
	public Iterable<Match<T>> match(ExtendedByteSequence bytes) {
		List<Match<T>> matches = new ArrayList<>();
		matcher.search(bytes, matches);
		return matches;
	}

	@Override
	public String getDescription() {
		return "Bulk Pattern Searcher";
	}

}
