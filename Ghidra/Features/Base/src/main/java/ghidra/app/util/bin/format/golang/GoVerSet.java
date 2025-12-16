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
package ghidra.app.util.bin.format.golang;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a set of version numbers.
 * 
 * @param ranges list of ranges that define the set
 */
public record GoVerSet(List<GoVerRange> ranges) {
	public static final GoVerSet ALL = new GoVerSet(List.of(GoVerRange.ALL));

	/**
	 * Parses a version list string (eg. "all", or "1.0-1.5,1.8-1.9,1.11-") and returns 
	 * a {@link GoVerSet} containing the found versions.
	 * 
	 * @param s string to parse
	 * @return {@link GoVerSet} containing the found versions
	 * @throws IOException if the string had invalid start or end wildcard ranges
	 */
	public static GoVerSet parse(String s) throws IOException {
		if (s.trim().equalsIgnoreCase("all")) {
			return ALL;
		}

		List<GoVerRange> result = new ArrayList<>();
		for (String verStr : s.split(",")) {
			verStr = verStr.trim();
			if (verStr.isEmpty()) {
				continue;
			}
			GoVerRange range = GoVerRange.parse(verStr);
			if (range.isEmpty()) {
				continue;
			}
			if (range.start().isWildcard() && !result.isEmpty()) {
				throw new IOException("Invalid start wildcard position: [%s]".formatted(s));
			}
			GoVerRange prev = !result.isEmpty() ? result.get(result.size() - 1) : null;
			if (prev != null && prev.end().isWildcard()) {
				throw new IOException("Invalid end wildcard position: [%s]".formatted(s));
			}
			result.add(range);
		}
		return new GoVerSet(List.copyOf(result)); // immutable list
	}

	/**
	 * Returns true if the set contains no versions
	 * 
	 * @return boolean true if empty
	 */
	public boolean isEmpty() {
		return ranges.isEmpty();
	}

	/**
	 * Returns true if the specified version is present in the set.
	 * 
	 * @param ver {@link GoVer} to search for
	 * @return boolean true if version is present
	 */
	public boolean contains(GoVer ver) {
		for (GoVerRange range : ranges) {
			if (range.contains(ver)) {
				return true;
			}
		}
		return false;
	}
}
