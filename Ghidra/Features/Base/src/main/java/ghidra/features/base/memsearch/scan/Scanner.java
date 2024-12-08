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
package ghidra.features.base.memsearch.scan;

import java.util.function.Predicate;

import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;

/**
 * Scan algorithms that examine the byte values of existing search results and look for changes.
 * The specific scanner algorithm determines which results to keep and which to discard.
 */
public enum Scanner {
	// keep unchanged results
	EQUALS("Equals", mm -> compareBytes(mm) == 0, "Keep results whose values didn't change"),
	// keep changed results
	NOT_EQUALS("Not Equals", mm -> compareBytes(mm) != 0, "Keep results whose values changed"),
	// keep results whose values increased
	INCREASED("Increased", mm -> compareBytes(mm) > 0, "Keep results whose values increased"),
	// keep results whose values decreased
	DECREASED("Decreased", mm -> compareBytes(mm) < 0, "Keep results whose values decreased");

	private final String name;
	private final Predicate<MemoryMatch> acceptCondition;
	private final String description;

	private Scanner(String name, Predicate<MemoryMatch> condition, String description) {
		this.name = name;
		this.acceptCondition = condition;
		this.description = description;
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public boolean accept(MemoryMatch match) {
		return acceptCondition.test(match);
	}

	private static int compareBytes(MemoryMatch match) {
		byte[] bytes = match.getBytes();
		byte[] originalBytes = match.getPreviousBytes();

		ByteMatcher matcher = match.getByteMatcher();
		SearchSettings settings = matcher.getSettings();
		SearchFormat searchFormat = settings.getSearchFormat();
		return searchFormat.compareValues(bytes, originalBytes, settings);
	}

}
