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
package ghidra.features.base.memsearch.gui;

import java.util.*;

import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.matcher.ByteMatcher;

/**
 * Class for managing memory search history. It maintains a list of previously used ByteMatchers to
 * do memory searching. Each ByteMatcher records the input search text and the search settings used
 * to create it.
 */
public class SearchHistory {
	private List<ByteMatcher> history = new LinkedList<>();
	private int maxHistory;

	public SearchHistory(int maxHistory) {
		this.maxHistory = maxHistory;
	}

	public SearchHistory(SearchHistory other) {
		this.history = new LinkedList<>(other.history);
		this.maxHistory = other.maxHistory;
	}

	public void addSearch(ByteMatcher matcher) {
		removeSimilarMatchers(matcher);
		history.addFirst(matcher);
		truncateHistoryAsNeeded();
	}

	private void removeSimilarMatchers(ByteMatcher matcher) {
		Iterator<ByteMatcher> it = history.iterator();
		String newInput = matcher.getInput();
		SearchFormat newFormat = matcher.getSettings().getSearchFormat();
		while (it.hasNext()) {
			ByteMatcher historyMatch = it.next();
			SearchFormat historyFormat = historyMatch.getSettings().getSearchFormat();
			String historyInput = historyMatch.getInput();
			if (historyFormat.equals(newFormat) && historyInput.equals(newInput)) {
				it.remove();
			}
		}
	}

	private void truncateHistoryAsNeeded() {
		int historySize = history.size();

		if (historySize > maxHistory) {
			int numToRemove = historySize - maxHistory;

			for (int i = 0; i < numToRemove; i++) {
				history.remove(history.size() - 1);
			}
		}
	}

	public ByteMatcher[] getHistoryAsArray() {
		ByteMatcher[] historyArray = new ByteMatcher[history.size()];
		history.toArray(historyArray);
		return historyArray;
	}

}
