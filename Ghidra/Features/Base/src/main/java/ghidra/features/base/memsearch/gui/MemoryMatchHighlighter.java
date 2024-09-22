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

import java.awt.Color;
import java.util.*;

import org.apache.commons.lang3.ArrayUtils;

import docking.widgets.fieldpanel.support.Highlight;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

/**
 * Listing highlight provider to highlight memory search results.
 */
public class MemoryMatchHighlighter implements ListingHighlightProvider {
	private Navigatable navigatable;
	private Program program;
	private List<MemoryMatch> sortedResults;
	private MemoryMatchTableModel model;
	private MemorySearchOptions options;
	private MemoryMatch selectedMatch;

	public MemoryMatchHighlighter(Navigatable navigatable, MemoryMatchTableModel model,
			MemorySearchOptions options) {
		this.model = model;
		this.options = options;
		this.navigatable = navigatable;
		this.program = navigatable.getProgram();

		model.addThreadedTableModelListener(new ThreadedTableModelListener() {
			@Override
			public void loadingStarted() {
				clearCache();
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				// stub
			}

			@Override
			public void loadPending() {
				clearCache();
			}

		});
	}

	@Override
	public Highlight[] createHighlights(String text, ListingField field, int cursorTextOffset) {
		if (!options.isShowHighlights()) {
			return NO_HIGHLIGHTS;
		}

		if (program != navigatable.getProgram()) {
			return NO_HIGHLIGHTS;
		}

		Class<? extends FieldFactory> fieldFactoryClass = field.getFieldFactory().getClass();
		if (fieldFactoryClass != BytesFieldFactory.class) {
			return NO_HIGHLIGHTS;
		}

		ProxyObj<?> proxy = field.getProxy();
		Object obj = proxy.getObject();
		if (!(obj instanceof CodeUnit cu)) {
			return NO_HIGHLIGHTS;
		}

		Address minAddr = cu.getMinAddress();
		Address maxAddr = cu.getMaxAddress();
		List<MemoryMatch> results = getMatchesInRange(minAddr, maxAddr);
		if (results.isEmpty()) {
			return NO_HIGHLIGHTS;
		}

		return getHighlights(text, minAddr, results);
	}

	private Highlight[] getHighlights(String text, Address minAddr, List<MemoryMatch> results) {

		Highlight[] highlights = new Highlight[results.size()];
		int selectedMatchIndex = -1;

		for (int i = 0; i < highlights.length; i++) {
			MemoryMatch match = results.get(i);
			Color highlightColor = SearchConstants.SEARCH_HIGHLIGHT_COLOR;
			if (match == selectedMatch) {
				selectedMatchIndex = i;
				highlightColor = SearchConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR;
			}
			highlights[i] = createHighlight(match, minAddr, text, highlightColor);
		}

		// move the selected match to the end so that it gets painted last and doesn't get 
		// painted over by the non-active highlights
		if (selectedMatchIndex >= 0) {
			ArrayUtils.swap(highlights, selectedMatchIndex, highlights.length - 1);
		}

		return highlights;
	}

	private Highlight createHighlight(MemoryMatch match, Address start, String text, Color color) {
		int highlightLength = match.getLength();
		Address address = match.getAddress();
		int startByteOffset = (int) address.subtract(start);
		int endByteOffset = startByteOffset + highlightLength - 1;
		startByteOffset = Math.max(startByteOffset, 0);
		return getHighlight(text, startByteOffset, endByteOffset, color);
	}

	private Highlight getHighlight(String text, int start, int end, Color color) {
		int charStart = getCharPosition(text, start);
		int charEnd = getCharPosition(text, end) + 1;
		return new Highlight(charStart, charEnd, color);

	}

	private int getCharPosition(String text, int byteOffset) {
		int byteGroupSize = options.getByteGroupSize();
		int byteDelimiterLength = options.getByteDelimiter().length();

		int groupSize = byteGroupSize * 2 + byteDelimiterLength;
		int groupIndex = byteOffset / byteGroupSize;
		int groupOffset = byteOffset % byteGroupSize;

		int pos = groupIndex * groupSize + 2 * groupOffset;
		return Math.min(text.length() - 1, pos);
	}

	List<MemoryMatch> getMatches() {

		if (sortedResults != null) {
			return sortedResults;
		}

		if (model.isBusy()) {
			return Collections.emptyList();
		}

		List<MemoryMatch> modelData = model.getModelData();
		if (model.isSortedOnAddress()) {
			return modelData;
		}

		sortedResults = new ArrayList<>(modelData);
		Collections.sort(sortedResults);

		return sortedResults;
	}

	private List<MemoryMatch> getMatchesInRange(Address start, Address end) {
		List<MemoryMatch> matches = getMatches();
		int startIndex = findFirstIndex(matches, start, end);
		if (startIndex < 0) {
			return Collections.emptyList();
		}

		int endIndex = findIndexAtOrGreater(matches, end);
		if (endIndex < matches.size() && (matches.get(endIndex).getAddress().equals(end))) {
			endIndex++; // end index is non-inclusive and we want to include direct hit
		}

		List<MemoryMatch> resultList = matches.subList(startIndex, endIndex);
		return resultList;
	}

	private int findFirstIndex(List<MemoryMatch> matches, Address start, Address end) {

		int startIndex = findIndexAtOrGreater(matches, start);
		if (startIndex > 0) { // see if address before extends into this range.
			MemoryMatch resultBefore = matches.get(startIndex - 1);
			Address beforeAddr = resultBefore.getAddress();
			int length = resultBefore.getLength();
			if (start.hasSameAddressSpace(beforeAddr) && start.subtract(beforeAddr) < length) {
				return startIndex - 1;
			}
		}

		if (startIndex == matches.size()) {
			return -1;
		}

		MemoryMatch result = matches.get(startIndex);
		Address addr = result.getAddress();
		if (end.compareTo(addr) >= 0) {
			return startIndex;
		}
		return -1;
	}

	private int findIndexAtOrGreater(List<MemoryMatch> matches, Address address) {

		MemoryMatch key = new MemoryMatch(address);
		int index = Collections.binarySearch(matches, key);
		if (index < 0) {
			index = -index - 1;
		}
		return index;
	}

	private void clearCache() {
		if (sortedResults != null) {
			sortedResults.clear();
			sortedResults = null;
		}
	}

	void dispose() {
		navigatable.removeHighlightProvider(this, program);
		clearCache();
	}

	void setSelectedMatch(MemoryMatch selectedMatch) {
		this.selectedMatch = selectedMatch;
	}

}
