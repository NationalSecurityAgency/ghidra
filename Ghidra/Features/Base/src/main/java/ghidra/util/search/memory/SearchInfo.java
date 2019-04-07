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
package ghidra.util.search.memory;

import ghidra.app.plugin.core.searchmem.RegExSearchData;
import ghidra.app.plugin.core.searchmem.SearchData;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskListener;

public class SearchInfo {
	private final SearchData searchData;
	private final int matchLimit;
	private final boolean forwardSearch;
	protected final boolean searchSelection;
	private final int alignment;
	private final CodeUnitSearchInfo codeUnitSearchInfo;
	private final TaskListener listener;
	protected final boolean includeNonLoadedBlocks;

	public SearchInfo(SearchData searchData, int matchLimit, boolean searchSelection,
			boolean forwardSearch, int alignment, boolean includeNonLoadedBlocks,
			TaskListener listener) {
		this(searchData, matchLimit, searchSelection, forwardSearch, alignment,
			includeNonLoadedBlocks, new CodeUnitSearchInfo(true, true, true), listener);
	}

	public SearchInfo(SearchData searchData, int matchLimit, boolean searchSelection,
			boolean forwardSearch, int alignment, boolean includeNonLoadedBlocks,
			CodeUnitSearchInfo codeUnitSearchInfo, TaskListener listener) {
		this.searchData = searchData;
		this.matchLimit = matchLimit;
		this.searchSelection = searchSelection;
		this.forwardSearch = forwardSearch;
		this.alignment = alignment;
		this.listener = listener;
		this.codeUnitSearchInfo = codeUnitSearchInfo;
		this.includeNonLoadedBlocks = includeNonLoadedBlocks;
	}

	/**
	 * Generate an address set which only includes initialized memory
	 * 
	 * @param program the program
	 * @param startAddress starting point for search or null to start from the top of memory
	 * @param selection addresses to be searched or null to search all memory
	 * @return searchable address set
	 */
	protected AddressSetView getSearchableAddressSet(Program program, Address startAddress,
			ProgramSelection selection) {

		if (startAddress == null) {
			return new AddressSet();		// special case if we are at the first address going backwards
			// or the last address going forwards
		}

		Memory memory = program.getMemory();
		AddressSetView set = includeNonLoadedBlocks ? memory.getAllInitializedAddressSet()
				: memory.getLoadedAndInitializedAddressSet();
		if (searchSelection && selection != null && !selection.isEmpty()) {
			set = set.intersect(selection);
		}
		Address start = forwardSearch ? startAddress : memory.getMinAddress();
		Address end = forwardSearch ? memory.getMaxAddress() : startAddress;
		if (start.compareTo(end) > 0) {
			return new AddressSet();
		}
		AddressSet addressSet = program.getAddressFactory().getAddressSet(start, end);
		return set.intersect(addressSet);
	}

	public MemorySearchAlgorithm createSearchAlgorithm(Program p, Address start,
			ProgramSelection selection) {

		AddressSetView asView = getSearchableAddressSet(p, start, selection);

		// note: this should probably be true--is there a reason not to do this?
		//       -also, shouldn't the non-regex searcher cross 'gaps' as well?
		boolean searchAcrossGaps = false;

		if (searchData instanceof RegExSearchData) {
			return new RegExMemSearcherAlgorithm(this, asView, p, searchAcrossGaps);
		}
		return new MemSearcherAlgorithm(this, asView, p);
	}

	public boolean isSearchForward() {
		return forwardSearch;
	}

	public boolean isSearchAll() {
		return false;
	}

	public int getAlignment() {
		return alignment;
	}

	public int getMatchLimit() {
		return matchLimit;
	}

	public TaskListener getListener() {
		return listener;
	}

	public SearchData getSearchData() {
		return searchData;
	}

	public CodeUnitSearchInfo getCodeUnitSearchInfo() {
		return codeUnitSearchInfo;
	}

	public int getSearchLimit() {
		return matchLimit;
	}
}
