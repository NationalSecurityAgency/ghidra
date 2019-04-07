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
package ghidra.app.plugin.core.searchmem;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramSelection;
import ghidra.util.search.memory.CodeUnitSearchInfo;
import ghidra.util.search.memory.SearchInfo;

class SearchAllSearchInfo extends SearchInfo {

	public SearchAllSearchInfo(SearchData searchData, int matchLimit, boolean searchSelection,
			boolean forwardSearch, int alignment, boolean includeNonLoadedBlocks,
			CodeUnitSearchInfo codeUnitSearchInfo) {
		super(searchData, matchLimit, searchSelection, forwardSearch, alignment,
			includeNonLoadedBlocks, codeUnitSearchInfo, null /* search all uses a different listener mechanism */);
	}

	@Override
	protected AddressSetView getSearchableAddressSet(Program program, Address address,
			ProgramSelection selection) {

		// in the search all case, we don't care about the starting address.

		Memory memory = program.getMemory();
		AddressSetView set =
			this.includeNonLoadedBlocks ? memory.getAllInitializedAddressSet()
					: memory.getLoadedAndInitializedAddressSet();
		if (searchSelection && selection != null && !selection.isEmpty()) {
			set = set.intersect(selection);
		}
		return set;
	}

	@Override
	public boolean isSearchAll() {
		return true;
	}
}
