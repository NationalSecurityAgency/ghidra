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

import ghidra.app.plugin.core.searchmem.SearchData;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Search memory using the provided search text.
 */
public class MemSearcherAlgorithm implements MemorySearchAlgorithm {

	private boolean forwardSearch;
	private SearchData searchData;
	private AddressSetView searchSet;
	private int matchLimit;
	private Program program;
	private int alignment;
	private CodeUnitSearchInfo codeUnitSearchInfo;

	MemSearcherAlgorithm(SearchInfo searchInfo, AddressSetView searchSet, Program program) {

		this.searchData = searchInfo.getSearchData();
		this.forwardSearch = searchInfo.isSearchForward();
		this.alignment = searchInfo.getAlignment();
		this.searchSet = searchSet;
		this.matchLimit = searchInfo.getMatchLimit();
		this.program = program;
		this.codeUnitSearchInfo = searchInfo.getCodeUnitSearchInfo();
	}

	@Override
	public void search(Accumulator<MemSearchResult> accumulator, TaskMonitor monitor) {
		AddressRangeIterator addressRanges = searchSet.getAddressRanges(forwardSearch);
		monitor.initialize(searchSet.getNumAddresses());
		int progressCount = 0;

		while (addressRanges.hasNext() && !monitor.isCancelled()) {
			AddressRange range = addressRanges.next();
			searchRange(accumulator, range, monitor, progressCount);
			progressCount += range.getLength();
			monitor.setProgress(progressCount);
			if (accumulator.size() >= matchLimit) {
				return;
			}
		}
	}

	private void searchRange(Accumulator<MemSearchResult> accumulator, AddressRange range,
			TaskMonitor monitor, int progressCount) {

		Memory mem = program.getMemory();
		Address startAddress = forwardSearch ? range.getMinAddress() : range.getMaxAddress();
		Address endAddress = forwardSearch ? range.getMaxAddress() : range.getMinAddress();
		int length = searchData.getBytes().length;
		while (startAddress != null && !monitor.isCancelled()) {
			Address matchAddress = mem.findBytes(startAddress, endAddress, searchData.getBytes(),
				searchData.getMask(), forwardSearch, monitor);
			if (isMatchingAddress(matchAddress)) {
				MemSearchResult result = new MemSearchResult(matchAddress, length);
				accumulator.add(result);
				if (accumulator.size() >= matchLimit) {
					return;
				}
				monitor.setProgress(progressCount + getRangeDifference(range, matchAddress));
			}
			startAddress = getNextAddress(matchAddress, range);
		}
	}

	private boolean isMatchingAddress(Address address) {
		if (address == null) {
			return false;
		}

		if ((address.getOffset() % alignment) != 0) {
			return false; // wrong alignment
		}

		if (codeUnitSearchInfo.searchAll()) {
			return true;
		}

		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(address);
		if (codeUnit instanceof Instruction) {
			return codeUnitSearchInfo.isSearchInstructions();
		}
		else if (codeUnit instanceof Data) {
			Data data = (Data) codeUnit;
			if (data.isDefined()) {
				return codeUnitSearchInfo.isSearchDefinedData();
			}
			return codeUnitSearchInfo.isSearchUndefinedData();
		}

		return true;
	}

	private int getRangeDifference(AddressRange range, Address address) {
		return (int) (forwardSearch ? address.subtract(range.getMinAddress())
				: range.getMaxAddress().subtract(address));
	}

	private Address getNextAddress(Address currentAddress, AddressRange range) {
		if (currentAddress == null) {
			return null;
		}

		if (forwardSearch) {
			return currentAddress.equals(range.getMaxAddress()) ? null : currentAddress.next();
		}
		return currentAddress.equals(range.getMinAddress()) ? null : currentAddress.previous();
	}

	AddressSetView getSearchSet() {
		return searchSet;
	}
}
