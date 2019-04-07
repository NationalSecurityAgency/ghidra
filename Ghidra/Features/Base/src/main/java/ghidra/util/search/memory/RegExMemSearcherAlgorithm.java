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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.searchmem.RegExSearchData;
import ghidra.app.plugin.core.searchmem.SearchData;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Search memory using the provided regular expression.
 */
public class RegExMemSearcherAlgorithm implements MemorySearchAlgorithm {

	private SearchInfo searchInfo;
	private AddressSetView searchSet;
	private Program program;
	private boolean spanAddressGaps;
	private int alignment;
	private CodeUnitSearchInfo codeUnitSearchInfo;

	public RegExMemSearcherAlgorithm(SearchInfo searchInfo, AddressSetView searchSet,
			Program program, boolean searchAcrossAddressGaps) {

		SearchData data = searchInfo.getSearchData();
		if (!(data instanceof RegExSearchData)) {
			throw new IllegalArgumentException(
				"The given SearchInfo does not contain a RegExSearchData");
		}

		this.searchInfo = searchInfo;
		this.searchSet = searchSet;
		this.program = program;
		this.spanAddressGaps = searchAcrossAddressGaps;
		this.alignment = searchInfo.getAlignment();
		this.codeUnitSearchInfo = searchInfo.getCodeUnitSearchInfo();
	}

	@Override
	public void search(Accumulator<MemSearchResult> accumulator, TaskMonitor monitor) {
		monitor.initialize(searchSet.getNumAddresses());

		if (spanAddressGaps) {
			searchAddressSet(searchSet, accumulator, monitor, 0);
		}
		else {
			AddressRangeIterator rangeIterator = searchSet.getAddressRanges();
			int progress = 0;
			while (rangeIterator.hasNext()) {
				AddressRange range = rangeIterator.next();
				searchAddressSet(new AddressSet(range), accumulator, monitor, progress);
				progress += (int) range.getLength();
				monitor.setProgress(progress);
			}
		}
	}

	private void searchAddressSet(AddressSetView addressSet,
			Accumulator<MemSearchResult> accumulator, TaskMonitor monitor, int progressCount) {

		if (addressSet.getNumAddresses() <= Integer.MAX_VALUE) {
			searchSubAddressSet(addressSet, accumulator, monitor, progressCount);
			return;
		}
		List<AddressSet> sets = breakSetsByMemoryBlock(addressSet);
		for (AddressSet set : sets) {
			searchSubAddressSet(set, accumulator, monitor, progressCount);
		}
	}

	private List<AddressSet> breakSetsByMemoryBlock(AddressSetView addressSet) {
		Memory mem = program.getMemory();
		List<AddressSet> list = new ArrayList<>();
		MemoryBlock[] blocks = mem.getBlocks();
		for (MemoryBlock memoryBlock : blocks) {

			AddressSet set =
				addressSet.intersectRange(memoryBlock.getStart(), memoryBlock.getEnd());
			if (!set.isEmpty()) {
				list.add(set);
			}
		}
		return list;
	}

	private void searchSubAddressSet(AddressSetView addressSet,
			Accumulator<MemSearchResult> accumulator, TaskMonitor monitor, int progressCount) {

		SearchData searchData = searchInfo.getSearchData();
		Pattern pattern = ((RegExSearchData) searchData).getRegExPattern();
		Memory memory = program.getMemory();
		int matchLimit = searchInfo.getMatchLimit();

		try {
			MemoryAddressSetCharSequence charSet =
				new MemoryAddressSetCharSequence(memory, addressSet);
			Matcher matcher = pattern.matcher(charSet);

			int searchFrom = 0;
			while (matcher.find(searchFrom) && !monitor.isCancelled()) {
				int startIndex = matcher.start();
				int length = matcher.end() - startIndex;
				Address address = charSet.getAddressAtIndex(startIndex);
				if (isMatchingAddress(address, length)) {

					MemSearchResult result = new MemSearchResult(address, length);
					accumulator.add(result);
					monitor.setProgress(progressCount + startIndex);

					if (accumulator.size() >= matchLimit) {
						return;
					}
				}

				// move forward by one byte to check for matches within matches
				searchFrom = startIndex + 1;
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			monitor.setMessage("Error: Could not read memory");
		}
	}

	protected boolean isMatchingAddress(Address address, long matchSize) {
		if (address == null) {
			return false;
		}

		if ((address.getOffset() % alignment) != 0) {
			return false;
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

		return false;
	}

}
