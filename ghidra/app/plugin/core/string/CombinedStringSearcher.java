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
package ghidra.app.plugin.core.string;

import static ghidra.program.util.string.FoundString.DefinedState.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.util.string.*;
import ghidra.program.util.string.FoundString.DefinedState;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CombinedStringSearcher {

	private DefinedStringIterator definedStringIterator;
	private FoundString nextDefinedString;
	private Program program;
	private StringTableOptions options;
	private Accumulator<FoundString> accumulator;

	public CombinedStringSearcher(Program program, StringTableOptions options,
			Accumulator<FoundString> accumulator) {

		this.program = program;
		this.options = options;
		this.accumulator = accumulator;
		definedStringIterator =
			new DefinedStringIterator(program, options.getWordModelInitialized());
	}

	private FoundString findNextDefinedString() {
		if (definedStringIterator.hasNext()) {
			return definedStringIterator.next();
		}
		return null;
	}

	private void add(FoundString string) {
		if (passesLengthFilter(string)) {
			accumulator.add(string);
		}
	}

	private boolean passesLengthFilter(FoundString foundString) {
		String string = StringUtils.defaultString(foundString.getString(program.getMemory()));
		return string.length() >= options.getMinStringSize();
	}
	
	/**
	 * Searches the current program for strings based on the user-defined settings in
	 * {@link StringTableOptions}.
	 * 
	 * @param monitor the task monitor
	 * @throws CancelledException 
	 */
	public void search(TaskMonitor monitor) throws CancelledException {
					
		AbstractStringSearcher searcher = createSearcher();
		
		// Save off the set of addresses to search. This will be modified during the
		// search operation depending on whether loaded or unloaded blocks are to be 
		// searched.	
		AddressSetView updatedAddressSet = options.getAddressSet();
		
		updateNextString();
		
		if (options.includeUndefinedStrings() || options.includePartiallyDefinedStrings() ||
			options.includeConflictingStrings()) {
			updatedAddressSet = searcher.search(options.getAddressSet(), new AccumulatorAdapter(), options.useLoadedBlocksOnly(), monitor);
		}

		if (!options.includeDefinedStrings()) {
			return;
		}

		// Add defined strings to the accumulator that haven't been found by the StringSearcher
		monitor.setIndeterminate(true);
		while (nextDefinedString != null) {
			monitor.checkCanceled();
			if (!inRange(updatedAddressSet, nextDefinedString)) {
				updateNextString();
				continue;
			}

			if (!onlyShowWordStrings() ||
				((FoundStringWithWordStatus) nextDefinedString).isHighConfidenceWord()) {
				add(nextDefinedString);
			}

			updateNextString();
		}
	}
	
	private void updateNextString() {
		nextDefinedString = findNextDefinedString();
	}

	private AbstractStringSearcher createSearcher() {

		if (options.isPascalRequired()) {
			return new PascalStringSearcher(program, options.getMinStringSize(),
				options.getAlignment(), false);
		}

		return new StringSearcher(program, options.getMinStringSize(), options.getAlignment(),
			options.getIncludeAllCharSizes(), options.isNullTerminationRequired());
	}

	private boolean inRange(AddressSetView addrSet, FoundString string) {
		if (addrSet == null) {
			// this is all of memory
			return true;
		}

		return addrSet.contains(nextDefinedString.getAddress());
	}

	/** returns 0 if the strings (they represent address ranges) have any overlap */
	private int compareRange(FoundString string1, FoundString string2) {
		if (string1 == null) {  // for this purpose, null are larger than non nulls
			return 1;
		}
		else if (string2 == null) {
			return -1;
		}

		Address end1 = string1.getEndAddress();
		Address start2 = string2.getAddress();
		if (end1.compareTo(start2) < 0) {
			return -1;
		}

		Address start1 = string1.getAddress();
		Address end2 = string2.getEndAddress();
		if (end2.compareTo(start1) < 0) {
			return 1;
		}

		return 0;
	}

	public boolean shouldAddDefinedString(FoundString string) {
		if (!options.includeDefinedStrings()) {
			return false;
		}
		AddressSetView addrSet = options.getAddressSet();
		return addrSet == null || addrSet.contains(string.getAddress());
	}

	public boolean onlyShowWordStrings() {
		// Return true if selected in dialog AND word model has been successfully initialized
		// in ValidStringIdentifier
		return options.onlyShowWordStrings() ? options.getWordModelInitialized() : false;
	}

	/**
	 * Uses the StringsAnalyzer model to determine if the current FoundString is a high confidence word.
	 * 
	 * @param foundString
	 */
	private void setIsWordStatus(FoundStringWithWordStatus foundString) {
		StringAndScores candidateString =
			new StringAndScores(foundString.getString(program.getMemory()),
				NGramUtils.isLowerCaseModel());

		// Don't bother continuing if string length is shorter than model's absolute min length
		if (candidateString.getScoredStringLength() >= NGramUtils.getMinimumStringLength()) {
			NGramUtils.scoreString(candidateString);
			foundString.setIsHighConfidenceWord(candidateString.isScoreAboveThreshold());
		}
	}

	private class AccumulatorAdapter implements FoundStringCallback {

		@Override
		public void stringFound(FoundString foundString) {

			gatherStringsUpTo(foundString);

			// does the string overlap another?
			int result = compareRange(foundString, nextDefinedString);
			if (result == 0) {
				DefinedState state =
					isFoundStringCovered(nextDefinedString, foundString) ? DEFINED
							: PARTIALLY_DEFINED;
				foundString.setDefinedState(state);
				updateNextString();
			}
			else {
				// found string does not overlap any existing string, see if it conflicts with 
				// anything else at its start address
				CodeUnit cu = program.getListing().getCodeUnitAt(foundString.getAddress());
				if (!isUndefined(cu)) {
					foundString.setDefinedState(CONFLICTS);
				}
			}

			if (!shouldAddFoundString(foundString.getDefinedState())) {
				return;
			}

			FoundStringWithWordStatus wordString = new FoundStringWithWordStatus(foundString);
			setIsWordStatus(wordString);

			if (wordString.isHighConfidenceWord()) {
				add(wordString);
			}
			else if (!onlyShowWordStrings()) {
				add(wordString);
			}
		}

		private void gatherStringsUpTo(FoundString foundString) {
			int result = compareRange(foundString, nextDefinedString);
			while (result > 0) { // given string is higher in memory than the current string
				if (shouldAddDefinedString(nextDefinedString)) {
					if (!onlyShowWordStrings() ||
						((FoundStringWithWordStatus) nextDefinedString).isHighConfidenceWord()) {
						add(nextDefinedString);
					}
				}

				updateNextString();
				result = compareRange(foundString, nextDefinedString);
			}
		}

		private boolean shouldAddFoundString(DefinedState definedState) {
			switch (definedState) {
				case DEFINED:
					return options.includeDefinedStrings();
				case NOT_DEFINED:
					return options.includeUndefinedStrings();
				case CONFLICTS:
					return options.includeConflictingStrings();
				case PARTIALLY_DEFINED:
					return options.includePartiallyDefinedStrings();
			}
			return true;
		}

		private boolean isUndefined(CodeUnit cu) {
			if (cu == null) {
				return false;
			}
			if (cu instanceof Instruction) {
				return false;
			}
			Data data = (Data) cu;
			return Undefined.isUndefined(data.getDataType());
		}

		private boolean isFoundStringCovered(FoundString definedString, FoundString newString) {
			if (!definedString.getAddress().equals(newString.getAddress())) {
				return false;
			}
			if (definedString.getLength() == newString.getLength()) {
				return true;
			}
			// if the difference between string is only null termination, ignore the difference.
			String stringFromExisting = definedString.getString(program.getMemory());
			String stringFromNew = newString.getString(program.getMemory());
			return stringFromExisting != null && stringFromNew != null &&
				stringFromExisting.length() == stringFromNew.length();
		}

	}

}
