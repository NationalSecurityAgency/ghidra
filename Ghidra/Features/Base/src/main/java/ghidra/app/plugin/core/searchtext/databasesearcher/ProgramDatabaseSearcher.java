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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import java.util.*;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.searchtext.SearchOptions;
import ghidra.app.plugin.core.searchtext.Searcher;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.UserSearchUtils;
import ghidra.util.task.TaskMonitor;

/**
 * This class combines multiple field searchers to present a simple searcher interface for users of 
 * this class. First, based on the searchOptions, a field searcher is created for each field to be
 * search (comments, mnemonics, operands, etc.)  The searchers are ordered based on which field's matches
 * should be presented before another field's match at the same address.  Backwards searches would
 * have the searchers in the opposite order for forward searches.  This search is an efficient breadth
 * first search by requiring that each searcher only advance one record and only move to the next record
 * when all the other searches have reached records at or beyond the address of this searcher's current
 * record.  The basic algorithm is to ask each searcher if they have a match at the current address.  Since
 * they are asked in the appropriate order, if any of them has a match at the current address, it is
 * immediately returned.  Once all the searchers report not having a match at the current address, the
 * current address is advanced to the next address of the searcher whose current record is closest to
 * the current address (if the searcher's record is the current address, this is when it would fetch
 * its next record).
 * <P>
 * When a searcher's getMatch() method is called, the searcher should return it current match and 
 * advance its internal pointer to any additional matches at the same address or be prepared to 
 * report no match when the hasMatch() method is called again at the same address.  When the 
 * findNextSignificantAddress() method is called, the searcher should report its current record's
 * address if that address is not the current address.  Otherwise, the searcher should advance to
 * its next record and report that address.  When a search has no more records in the search
 * address set, it should return null for the findNextSignificantAddress() method and hasMatch should
 * return false.
 */

public class ProgramDatabaseSearcher implements Searcher {

	private List<ProgramDatabaseFieldSearcher> searchers = new ArrayList<>();
	private Address currentAddress;
	private boolean isForward;
	private SearchOptions searchOptions;

	private long totalSearchCount;
	private AddressSet remainingAddresses;
	private TaskMonitor monitor;

	public ProgramDatabaseSearcher(ServiceProvider serviceProvider, Program program,
			ProgramLocation startLoc, AddressSetView set, SearchOptions options,
			TaskMonitor monitor) {
		this.searchOptions = options;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		this.isForward = options.isForward();
		if (startLoc == null && set == null) {
			startLoc = new ProgramLocation(program,
				isForward ? program.getMinAddress() : program.getMaxAddress());
		}

		initialize(serviceProvider, program, startLoc, set, options);
		currentAddress = findNextSignificantAddress();
		monitor.initialize(totalSearchCount);
	}

	@Override
	public ProgramLocation search() {
		List<ProgramDatabaseFieldSearcher> orderedSearchers = searchers;
		if (!searchOptions.isForward()) {
			orderedSearchers = new ArrayList<>(searchers);
			Collections.reverse(orderedSearchers);
		}

		while (currentAddress != null) {
			monitor.setMessage("Checking address " + currentAddress);
			for (ProgramDatabaseFieldSearcher searcher : orderedSearchers) {
				if (searcher.hasMatch(currentAddress)) {
					return searcher.getMatch();
				}
			}

			Address lastAddress = currentAddress;
			currentAddress = findNextSignificantAddress();
			updateProgress(lastAddress, currentAddress);
		}
		return null;
	}

	private void updateProgress(Address lastAddress, Address newAddress) {
		if (newAddress == null) {
			return; // finished
		}

		if (isForward) {
			remainingAddresses.delete(remainingAddresses.getMinAddress(), lastAddress);
		}
		else {
			remainingAddresses.delete(lastAddress, remainingAddresses.getMaxAddress());
		}

		long progress = totalSearchCount - remainingAddresses.getNumAddresses();
		monitor.setProgress(progress);
	}

	@Override
	public SearchOptions getSearchOptions() {
		return searchOptions;
	}

	@Override
	public void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	private Address findNextSignificantAddress() {
		Address nextAddress = null;
		for (ProgramDatabaseFieldSearcher searcher : searchers) {
			if (monitor.isCancelled()) {
				return null;
			}
			Address nextAddressToCheck = searcher.getNextSignificantAddress(currentAddress);
			nextAddress = isForward ? getMin(nextAddress, nextAddressToCheck)
					: getMax(nextAddress, nextAddressToCheck);
		}

		return nextAddress;
	}

	private Address getMin(Address address1, Address address2) {
		if (address1 == null) {
			return address2;
		}
		if (address2 == null) {
			return address1;
		}
		return address1.compareTo(address2) < 0 ? address1 : address2;

	}

	private Address getMax(Address address1, Address address2) {
		if (address1 == null) {
			return address2;
		}
		if (address2 == null) {
			return address1;
		}
		return address1.compareTo(address2) > 0 ? address1 : address2;
	}

	private void initialize(ServiceProvider serviceProvider, Program program, ProgramLocation start,
			AddressSetView view, SearchOptions options) {
		searchOptions = options;
		boolean forward = options.isForward();

		AddressSetView trimmedSet = adjustSearchSet(program, start, view, forward);
		ProgramLocation adjustedStart = adjustStartLocation(program, start, trimmedSet, forward);
		remainingAddresses = new AddressSet(trimmedSet);
		totalSearchCount = trimmedSet.getNumAddresses();

		Pattern pattern =
			UserSearchUtils.createSearchPattern(options.getText(), options.isCaseSensitive());
		BrowserCodeUnitFormat format = new BrowserCodeUnitFormat(serviceProvider, false);

		if (options.searchComments()) {
			searchers.add(new CommentFieldSearcher(program, adjustedStart, trimmedSet, forward,
				pattern, CodeUnit.PLATE_COMMENT));
		}
		if (options.searchFunctions()) {
			searchers.add(
				new FunctionFieldSearcher(program, adjustedStart, trimmedSet, forward, pattern));
		}
		if (options.searchComments()) {
			searchers.add(new CommentFieldSearcher(program, adjustedStart, trimmedSet, forward,
				pattern, CodeUnit.PRE_COMMENT));
		}
		if (options.searchLabels()) {
			searchers.add(
				new LabelFieldSearcher(program, adjustedStart, trimmedSet, forward, pattern));
		}
		if (options.searchBothDataMnemonicsAndOperands()) {
			searchers.add(
				DataMnemonicOperandFieldSearcher.createDataMnemonicAndOperandFieldSearcher(program,
					adjustedStart, trimmedSet, forward, pattern, format));
		}
		if (options.searchOnlyDataMnemonics()) {
			searchers.add(DataMnemonicOperandFieldSearcher.createDataMnemonicOnlyFieldSearcher(
				program, adjustedStart, trimmedSet, forward, pattern, format));
		}
		if (options.searchOnlyDataOperands()) {
			searchers.add(DataMnemonicOperandFieldSearcher.createDataOperandOnlyFieldSearcher(
				program, adjustedStart, trimmedSet, forward, pattern, format));
		}
		if (options.searchBothInstructionMnemonicAndOperands()) {
			searchers.add(
				InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicAndOperandFieldSearcher(
					program, adjustedStart, trimmedSet, forward, pattern, format));
		}
		if (options.searchOnlyInstructionMnemonics()) {
			searchers.add(
				InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicOnlyFieldSearcher(
					program, adjustedStart, trimmedSet, forward, pattern, format));
		}
		if (options.searchOnlyInstructionOperands()) {
			searchers.add(
				InstructionMnemonicOperandFieldSearcher.createInstructionOperandOnlyFieldSearcher(
					program, adjustedStart, trimmedSet, forward, pattern, format));
		}
		if (options.searchComments()) {
			searchers.add(new CommentFieldSearcher(program, adjustedStart, trimmedSet, forward,
				pattern, CodeUnit.EOL_COMMENT));
			searchers.add(new CommentFieldSearcher(program, adjustedStart, trimmedSet, forward,
				pattern, CodeUnit.REPEATABLE_COMMENT));
			searchers.add(new CommentFieldSearcher(program, adjustedStart, trimmedSet, forward,
				pattern, CodeUnit.POST_COMMENT));
		}
	}

	/**
	 * Adjust the address set depending on the start location and whether searching forward 
	 * or backward. The address set is adjusted by removing addresses that are before the start
	 * locations address when searching forward or after the start address when searching backwards.
	 * @param program the program for the address set
	 * @param startLocation the program location where the search will start.
	 * @param view the address set to be searched.
	 * @param forward true for a forward search and false for backward search.
	 * @return the adjusted address set.
	 */
	private AddressSetView adjustSearchSet(Program program, ProgramLocation startLocation,
			AddressSetView view, boolean forward) {

		if (view == null) {
			view = program.getMemory();
		}

		if (startLocation == null) {
			return view;
		}

		AddressSetView trimmedSet = view;
		Address start = startLocation.getAddress();
		trimmedSet = trimAddressSet(program, trimmedSet, start, forward);
		if (trimmedSet.isEmpty()) {
			return trimmedSet;
		}

		Address maxAddress = trimmedSet.getMaxAddress();
		if (!forward && start.compareTo(maxAddress) > 0) {

			// If the adjustedStart isn't the maxAddress, then adjust this set to the
			// minimum address of the code unit.  Otherwise the FieldSearcher will
			// throw an IllegalArgumentException.
			ProgramLocation adjustedStart = new ProgramLocation(program, maxAddress);
			if (!adjustedStart.getAddress().equals(maxAddress)) {
				trimmedSet =
					trimAddressSet(program, trimmedSet, adjustedStart.getAddress(), forward);
			}
		}
		return trimmedSet;
	}

	private ProgramLocation adjustStartLocation(Program program, ProgramLocation start,
			AddressSetView trimmedSet, boolean forward) {

		ProgramLocation adjustedStart = start;
		if (adjustedStart != null && trimmedSet != null && !trimmedSet.isEmpty()) {
			Address minAddress = trimmedSet.getMinAddress();
			Address maxAddress = trimmedSet.getMaxAddress();
			if (forward && adjustedStart.getAddress().compareTo(minAddress) < 0) {
				return new ProgramLocation(program, minAddress);
			}
			else if (!forward && adjustedStart.getAddress().compareTo(maxAddress) > 0) {
				return new ProgramLocation(program, maxAddress);
			}
		}
		return adjustedStart;
	}

	/**
	 * Trims the given address set to only include addresses from the given address to the end of 
	 * the address set if going forward or from the beginning of the address set to the given address
	 * if going backwards. 
	 * @param view the address set to trim
	 * @param address the trim address
	 * @param searchForward true if trimming from the beginning or false otherwise
	 * @return a new address set with the potentially extraneous addresses removed.
	 */
	private AddressSetView trimAddressSet(Program program, AddressSetView view, Address address,
			boolean searchForward) {

		if (view == null || view.isEmpty()) {
			return view;
		}
		if (searchForward) {
			Address maxAddress = view.getMaxAddress();
			if (address.compareTo(maxAddress) > 0) {
				return new AddressSet();
			}
			return view.intersect(program.getAddressFactory().getAddressSet(address, maxAddress));
		}
		Address minAddress = view.getMinAddress();
		if (address.compareTo(minAddress) < 0) {
			return new AddressSet();
		}
		return view.intersect(program.getAddressFactory().getAddressSet(minAddress, address));
	}

}
