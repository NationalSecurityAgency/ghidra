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
package ghidra.app.plugin.core.searchtext;

import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.plugin.core.searchtext.iterators.*;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.framework.model.DomainObjectException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.UserSearchUtils;
import ghidra.util.task.TaskMonitor;

/**
 * This class attempts to search for text as it is rendered on the screen.  This in in 
 * contrast to the Program Database Searcher which searches the database.  This is 
 * needed because some information on the screen is rendered "on the fly" and not 
 * stored in the database.  This searcher is much slower, but delivers 
 * results that are in-line with what the user sees.
 * <p>
 * The search is performed in two steps.  First it uses Instruction and Data iterators to 
 * find possible addresses where where information would be rendered.  Then for each of those
 * addresses, it uses the code browsers rendering engine to produce a textual representation
 * for that address.  The textual representation also maintains information about the field
 * that generated it so that the search can be constrained to specific fields such as the
 * label or comment field. 
 * 
 */
class ListingDisplaySearcher implements Searcher {

	private PluginTool tool;
	private Program program;
	private ListingModel listingModel;

	private boolean isInitialized;
	private SearchOptions options;
	private AddressSetView searchAddresses;
	private TaskMonitor monitor;

	private List<ProgramLocation> locationList;
	private ListIterator<ProgramLocation> locationIterator;

	private ProgramLocation startLocation;
	private int startIndex;
	private Address startAddress;
	private Address currentAddress;
	private CodeUnit currentCodeUnit;
	private Layout currentLayout;

	private int currentFieldIndex;
	private MultiAddressIterator addressIterator;

	private Pattern searchPattern;

	/**
	 * Constructor
	 * @param codeViewerService service to get the Layouts
	 * @param program current program
	 * @param startLocation location from where to begin searching
	 * @param set address set; may be null
	 * @param options search options
	 * @param monitor progress monitor
	 */
	ListingDisplaySearcher(PluginTool tool, Program program, ProgramLocation startLocation,
			AddressSetView set, SearchOptions options, TaskMonitor monitor) {
		this.tool = tool;
		this.program = program;
		this.startLocation = startLocation;
		this.searchAddresses = set;
		this.options = options;
		this.monitor = monitor;

		initializeStartAddress(set);
		initializeAddressSet();

		addressIterator = new MultiAddressIterator(getSearchIterators(), options.isForward());
		searchPattern =
			UserSearchUtils.createSearchPattern(options.getText(), options.isCaseSensitive());

		locationList = new ArrayList<>();
		locationIterator = locationList.listIterator();

		CodeViewerService service = tool.getService(CodeViewerService.class);
		listingModel = service.getListingModel();

		monitor.initialize(searchAddresses.getNumAddresses());
	}

	private void initializeStartAddress(AddressSetView set) {
		if (startLocation != null) {
			startAddress = startLocation.getAddress();
		}
		else if (set != null) {
			startAddress = options.isForward() ? set.getMinAddress() : set.getMaxAddress();
		}
		else {
			startAddress = options.isForward() ? program.getMinAddress() : program.getMaxAddress();
		}
	}

	private void initializeAddressSet() {
		if (searchAddresses == null) {
			searchAddresses = program.getMemory();
		}
		CodeUnit cu = program.getListing().getCodeUnitContaining(startAddress);
		Address start = options.isForward() ? cu.getMinAddress() : searchAddresses.getMinAddress();
		Address end = options.isForward() ? searchAddresses.getMaxAddress() : cu.getMaxAddress();
		if (start.compareTo(end) <= 0) {
			AddressSet restrictedSet = new AddressSet(program, start, end);
			searchAddresses = searchAddresses.intersect(restrictedSet);
		}
		else {
			searchAddresses = new AddressSet();
		}
	}

	private AddressIterator[] getSearchIterators() {
		//
		// This code used to get specific iterators for labels, comments, etc, depending
		// on what options were selected (which is the fastest way to search).  However, 
		// this approach missed auto comments and structure comments.
		//
		// The idea now is to get iterators that will return addresses for every defined
		// code unit, which works because all on-screen, non-database items are associated
		// with a defined code unit.   See the history for the original code.  See the
		// header for more info.
		//
		List<AddressIterator> iterators = new ArrayList<>();

		Listing listing = program.getListing();

		InstructionIterator instructions =
			listing.getInstructions(searchAddresses, options.isForward());
		iterators.add(new InstructionSearchAddressIterator(instructions));

		DataIterator data = listing.getDefinedData(searchAddresses, options.isForward());
		iterators.add(new DataSearchAddressIterator(data, options.isForward()));

		boolean all = options.searchAllFields();

		if (options.searchComments() || all) {
			iterators.add(listing.getCommentAddressIterator(searchAddresses, options.isForward()));
		}
		if (options.searchLabels() || all) {
			SymbolIterator labels = program.getSymbolTable().getPrimarySymbolIterator(
				searchAddresses, options.isForward());
			iterators.add(new LabelSearchAddressIterator(labels));
		}
		return iterators.toArray(new AddressIterator[iterators.size()]);
	}

	/**
	 * Get the next location.
	 */
	ProgramLocation next() {
		if (locationList.size() == 0) {
			findNext();
		}

		boolean isForward = options.isForward();
		if (isForward && locationIterator.hasNext()) {
			ProgramLocation loc = locationIterator.next();
			if (!locationIterator.hasNext()) {
				locationList.clear();
				locationIterator = locationList.listIterator();
			}
			return loc;
		}

		if (!isForward && locationIterator.hasPrevious()) {
			ProgramLocation loc = locationIterator.previous();
			if (!locationIterator.hasPrevious()) {
				locationList.clear();
				locationIterator = locationList.listIterator();
			}
			return loc;
		}
		return null;
	}

	boolean hasNext() {
		if (locationList.size() == 0) {
			findNext();
		}
		return options.isForward() ? locationIterator.hasNext() : locationIterator.hasPrevious();
	}

	@Override
	public void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	@Override
	public ProgramLocation search() {
		try {
			if (hasNext()) {
				return next();
			}
		}
		catch (Exception e) {
			// if the tool is busy disassembling or if the program got closed,
			// ignore the exception.
			if (tool.isExecutingCommand()) {
				tool.setStatusInfo("Search failed: try search when tool is not " +
					"executing commands that may change the program");
			}
			else if (!program.isClosed() && program.getCurrentTransaction() != null) {
				tool.setStatusInfo("Search failed: try search when program is not being changed");
			}
			else if (!program.isClosed() && !(e instanceof DomainObjectException)) {
				Msg.showError(this, null, "Error", "Error searching", e);
			}
		}
		return null;
	}

	@Override
	public SearchOptions getSearchOptions() {
		return options;
	}

	private void findNext() {
		if (currentLayout != null) {
			findNextMatch();
			if (locationList.size() > 0) {
				return;
			}
		}

		int progress = options.getProgress();
		monitor.setMessage("Searching...");
		currentAddress = null;
		currentCodeUnit = null;
		Listing listing = program.getListing();
		while (!monitor.isCancelled() && currentLayout == null && addressIterator.hasNext() &&
			locationList.size() == 0) {

			currentAddress = addressIterator.next();
			monitor.setMessage("Checking address " + currentAddress);
			if (!options.searchAllFields()) {
				currentCodeUnit = listing.getCodeUnitContaining(currentAddress);
			}

			++progress;
			options.setProgress(progress);
			monitor.setProgress(progress);

			if ((options.isForward() && currentAddress.compareTo(startAddress) < 0) ||
				(!options.isForward() && currentAddress.compareTo(startAddress) > 0)) {
				continue;
			}
			if ((options.isForward() &&
				currentAddress.compareTo(searchAddresses.getMaxAddress()) > 0) ||
				(!options.isForward() &&
					currentAddress.compareTo(searchAddresses.getMinAddress()) < 0)) {
				return;
			}
			if (!searchAddresses.contains(currentAddress)) {
				continue;
			}
			currentLayout = listingModel.getLayout(currentAddress, false);
			if (currentLayout == null) {
				continue;
			}

			if (options.isForward()) {
				while (!monitor.isCancelled() && locationList.size() == 0 &&
					currentLayout != null && currentFieldIndex < currentLayout.getNumFields()) {
					findNextMatch();
				}
			}
			else {
				currentFieldIndex = currentLayout.getNumFields() - 1;
				while (!monitor.isCancelled() && locationList.size() == 0 &&
					currentLayout != null && currentFieldIndex >= 0) {
					findNextMatch();
				}
			}
		}
	}

	private void findNextMatch() {

		if (options.isForward()) {
			initializeForward();
			searchForward();
		}
		else {
			initializeBackward();
			searchBackward();
		}
	}

	private void searchForward() {
		for (int i =
			currentFieldIndex; i < currentLayout.getNumFields(); i++, currentFieldIndex++) {
			int matchingFieldCount = findLocations(i);
			if (matchingFieldCount != 0) {
				currentFieldIndex += matchingFieldCount;
				return;
			}
		}
		currentLayout = null;
		currentFieldIndex = 0;
	}

	private void searchBackward() {
		for (int i = currentFieldIndex; i >= 0; i--, currentFieldIndex--) {
			int matchingFieldCount = findLocations(i);
			if (matchingFieldCount != 0) {
				currentFieldIndex -= matchingFieldCount;
				return;
			}
		}
		currentLayout = null;
		currentFieldIndex = 0;
	}

	/**
	 * Returns the number of fields used in the match.
	 */
	private int findLocations(int fieldIndex) {
		ListingField field = (ListingField) currentLayout.getField(fieldIndex);
		FieldFactory ff = field.getFieldFactory();
		String fieldName = ff.getFieldName();
		if (!doSearchField(fieldName)) {
			return 0;
		}

		int fieldCount = 1; // we always match on one field, unless it is the Mnemonic/Operand combo

		// if field is the Mnemonic, and instructions or data are 
		// being searched, get the next field as well
		boolean isMnemonic = fieldName.equals(MnemonicFieldFactory.FIELD_NAME);
		boolean isInstructionsOrData =
			options.searchAllFields() || options.searchBothDataMnemonicsAndOperands() ||
				options.searchBothInstructionMnemonicAndOperands();
		if (isMnemonic && isInstructionsOrData) {
			if (currentFieldIndex <= currentLayout.getNumFields() - 2) {
				ListingField opField = (ListingField) currentLayout.getField(fieldIndex + 1);
				findMnemonicOperandLocations(field, opField);
				fieldCount = 2; // if we match here, then signal that we matched across two fields
			}
			else {
				findLocations(field);
			}
		}
		else {
			findLocations(field);
		}

		if (locationList.size() > 0) {
			// we found a match!
			return fieldCount;
		}
		return 0;
	}

	private void initializeForward() {
		if (isInitialized) {
			return;
		}
		startIndex = -1;

		if (startLocation != null) {
			if (startLocation.getAddress().equals(currentAddress)) {
				// set the current Field index to correspond to the program location
				for (int i = 0; i < currentLayout.getNumFields(); i++) {
					ListingField field = (ListingField) currentLayout.getField(i);
					if (getFieldForLocation(field, i)) {
						break;
					}
				}
			}
		}
		isInitialized = true;
	}

	private void initializeBackward() {
		if (isInitialized) {
			return;
		}
		startIndex = Integer.MAX_VALUE;

		if (startLocation != null) {
			// set the current Field index to correspond to the program location
			if (startLocation.getAddress().equals(currentAddress)) {
				for (int i = currentLayout.getNumFields() - 1; i >= 0; i--) {
					ListingField field = (ListingField) currentLayout.getField(i);
					if (getFieldForLocation(field, i)) {
						break;
					}
				}
			}
		}
		isInitialized = true;
	}

	/**
	 * Sets the currentFieldIndex of the field that corresponds to the
	 * startLoc program location
	 * @param field
	 * @param fieldIndex
	 * @return true if this field corresponds to the startLoc program location
	 */
	private boolean getFieldForLocation(ListingField field, int fieldIndex) {
		FieldFactory ff = field.getFieldFactory();
		FieldLocation floc = ff.getFieldLocation(field, BigInteger.ZERO, fieldIndex, startLocation);
		if (floc == null) {
			return false;
		}

		if (!doSearchField(ff.getFieldName())) {
			return false;
		}

		// now determine where to start searching within the string
		currentFieldIndex = fieldIndex;
		startIndex = field.screenLocationToTextOffset(floc.getRow(), floc.getCol());
		return true;
	}

	private boolean doSearchField(String fieldName) {
		if (options.searchAllFields()) {
			return true;
		}

		if (options.searchComments()) {
			if (fieldName.equals(PreCommentFieldFactory.FIELD_NAME) ||
				fieldName.equals(PlateFieldFactory.FIELD_NAME) ||
				fieldName.equals(PostCommentFieldFactory.FIELD_NAME) ||
				fieldName.equals(EolCommentFieldFactory.FIELD_NAME)) {
				return true;
			}
		}

		if (options.searchBothInstructionMnemonicAndOperands() &&
			(currentCodeUnit instanceof Instruction)) {
			if (fieldName.equals(MnemonicFieldFactory.FIELD_NAME) ||
				fieldName.equals(OperandFieldFactory.FIELD_NAME)) {
				return true;
			}
		}
		if (options.searchOnlyInstructionMnemonics() && (currentCodeUnit instanceof Instruction)) {
			if (fieldName.equals(MnemonicFieldFactory.FIELD_NAME)) {
				return true;
			}
		}
		if (options.searchOnlyInstructionOperands() && (currentCodeUnit instanceof Instruction)) {
			if (fieldName.equals(OperandFieldFactory.FIELD_NAME)) {
				return true;
			}
		}

		if (options.searchBothDataMnemonicsAndOperands() && (currentCodeUnit instanceof Data)) {
			if (fieldName.equals(MnemonicFieldFactory.FIELD_NAME) ||
				fieldName.equals(OperandFieldFactory.FIELD_NAME)) {
				return true;
			}
		}
		if (options.searchOnlyDataMnemonics() && (currentCodeUnit instanceof Data)) {
			if (fieldName.equals(MnemonicFieldFactory.FIELD_NAME)) {
				return true;
			}
		}
		if (options.searchOnlyDataOperands() && (currentCodeUnit instanceof Data)) {
			if (fieldName.equals(OperandFieldFactory.FIELD_NAME)) {
				return true;
			}
		}

		if (options.searchFunctions()) {
			if (fieldName.equals(FunctionRepeatableCommentFieldFactory.FIELD_NAME) ||
				fieldName.equals(FunctionSignatureFieldFactory.FIELD_NAME) ||
				fieldName.equals(VariableCommentFieldFactory.FIELD_NAME) ||
				fieldName.equals(VariableLocFieldFactory.FIELD_NAME) ||
				fieldName.equals(VariableNameFieldFactory.FIELD_NAME) ||
				fieldName.equals(VariableTypeFieldFactory.FIELD_NAME)) {
				return true;
			}
		}
		if (options.searchLabels()) {
			if (fieldName.equals(LabelFieldFactory.FIELD_NAME)) {
				return true;
			}
		}

		return false;
	}

	private void findMnemonicOperandLocations(ListingField mnemonicField, ListingField opField) {

		MnemonicText mnemonicText = generateMnemonicSearchText(mnemonicField, opField);
		String text = mnemonicText.getText();
		Matcher matcher = searchPattern.matcher(text);
		boolean forward = options.isForward();
		int mnemonicLength = mnemonicText.mnemonicLength();
		while (matcher.find()) {
			int index = matcher.start();
			if (index > mnemonicLength) {
				break;
			}
			if (forward && index <= startIndex) {
				continue;
			}
			if (!forward && index >= startIndex) {
				break;
			}
			FieldFactory fieldFactory = mnemonicField.getFieldFactory();
			RowColLocation rc = mnemonicField.textOffsetToScreenLocation(index);
			int col = rc.col();

			if (index == mnemonicLength) {
				col++;
			}
			locationList.add(fieldFactory.getProgramLocation(rc.row(), col, mnemonicField));
		}

		adjustIterator();
	}

	private MnemonicText generateMnemonicSearchText(ListingField mnemonicField,
			ListingField opField) {
		String mnemonic = mnemonicField.getText();
		String operands = opField != null ? opField.getText() : "";

		return new MnemonicText(mnemonic, operands);
	}

	private void findLocations(ListingField field) {
		String text = field.getText();
		boolean forward = options.isForward();

		Matcher match = searchPattern.matcher(text);
		while (match.find()) {
			int index = match.start();
			if (forward && index <= startIndex) {
				continue;
			}
			if (!forward && index >= startIndex) {
				break;
			}
			RowColLocation rc = field.textOffsetToScreenLocation(index);
			FieldFactory fieldFactory = field.getFieldFactory();
			ProgramLocation loc = fieldFactory.getProgramLocation(rc.row(), rc.col(), field);
			if ((loc != null) && !isSameLocation(loc)) { // loc will be null if field is clipped.
				locationList.add(loc);
			}
		}

		adjustIterator();
		startIndex = forward ? -1 : Integer.MAX_VALUE;
		startLocation = null;
	}

	private void adjustIterator() {
		locationIterator = locationList.listIterator();
		if (!options.isForward()) {
			// position iterator to end so that previous() will work
			while (locationIterator.hasNext()) {
				locationIterator.next();
			}
		}
	}

	private boolean isSameLocation(ProgramLocation loc) {
		if (startLocation == null || !(loc instanceof OperandFieldLocation) ||
			!(startLocation instanceof OperandFieldLocation)) {
			return false;
		}

		OperandFieldLocation opStartLoc = (OperandFieldLocation) startLocation;
		OperandFieldLocation opLoc = (OperandFieldLocation) loc;
		if (!opStartLoc.getAddress().equals(opLoc.getAddress())) {
			return false;
		}
		// note: the program database search generates a location with sub op index as -1,
		// so treat this as the same location if the sub op index is -1;
		// this happens when transitioning from a database search to listing display search.
		return (opStartLoc.getSubOperandIndex() < 0 &&
			opStartLoc.getOperandIndex() == opLoc.getOperandIndex());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MnemonicText {
		private String mnemonic;
		private String text;

		MnemonicText(String mnemonic, String operands) {
			this.mnemonic = mnemonic;
			this.text = mnemonic + " " + operands;
		}

		int mnemonicLength() {
			return mnemonic.length();
		}

		String getText() {
			return text;
		}
	}
}
