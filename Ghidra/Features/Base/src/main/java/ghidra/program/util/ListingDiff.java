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
package ghidra.program.util;

import ghidra.app.util.viewer.listingpanel.ListingDiffChangeListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.ListingAddressCorrelation;
import ghidra.util.Msg;

import java.util.ArrayList;

/**
 * Determines where instructions couldn't be matched and where they differ between sets of 
 * addresses as provided by a ListingAddressCorrelation. Initially this will be byte 
 * differences and instruction operand differences for any instructions that were determined 
 * to be matched.
 * <br>Important: This class is not intended to be used for an entire program. Instead it is 
 * for comparing smaller portions such as functions. If the correlation handed to this class 
 * associates two large address sets, then the address sets, such as byte differences, that are 
 * created by this class could potentially consume large amounts of memory.
 */
public class ListingDiff {

	private ListingAddressCorrelation correlation;
	AddressSet unmatchedCode1;
	AddressSet unmatchedCode2;
	AddressSet byteDiffs1;
	AddressSet byteDiffs2;
	AddressSet codeUnitDiffs1;
	AddressSet codeUnitDiffs2;

	private boolean ignoreByteDiffs;
	private boolean ignoreConstants;
	private boolean ignoreRegisters;

	private ArrayList<ListingDiffChangeListener> listeners =
		new ArrayList<ListingDiffChangeListener>();

	/**
	 * Creates a ListingDiff to determine where instructions couldn't be matched and where they 
	 * differ between sets of addresses as provided by a ListingAddressCorrelation.
	 */
	public ListingDiff() {
		init();
	}

	/**
	 * Sets the address correlation that is used to determine matching addresses between the two 
	 * listings. Differences can then be determined where a matching address is found.
	 * <br>Important: This class is not intended to be used for an entire program. Instead it is 
	 * for comparing smaller portions such as functions. If the correlation handed to this class 
	 * associates two large address sets, then the address sets, such as byte differences, that are 
	 * created by this class could potentially consume large amounts of memory.
	 * @param correlation the address correlation. Otherwise, null to clear the correlation.
	 * @throws MemoryAccessException if memory can't be read.
	 */
	public void setCorrelation(ListingAddressCorrelation correlation) throws MemoryAccessException {
		this.correlation = correlation;
		if (correlation == null) {
			init();
			return;
		}
		getDiffs();
	}

	/**
	 * Determines if this ListingDiff currently has an address correlation to use.
	 * @return true if it has an address correlation currently.
	 */
	public boolean hasCorrelation() {
		return correlation != null;
	}

	private void init() {
		unmatchedCode1 = new AddressSet();
		unmatchedCode2 = new AddressSet();
		codeUnitDiffs1 = new AddressSet();
		codeUnitDiffs2 = new AddressSet();
		byteDiffs1 = new AddressSet();
		byteDiffs2 = new AddressSet();
	}

	private void getDiffs() throws MemoryAccessException {
		init();
		AddressSetView addrSet1 = correlation.getAddressesInFirst();
		AddressSetView addrSet2 = correlation.getAddressesInSecond();
		Listing listing1 = correlation.getFirstProgram().getListing();
		Listing listing2 = correlation.getSecondProgram().getListing();
		CodeUnitIterator cuIter1 = listing1.getCodeUnits(addrSet1, true);
		CodeUnitIterator cuIter2 = listing2.getCodeUnits(addrSet2, true);
		for (CodeUnit cu1 : cuIter1) {
			Address min1 = cu1.getMinAddress();
			Address addr2 = correlation.getAddressInSecond(min1);
			if (addr2 == null) {
				// Add codeunit1 to the unmatchedDiffs
				unmatchedCode1.addRange(cu1.getMinAddress(), cu1.getMaxAddress());
				continue;
			}
			CodeUnit cu2 = listing2.getCodeUnitAt(addr2);

			getByteDiffs(cu1, cu2, byteDiffs1);

			getCodeUnitDiffs(cu1, cu2, codeUnitDiffs1);
		}
		for (CodeUnit cu2 : cuIter2) {
			Address min2 = cu2.getMinAddress();
			Address addr1 = correlation.getAddressInFirst(min2);
			if (addr1 == null) {
				// Add codeunit2 to the unmatchedDiffs
				unmatchedCode2.addRange(cu2.getMinAddress(), cu2.getMaxAddress());
				continue;
			}
			CodeUnit cu1 = listing1.getCodeUnitAt(addr1);

			getByteDiffs(cu2, cu1, byteDiffs2);

			getCodeUnitDiffs(cu2, cu1, codeUnitDiffs2);
		}
		notifyListeners();
	}

	private void recomputeCodeUnitDiffs() {
		AddressSetView addressSet1 = correlation.getAddressesInFirst();
		AddressSetView addressSet2 = correlation.getAddressesInSecond();
		AddressSetView matchedAddresses1 = addressSet1.subtract(unmatchedCode1);
		AddressSetView matchedAddresses2 = addressSet2.subtract(unmatchedCode2);
		Listing listing1 = correlation.getFirstProgram().getListing();
		Listing listing2 = correlation.getSecondProgram().getListing();
		CodeUnitIterator cuIter1 = listing1.getCodeUnits(matchedAddresses1, true);
		CodeUnitIterator cuIter2 = listing2.getCodeUnits(matchedAddresses2, true);
		codeUnitDiffs1.clear();
		for (CodeUnit cu1 : cuIter1) {
			Address min1 = cu1.getMinAddress();
			Address addr2 = correlation.getAddressInSecond(min1);
			if (addr2 == null) {
				continue;
			}
			CodeUnit cu2 = listing2.getCodeUnitAt(addr2);

			getCodeUnitDiffs(cu1, cu2, codeUnitDiffs1);
		}
		codeUnitDiffs2.clear();
		for (CodeUnit cu2 : cuIter2) {
			Address min2 = cu2.getMinAddress();
			Address addr1 = correlation.getAddressInFirst(min2);
			if (addr1 == null) {
				continue;
			}
			CodeUnit cu1 = listing1.getCodeUnitAt(addr1);

			getCodeUnitDiffs(cu2, cu1, codeUnitDiffs2);
		}
	}

	private void getByteDiffs(CodeUnit cu1, CodeUnit cu2, AddressSet byteDiffs)
			throws MemoryAccessException {
		if (cu2 == null) {
			byteDiffs.addRange(cu1.getMinAddress(), cu1.getMaxAddress());
		}
		else {
			byte[] bytes1 = cu1.getBytes();
			byte[] bytes2 = cu2.getBytes();
			int minBytes = Math.min(bytes1.length, bytes2.length);
			Address minAddr = cu1.getMinAddress();
			for (int i = 0; i < minBytes; i++) {
				if (bytes1[i] != bytes2[i]) {
					byteDiffs.add(minAddr.add(i));
				}
			}
			if (bytes1.length > bytes2.length) {
				byteDiffs.addRange(minAddr.add(bytes2.length), cu1.getMaxAddress());
			}
		}
	}

	private void getCodeUnitDiffs(CodeUnit cu1, CodeUnit cu2, AddressSet cuDiffs) {
		if (!equivalentCodeUnits(cu1, cu2)) {
			// Add codeunit1 to the codeUnitDiffs
			cuDiffs.addRange(cu1.getMinAddress(), cu1.getMaxAddress());
		}
	}

	private boolean equivalentCodeUnits(CodeUnit cu1, CodeUnit cu2) {

		// Check mnemonics.
		if (!isSameMnemonic(cu1, cu2)) {
			return false;
		}

		// Check operands.
		if (doesEntireOperandSetDiffer(cu1, cu2)) {
			return false;
		}
		int[] operandsThatDiffer = getOperandsThatDiffer(cu1, cu2);
		return (operandsThatDiffer != null && operandsThatDiffer.length == 0);
	}

	private boolean isSameMnemonic(CodeUnit codeUnit1, CodeUnit codeUnit2) {
		if (!sameType(codeUnit1, codeUnit2)) {
			return false;
		}
		return codeUnit1.getMnemonicString().equals(codeUnit2.getMnemonicString());
	}

	/**
	 * Gets an array containing the operand indices where the two indicated code units differ.
	 * These differences are determined based on whether constants and registers are
	 * being ignored.
	 * @param codeUnit1 the first code unit
	 * @param codeUnit2 the second code unit
	 * @return an array of operand indices where the operands differ between the two code units 
	 * based on the current settings that indicate what differences can be ignored.
	 */
	public int[] getOperandsThatDiffer(CodeUnit codeUnit1, CodeUnit codeUnit2) {
		int numOperands = codeUnit1.getNumOperands();
		if (codeUnit2 == null) {
			return getAllIndices(numOperands);
		}
		if (codeUnit1 instanceof Instruction && codeUnit2 instanceof Instruction) {
			int otherNumOperands = codeUnit2.getNumOperands();
			// Return indices for whole operand string if number of operands differs.
			if (numOperands != otherNumOperands) {
				return getAllIndices(numOperands);
			}

			// Add each operand index where the operands differ between the two instructions.
			Instruction inst1 = (Instruction) codeUnit1;
			Instruction inst2 = (Instruction) codeUnit2;
			ArrayList<Integer> opIndices = new ArrayList<Integer>();
			for (int opIndex = 0; opIndex < numOperands; opIndex++) {
				Object[] opObjects1 = inst1.getOpObjects(opIndex);
				Object[] opObjects2 = inst2.getOpObjects(opIndex);
				if (opObjectsDiffer(opObjects1, opObjects2)) {
					opIndices.add(opIndex);
				}
			}
			// Convert to int array.
			int[] diffOpIndices = new int[opIndices.size()];
			for (int index = 0; index < diffOpIndices.length; index++) {
				diffOpIndices[index] = opIndices.get(index);
			}
			return diffOpIndices;
		}
		else if (codeUnit1 instanceof Data && codeUnit2 instanceof Data) {
			Data data1 = (Data) codeUnit1;
			Data data2 = (Data) codeUnit2;
			if (isSameData(data1, data2)) {
				return new int[0]; // No operands differ.
			}
		}
		return getAllIndices(numOperands); // All operands differ.
	}

	/**
	 * Determine if the first and second instructions objects for a particular operand differ.
	 * The opObjects are checked using the currently specified ignore flags for determining 
	 * instruction operand differences.
	 * @param opObjects1 the operand objects that compose an operand for the first instruction
	 * @param opObjects2 the operand objects that compose an operand for the second instruction
	 * @return true if the opObjects differ based on the current diff ignore flags.
	 */
	private boolean opObjectsDiffer(Object[] opObjects1, Object[] opObjects2) {
		if (opObjects1.length != opObjects2.length) {
			return true;
		}
		for (int i = 0; i < opObjects1.length; i++) {
			Object obj1 = opObjects1[i];
			Object obj2 = opObjects2[i];
			if (obj1.equals(obj2)) {
				continue;
			}
			if (obj1 instanceof Scalar && obj2 instanceof Scalar) {
				if (ignoreConstants) {
					continue;
				}
			}
			else if (obj1 instanceof Address && obj2 instanceof Address) {
				if (ignoreConstants) {
					continue;
				}
			}
			else if (obj1 instanceof Register && obj2 instanceof Register) {
				Register reg1 = (Register) obj1;
				Register reg2 = (Register) obj2;
				int len1 = reg1.getBitLength();
				int len2 = reg2.getBitLength();
				if (len1 != len2) {
					return true;
				}
				if (!ignoreRegisters && !reg1.equals(reg2)) {
					return true;
				}
				continue;
			}
			return true;
		}
		return false;
	}

	/**
	 * Determines if the entire set of operands should indicate that it differs.
	 * If the code units aren't the same type then the entire set of operands is considered different.
	 * Also if the number of operands differs then as far as we're concerned the entire set differs.
	 * @param codeUnit1 the first code unit
	 * @param codeUnit2 the second code unit
	 * @return true if we should indicate that all operands differ.
	 */
	public boolean doesEntireOperandSetDiffer(CodeUnit codeUnit1, CodeUnit codeUnit2) {
		if (!sameType(codeUnit1, codeUnit2)) {
			return true;
		}
		int numOperands = codeUnit1.getNumOperands();
		int otherNumOperands = codeUnit2.getNumOperands();
		// Return whole operand string if number of operands differs.
		if (numOperands != otherNumOperands) {
			return true;
		}
		return false;
	}

	private boolean sameType(CodeUnit codeUnit1, CodeUnit codeUnit2) {
		if (codeUnit1 == null) {
			return (codeUnit2 == null);
		}
		if (codeUnit2 == null) {
			return false;
		}
		return (codeUnit1 instanceof Instruction && codeUnit2 instanceof Instruction) ||
			(codeUnit1 instanceof Data && codeUnit2 instanceof Data);
	}

	private boolean isSameData(Data data1, Data data2) {
		if (data1.getLength() != data2.getLength()) {
			return false;
		}
		DataType dt1 = data1.getDataType();
		DataType dt2 = data2.getDataType();
		if (!dt1.isEquivalent(dt2)) {
			return false;
		}
		// Detect that data type name or path differs?
		if (!dt1.getPathName().equals(dt2.getPathName())) {
			return false;
		}
		return true;
	}

	@SuppressWarnings("unused")
	private boolean sameBytes(CodeUnit cu1, CodeUnit cu2) {
		byte[] bytes1;
		byte[] bytes2;
		try {
			bytes1 = cu1.getBytes();
			bytes2 = cu2.getBytes();
		}
		catch (MemoryAccessException e) {
			return false;
		}
		if (bytes1.length != bytes2.length) {
			return false;
		}
		for (int i = 0; i < bytes1.length; i++) {
			if (bytes1[i] != bytes2[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Gets the addresses in the first listing where matching code couldn't be determined in the 
	 * second listing.
	 * @return the addresses of the unmatched code in the first listing.
	 */
	public AddressSetView getListing1UnmatchedCode() {
		return new AddressSet(unmatchedCode1);
	}

	/**
	 * Gets the addresses in the second listing where matching code couldn't be determined in the 
	 * first listing.
	 * @return the addresses of the unmatched code in the second listing.
	 */
	public AddressSetView getListing2UnmatchedCode() {
		return new AddressSet(unmatchedCode2);
	}

	/**
	 * Gets the addresses in the first listing where differences were found based on the current 
	 * difference settings.
	 * @return the addresses with differences in the first listing.
	 */
	public AddressSetView getListing1Diffs() {
		AddressSet diffs = new AddressSet(getListing1ByteDiffs());
		diffs.add(getListing1CodeUnitDiffs());
		return DiffUtility.getCodeUnitSet(diffs, correlation.getFirstProgram());
	}

	/**
	 * Gets the addresses in the second listing where differences were found based on the current 
	 * difference settings.
	 * @return the addresses with differences in the second listing.
	 */
	public AddressSetView getListing2Diffs() {
		AddressSet diffs = new AddressSet(getListing2ByteDiffs());
		diffs.add(getListing2CodeUnitDiffs());
		return DiffUtility.getCodeUnitSet(diffs, correlation.getSecondProgram());
	}

	/**
	 * Gets the addresses in the first listing where code unit (mnemonic and/or operand) differences 
	 * were found based on the current difference settings.
	 * @return the addresses with code unit differences in the first listing.
	 */
	public AddressSetView getListing1CodeUnitDiffs() {
		return new AddressSet(codeUnitDiffs1);
	}

	/**
	 * Gets the addresses in the second listing where code unit (mnemonic and/or operand) differences 
	 * were found based on the current difference settings.
	 * @return the addresses with code unit differences in the second listing.
	 */
	public AddressSetView getListing2CodeUnitDiffs() {
		return new AddressSet(codeUnitDiffs2);
	}

	/**
	 * Gets the addresses in the first listing where byte differences were found based on the 
	 * current difference settings.
	 * @return the addresses with byte differences in the first listing.
	 */
	public AddressSetView getListing1ByteDiffs() {
		if (ignoreByteDiffs) {
			return new AddressSet();
		}
		return new AddressSet(byteDiffs1);
	}

	/**
	 * Gets the addresses in the second listing where byte differences were found based on the 
	 * current difference settings.
	 * @return the addresses with byte differences in the second listing.
	 */
	public AddressSetView getListing2ByteDiffs() {
		if (ignoreByteDiffs) {
			return new AddressSet();
		}
		return new AddressSet(byteDiffs2);
	}

	/**
	 * Gets the matching address from the other listing for the specified address from one
	 * of the two listings whose differences this class determines.
	 * @param address the address whose matching address this determines.
	 * @param isListing1 true indicates the address is from the first listing. false indicates
	 * it is from the second listing.
	 * @return the matching address or null
	 */
	public Address getMatchingAddress(Address address, boolean isListing1) {
		if (correlation == null) {
			return null;
		}
		if (isListing1) {
			return correlation.getAddressInSecond(address);
		}
		return correlation.getAddressInFirst(address);
	}

	/**
	 * Outputs an information message, primarily for debugging, that indicates where code was 
	 * unmatched with the other listing and where various differences, such as bytes and 
	 * code units, were found.
	 */
	public void printFunctionComparisonDiffs() {
		StringBuffer buffer = new StringBuffer();
		outputAddressSet(buffer, "Unmatched Diffs 1", unmatchedCode1);
		outputAddressSet(buffer, "Unmatched Diffs 2", unmatchedCode2);
		outputAddressSet(buffer, "Byte Diffs 1", byteDiffs1);
		outputAddressSet(buffer, "Byte Diffs 2", byteDiffs2);
		outputAddressSet(buffer, "Code Diffs 1", codeUnitDiffs1);
		outputAddressSet(buffer, "Code Diffs 2", codeUnitDiffs2);
		Msg.info(this, buffer.toString());
	}

	private void outputAddressSet(StringBuffer buffer, String title, AddressSet addressSet) {
		buffer.append(title + ":\n");
		int i = 0;
		for (AddressRange addressRange : addressSet) {
			buffer.append(addressRange.toString());
			// Wrap the output line for readability every time we output 10 ranges.
			if (++i % 10 == 0) {
				buffer.append("\n");
			}
		}
		buffer.append("\n");
	}

	/**
	 * Gets the setting indicating if byte differences are currently being ignored.
	 * @return true if byte differences are being ignored.
	 */
	public boolean isIgnoringByteDiffs() {
		return ignoreByteDiffs;
	}

	/**
	 * Changes the setting indicating whether or not byte differences should be ignored.
	 * @param ignore true indicates to ignore byte differences
	 */
	public void setIgnoreByteDiffs(boolean ignore) {
		ignoreByteDiffs = ignore;
		notifyListeners();
	}

	/**
	 * Gets the setting indicating if values of operand constants that differ are currently 
	 * being ignored when determining code unit differences.
	 * @return true if code unit differences are ignoring differences in values of operand
	 * constants.
	 */
	public boolean isIgnoringConstants() {
		return ignoreConstants;
	}

	/**
	 * Changes the setting indicating if values of operand constants that differ should be 
	 * ignored when determining code unit differences.
	 * @param ignore true means code unit differences should ignore differences in values of 
	 * operand constants.
	 */
	public void setIgnoreConstants(boolean ignore) {
		ignoreConstants = ignore;
		if (correlation != null) {
			recomputeCodeUnitDiffs();
		}
		notifyListeners();
	}

	/**
	 * Gets the setting indicating if operand registers that differ other than in size
	 * are currently being ignored when determining code unit differences.
	 * @return true if code unit differences are ignoring operand register differences other 
	 * than in size.
	 */
	public boolean isIgnoringRegisters() {
		return ignoreRegisters;
	}

	/**
	 * Changes the setting indicating if operand registers that differ other than in size 
	 * should be ignored when determining code unit differences.
	 * @param ignore true means code unit differences should ignore operand register differences
	 * other than in size.
	 */
	public void setIgnoreRegisters(boolean ignore) {
		ignoreRegisters = ignore;
		if (correlation != null) {
			recomputeCodeUnitDiffs();
		}
		notifyListeners();
	}

	private void notifyListeners() {
		for (ListingDiffChangeListener listener : listeners) {
			listener.listingDiffChanged();
		}
	}

	/**
	 * Adds the indicated listener to those that get notified when the ListingDiff's set of 
	 * differences and unmatched addresses changes.
	 * @param listener the listener to be notified
	 */
	public void addListingDiffChangeListener(ListingDiffChangeListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes the indicated listener from those that get notified when the ListingDiff's set of 
	 * differences and unmatched addresses changes.
	 * @param listener the listener to be removed
	 */
	public void removeListingDiffChangeListener(ListingDiffChangeListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Gets the matching code unit from the other listing for the specified code unit from one
	 * of the two listings whose differences this class determines.
	 * @param codeUnit the code unit whose match this determines.
	 * @param isListing1 true indicates the code unit is from the first listing. false indicates
	 * it is from the second listing.
	 * @return the matching code unit or null
	 */
	public CodeUnit getMatchingCodeUnit(CodeUnit codeUnit, boolean isListing1) {
		if (correlation == null) {
			return null;
		}
		Address minAddress = codeUnit.getMinAddress();
		Program sourceProgram = correlation.getFirstProgram();
		Program destinationProgram = correlation.getSecondProgram();
		if (isListing1) {
			Address destination = correlation.getAddressInSecond(minAddress);
			if (destination != null) {
				return destinationProgram.getListing().getCodeUnitAt(destination);
			}
		}
		else {
			Address source = correlation.getAddressInFirst(minAddress);
			if (source != null) {
				return sourceProgram.getListing().getCodeUnitAt(source);
			}
		}
		// code unit not from our programs.
		return null;
	}

	/**
	 * Returns an array of the indicated contiguous number of indices starting at 0.
	 * This provides a convenient way to get an array indicating all the operand indices for
	 * a particular code unit by specifying its number of operands.
	 * @param number the number of indices to return.
	 * @return the indices.
	 */
	private int[] getAllIndices(int number) {
		if (number < 0) {
			throw new IllegalArgumentException();
		}
		int[] numbers = new int[number];
		for (int i = 0; i < number; i++) {
			numbers[i] = i;
		}
		return numbers;
	}
}
