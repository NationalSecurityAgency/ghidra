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
package ghidra.app.util.viewer.listingpanel;

import java.awt.Color;
import java.util.ArrayList;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ListingDiff;

public class ListingDiffHighlightProvider implements HighlightProvider {

	private static final int NUM_CHARACTERS_PER_BYTE = 3; // 2 hex digits and a space;
	private static final String DEFAULT_OPERAND_SEPARATOR = ",";

	private ListingDiff listingDiff;
	private boolean isListing1;
	private ListingCodeComparisonOptions comparisonOptions;

	/**
	 * Constructor for this highlight provider.
	 * @param listingDiff the ListingDiff to use to determine where there are differences that 
	 * need highlighting.
	 * @param isListing1 true means that these are the highlights for the first listing.
	 * false means the highlights are for the second listing.
	 * @param comparisonOptions the tool options that indicate the current 
	 * background colors for the Listing code comparison panel.
	 */
	public ListingDiffHighlightProvider(ListingDiff listingDiff, boolean isListing1,
			ListingCodeComparisonOptions comparisonOptions) {
		this.listingDiff = listingDiff;
		this.isListing1 = isListing1;
		this.comparisonOptions = comparisonOptions;
	}

	@Override
	public Highlight[] getHighlights(String text, Object obj,
			Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {

		Highlight[] highlights = EMPTY_HIGHLIGHT;

		if (obj instanceof CodeUnit) {
			CodeUnit codeUnit = (CodeUnit) obj;
			if (fieldFactoryClass == BytesFieldFactory.class) {
				highlights = getByteDiffHighlights(text, codeUnit, cursorTextOffset);
			}
			else if (fieldFactoryClass == MnemonicFieldFactory.class) {
				highlights = getMnemonicDiffHighlights(text, codeUnit, cursorTextOffset);
			}
			else if (fieldFactoryClass == OperandFieldFactory.class) {
				highlights = getOperandDiffHighlights(text, codeUnit, cursorTextOffset);
			}
		}
		return highlights;
	}

	private Highlight[] getByteDiffHighlights(String text, CodeUnit codeUnit,
			int cursorTextOffset) {
		Address minAddress = codeUnit.getMinAddress();
		AddressSetView unmatchedDiffs = (isListing1) ? listingDiff.getListing1UnmatchedCode()
				: listingDiff.getListing2UnmatchedCode();
		if (unmatchedDiffs.contains(minAddress)) {
			return EMPTY_HIGHLIGHT;
		}
		Color byteDiffsBackgroundColor = comparisonOptions.getByteDiffsBackgroundColor();
		AddressSetView byteDiffs =
			(isListing1) ? listingDiff.getListing1ByteDiffs() : listingDiff.getListing2ByteDiffs();
		// Get intersection of Byte Diff addresses and this code unit's addresses
		AddressSet diffSet = new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
		diffSet = diffSet.intersect(byteDiffs);
		if (!diffSet.isEmpty()) {
			ArrayList<Highlight> highlights = new ArrayList<>();
			// Get Highlight for each byte that differs.
			for (AddressRange addressRange : diffSet) {
				Address rangeMinAddress = addressRange.getMinAddress();
				long minByteIndex = rangeMinAddress.subtract(minAddress);
				int startIndex = (int) minByteIndex * NUM_CHARACTERS_PER_BYTE;
				Address rangeMaxAddress = addressRange.getMaxAddress();
				long maxByteIndex = rangeMaxAddress.subtract(minAddress);
				int endIndex = (int) (maxByteIndex * NUM_CHARACTERS_PER_BYTE) + 1;
				highlights.add(new Highlight(startIndex, endIndex, byteDiffsBackgroundColor));
			}
			return highlights.toArray(new Highlight[highlights.size()]);
		}
		return EMPTY_HIGHLIGHT;
	}

	private Highlight[] getMnemonicDiffHighlights(String text, CodeUnit codeUnit,
			int cursorTextOffset) {
		Address minAddress = codeUnit.getMinAddress();
		AddressSetView unmatchedDiffs = (isListing1) ? listingDiff.getListing1UnmatchedCode()
				: listingDiff.getListing2UnmatchedCode();
		if (unmatchedDiffs.contains(minAddress)) {
			return EMPTY_HIGHLIGHT;
		}
		Color mnemonicDiffsBackgroundColor = comparisonOptions.getMnemonicDiffsBackgroundColor();
		AddressSetView codeUnitDiffs = (isListing1) ? listingDiff.getListing1CodeUnitDiffs()
				: listingDiff.getListing2CodeUnitDiffs();
		// Get intersection of Code Unit Diff addresses and this code unit's addresses
		AddressSet diffSet = new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
		diffSet = diffSet.intersect(codeUnitDiffs);
		if (!diffSet.isEmpty()) {
			CodeUnit otherCodeUnit = listingDiff.getMatchingCodeUnit(codeUnit, isListing1);
			if (otherCodeUnit == null) {
				return entireTextHighlight(text, cursorTextOffset, mnemonicDiffsBackgroundColor);
			}
			// Highlight the mnemonic if they differ.
			boolean sameMnemonics =
				codeUnit.getMnemonicString().equals(otherCodeUnit.getMnemonicString());
			if (!sameMnemonics) {
				return entireTextHighlight(text, cursorTextOffset, mnemonicDiffsBackgroundColor);
			}
		}
		return EMPTY_HIGHLIGHT;
	}

	private Highlight[] getOperandDiffHighlights(String text, CodeUnit codeUnit,
			int cursorTextOffset) {
		Address minAddress = codeUnit.getMinAddress();
		AddressSetView unmatchedDiffs = (isListing1) ? listingDiff.getListing1UnmatchedCode()
				: listingDiff.getListing2UnmatchedCode();
		if (unmatchedDiffs.contains(minAddress)) {
			return EMPTY_HIGHLIGHT;
		}
		Color operandDiffsBackgroundColor = comparisonOptions.getOperandDiffsBackgroundColor();
		AddressSetView codeUnitDiffs = (isListing1) ? listingDiff.getListing1CodeUnitDiffs()
				: listingDiff.getListing2CodeUnitDiffs();
		// Get intersection of Code Unit Diff addresses and this code unit's addresses
		AddressSet diffSet = new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
		diffSet = diffSet.intersect(codeUnitDiffs);
		if (!diffSet.isEmpty()) {
			CodeUnit matchingCodeUnit = listingDiff.getMatchingCodeUnit(codeUnit, isListing1);
			if (listingDiff.doesEntireOperandSetDiffer(codeUnit, matchingCodeUnit)) {
				return entireTextHighlight(text, cursorTextOffset, operandDiffsBackgroundColor);
			}
			Pair[] pairs = getOperandPairs(text, codeUnit);
			int numOperands = codeUnit.getNumOperands();
			if (pairs.length != numOperands) {
				return entireTextHighlight(text, cursorTextOffset, operandDiffsBackgroundColor);
			}
			int[] diffOpIndices = listingDiff.getOperandsThatDiffer(codeUnit, matchingCodeUnit);
			ArrayList<Highlight> highlights = new ArrayList<>();
			for (int diffOpIndex : diffOpIndices) {
				// Highlight each operand that differs.
				highlights.add(new Highlight(pairs[diffOpIndex].start, pairs[diffOpIndex].end,
					operandDiffsBackgroundColor));
			}
			return highlights.toArray(new Highlight[highlights.size()]);
		}
		return EMPTY_HIGHLIGHT;
	}

	/**
	 * Gets an array of start/end positions for each operand within the operand field's full text. 
	 * @param text the full text from the operand field
	 * @param codeUnit the code unit whose operand text is provided
	 * @return the operand pairs indicating the start and end offsets for each individual operand
	 * within the text.
	 */
	private Pair[] getOperandPairs(String text, CodeUnit codeUnit) {
		if (text == null || text.isEmpty()) {
			return new Pair[0];
		}
		Instruction instruction = (codeUnit instanceof Instruction) ? (Instruction) codeUnit : null;
		ArrayList<Pair> list = new ArrayList<>();
		int opIndex = 0;
		int textLength = text.length();
		int start = 0; // Start index in the text for the current operand.
		int separatorIndex = -1;
		// Need to get the separator between each of the operands because it can be something
		// other than a comma. The index for the operands is 0 based.
		// Calling getSeparator(opIndex) gets the separator that comes before the indicated operand.
		// There can be a separator that comes before the first operand too.
		String separator = (instruction != null) ? instruction.getSeparator(opIndex) : null;
		// Is there a separator before the first operand? If so, adjust the start.
		if (separator != null && !separator.isEmpty()) {
			separatorIndex = text.indexOf(separator, start);
			start = separatorIndex + separator.length();
		}
		// Get a start/end Pair of indexes for each operand.
		while (start < textLength) {
			++opIndex; // Increment the opIndex since we find the separator before an operand.
			separator = DEFAULT_OPERAND_SEPARATOR; // default separator
			if (instruction != null) {
				// Get the separator that follows the operand for opIndex-1.
				separator = instruction.getSeparator(opIndex);
			}
			// Get the index of the separator that follows the operand.
			separatorIndex =
				(separator != null && !separator.isEmpty()) ? text.indexOf(separator, start) : -1;
			if (separatorIndex == -1) {
				// Add the last operand's index Pair to the list.
				list.add(new Pair(start, textLength - 1));
				start = textLength;
				continue;
			}
			// Add the current operand's index Pair to the list.
			list.add(new Pair(start, separatorIndex - 1));
			// Move start to the beginning of the next operand.
			start = separatorIndex + separator.length();
		}
		return list.toArray(new Pair[list.size()]);
	}

	private Highlight[] entireTextHighlight(String text, int cursorTextOffset, Color color) {
		int startIndex = 0;
		int endIndex = text.length() - 1;
		Highlight highlight = new Highlight(startIndex, endIndex, color);
		return new Highlight[] { highlight };
	}

	/**
	 * Determines if this highlight provider is for the first listing of the ListingDiff.
	 * @return true if this provider's highlights are for the first listing. false if the
	 * highlights are for the second listing.
	 */
	public boolean isListing1() {
		return isListing1;
	}

	private class Pair {

		private int start;
		private int end;

		private Pair(int start, int end) {
			this.start = start;
			this.end = end;
		}
	}
}
