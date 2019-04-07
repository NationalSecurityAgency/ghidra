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
package ghidra.app.util.html.diff;

import java.util.List;

import ghidra.app.util.html.*;
import ghidra.util.exception.AssertException;

public class DataTypeDiffBuilder {

	/**
	 * HACK: for some reason when opening the HTML document with '&#47;', all text until the
	 * next HTML tag is not displayed.  So, we put in a dummy tag and all is well.
	 * Java 1.5.0_12
	 */
	protected static final String EMPTY_TAG = "<I></I>";
	protected static final String BR = "<BR>";

	private DataTypeDiffBuilder() {
		// no; factory
	}

	public static DataTypeDiff diffLines(DataTypeDiffInput left, DataTypeDiffInput right) {
		DiffLines leftLines = new DiffLines(left);
		DiffLines rightLines = new DiffLines(right);

		padLines(leftLines, rightLines);

		highlightDiffLineDiferences(leftLines, rightLines);

		return new DataTypeDiff(leftLines, rightLines);
	}

	public static DataTypeDiff diffHeader(DataTypeDiffInput left, DataTypeDiffInput right) {

		DataTypeDiff result = diffLines(left, right);
		return result;
	}

	public static void padLines(DiffLines leftLines, DiffLines rightLines) {
		int length = leftLines.size();
		int otherLength = rightLines.size();

		if (length == otherLength) {
			return;
		}

		int maxLength = Math.max(length, otherLength);
		for (int i = 0; i < maxLength; i++) {
			// special case (see docs for EMPTY_TAG)
			String paddingText = (i == 0) ? EMPTY_TAG : BR;

			if (i >= length) {
				leftLines.add(new TextLine(paddingText));
			}
			else if (i >= otherLength) {
				rightLines.add(new TextLine(paddingText));
			}
		}

	}

	public static DataTypeDiff diffBody(DataTypeDiffInput left, DataTypeDiffInput right) {

		DiffLinesValidator leftDiff = new DiffLinesValidator(left, true);
		DiffLinesValidator rightDiff = new DiffLinesValidator(right, false);

		alignRows(leftDiff, rightDiff);

		DiffLines leftLines = leftDiff.getValidatedLines();
		DiffLines rightLines = rightDiff.getValidatedLines();

		removeExcessEmptyRows(leftLines, rightLines);

		return new DataTypeDiff(leftLines, rightLines);
	}

	/** walk both lists, processing the lines and adding blank lines to align the data */
	private static void alignRows(DiffLinesValidator leftValidator,
			DiffLinesValidator rightValidator) {

		while (!leftValidator.isDone() || !rightValidator.isDone()) {
			// process the next line in the first list
			validateNextLine(leftValidator, rightValidator);
			validateNextLine(rightValidator, leftValidator);
		}
	}

	private static void validateNextLine(DiffLinesValidator validator1,
			DiffLinesValidator validator2) {
		if (validator1.isDone()) {
			return;
		}

		ValidatableLine line1 = validator1.getLine();
		if (line1 == null) { // null means no lines or nothing left but empty lines
			return;
		}

		ValidatableLine line2 = validator2.getLine();
		if (line2 == null) { // the other state is shorter than this one and has run out of lines
			PlaceHolderLine placeholder =
				validator2.insertMismatchPlaceholder(validator2.getMarkerPosition(), line1);

			line1.setValidationLine(placeholder);
			validator1.increment(); // done with this line, move the state forward
			return;
		}

		if (line1.matches(line2)) {

			line1.setValidationLine(line2);

			// since they matched, mark the other line as valid too
			validator2.increment();
			validator1.increment();
			return;
		}

		//
		// No match at the current position; we need to decide if there is any match...
		//
		Integer list2MatchForLine1 = findNextMatch(validator1, line1, validator2);
		if (list2MatchForLine1 != null) {

			ValidatableLine match = validator2.getLine(list2MatchForLine1);
			line1.setValidationLine(match);

			// ...there is an upcoming match; that match will be handled later; mark this line done
			validator1.increment();
			return;
		}

		Integer list1MatchForLine2 = findNextMatch(validator2, line2, validator1);
		if (list1MatchForLine2 == null) {
			// neither line has a match in the other list, treat them as 
			// two different values in the same position			
			line1.setValidationLine(line2);
			validator2.increment();
		}
		else {
			// list 1 has a match for line2, so they will sync up later
			PlaceHolderLine placeholder =
				validator2.insertMismatchPlaceholder(validator1.getMarkerPosition(), line1);

			line1.setValidationLine(placeholder);
		}

		validator1.increment(); // done with this line, move the state forward
	}

	/**
	 * Returns a line that matches the given line that occurs later in the 'other' validator; 
	 * returns null if no suitable match is found.
	 * 
	 * @param source the validator that has a line which needs matching
	 * @param sourceLine the line that needs matching
	 * @param other the validator in which to find a match for the given line
	 * @return a line that matches the given line that occurs later in the 'other' validator; 
	 * 		   returns null if no suitable match is found.
	 */
	private static Integer findNextMatch(DiffLinesValidator source, ValidatableLine sourceLine,
			DiffLinesValidator other) {

		//
		// The goal of this method is to find a match for the line from the source structure in
		// the other structure.  Further, we are trying to match an item that was pushed down due
		// to a user inserting a new item into the structure.  We do NOT want to match the 
		// case when the user changed an item.  In that case, there is no logical match, but there
		// may be other matching items in the list (which we do not want).  We assume that matching
		// lines at the same offset is a signal that the given item we seek can not exists.
		//

		/*
		 
		 	Good Match:    
		 	
			 	struct 1 {
			 		byte
			 		int
			 		byte
			 	}
			 	
			 	struct 1.1 {
			 		word
			 		byte
			 		int
			 		byte
			 	}
		 	
			source - struct 1
			source line - the first 'byte'
			other - struct 1.1
			
			result: there should be a match for the 'byte' at index 1 in 'struct 1.1'
			
			
			Bad Match:
			
				struct 1 {
			 		byte
			 		int
			 		byte
			 	}
			 	
			 	struct 1.1 {
			 		word
			 		int
			 		byte
			 	}
		 	
			source - struct 1
			source line - the first 'byte'
			other - struct 1.1
			
			result: there should NOT be a match for the 'byte' at index 2 in 'struct 1.1'; rather
			        the eventual pairing for the diff algorithm will be for struct 1[0] to 
			        struct 1.1[0], from 'byte' -> 'word'
		 	
		 
		 */

		Integer index = other.findNextMatch(sourceLine);
		if (index == null) {
			return null; // no other match for the item at all in the list
		}

		//
		// Starting after the index of the current line, see if there is a match in the structures,
		// at the same index.  If so, then we don't want to use the match from another 
		// offset that we found above.
		//
		int start = source.indexOf(sourceLine) + 1;
		int end = Math.min(source.size(), index);
		for (int i = start; i < end; i++) {
			ValidatableLine nextOther = other.getLine(i);
			ValidatableLine nextSource = source.getLine(i);

			if (nextSource.matches(nextOther)) {
				return null;
			}
		}

		return index;
	}

	/** Removes empty rows that are no longer necessary for alignment (it may add new empty rows) */
	private static void removeExcessEmptyRows(DiffLines leftLines, DiffLines rightLines) {

		DiffLines newLeftLines = leftLines.createEmptyClone();
		DiffLines newRightLines = rightLines.createEmptyClone();

		leftLines.removeLeadingEmptyRows();
		rightLines.removeLeadingEmptyRows();

		// 
		// For the lists, condense areas with empty rows by adjusting the blocks with empty rows
		// so that the empty rows are at the bottom.  This seems to be aesthetically more pleasing
		// when viewing the diff.
		// 
		int end = Math.min(leftLines.size(), rightLines.size());
		condenseSharedRange(leftLines, rightLines, newLeftLines, newRightLines, 0, end);

		// handle remaining list elements from the longer list
		copyRealLines(leftLines, newLeftLines, end);
		copyRealLines(rightLines, newRightLines, end);

		// reset the contents with the new layout
		leftLines.installNewLines(newLeftLines);
		rightLines.installNewLines(newRightLines);
	}

	private static void condenseSharedRange(DiffLines left, DiffLines right, DiffLines newLeft,
			DiffLines newRight, int start, int end) {

		for (int i = start; i < end; i++) {
			ValidatableLine line1 = left.get(i);
			ValidatableLine line2 = right.get(i);

			if (line1.matches(line2)) {
				copyLine(left, newLeft, i);
				copyLine(right, newRight, i);
				continue;
			}

			int endOfRange = findEndOfDistinctLines(left, right, i);
			condenseSubRange(left, right, newLeft, newRight, i, endOfRange);

			// setup the next range match
			i = endOfRange - 1; // -1 since endOfRange is exclusive
		}
	}

	private static int findEndOfDistinctLines(DiffLines left, DiffLines right, int start) {
		int end = Math.min(left.size(), right.size());
		for (int i = start; i < end; i++) {
			ValidatableLine line1 = left.get(i);
			ValidatableLine line2 = right.get(i);

			if (line1.matches(line2)) {
				return i;
			}
		}
		return end;
	}

	/** 
	 * Copies from the source to the destination all lines that are not placeholders.  If the 
	 * two input lists are not the same after the copy, then the smaller list is padded with
	 * placeholder lines.
	 */
	private static void condenseSubRange(DiffLines leftSource, DiffLines rightSource,
			DiffLines leftDestination, DiffLines rightDestination, int start, int end) {

		int safeEndIndex = Math.min(end, leftSource.size());
		copyRealLines(leftSource, leftDestination, start, safeEndIndex);

		safeEndIndex = Math.min(end, rightSource.size());
		copyRealLines(rightSource, rightDestination, start, safeEndIndex);

		padSmaller(leftDestination, rightDestination);
	}

	private static void copyLine(DiffLines from, DiffLines to, int index) {
		ValidatableLine line = from.get(index);
		if (line instanceof PlaceHolderLine) {
			throw new AssertException(
				"copyLine() is meant to copy only real lines, not placeholders");
		}
		to.add(line);
	}

	private static void copyRealLines(DiffLines from, DiffLines to, int offset) {
		copyRealLines(from, to, offset, from.size());
	}

	private static void copyRealLines(DiffLines from, DiffLines to, int start, int end) {

		for (int i = start; i < end; i++) {
			ValidatableLine line = from.get(i);
			if (line instanceof PlaceHolderLine) {
				// the final list only has placeholders in between items, not at the end
				continue;
			}

			to.add(line);
		}
	}

	private static void padSmaller(DiffLines leftDestination, DiffLines rightDestination) {

		// for the bigger list, we need to pad, for the other, we don't need the empty rows        
		DiffLines smallerList = null;
		DiffLines largerList = null;

		int sizeDifference = 0;
		int length = Math.min(leftDestination.size(), rightDestination.size());
		if (leftDestination.size() == length) {
			smallerList = leftDestination;
			largerList = rightDestination;
			sizeDifference = rightDestination.size() - leftDestination.size();
		}
		// right is the small list
		else {
			smallerList = rightDestination;
			largerList = leftDestination;
			sizeDifference = leftDestination.size() - rightDestination.size();
		}

		for (int i = 0; i < sizeDifference; i++) {
			int size = smallerList.size();

			// get the line opposite of the empty line we are adding
			ValidatableLine oppositeLine = largerList.get(size);
			smallerList.insertPlaceholder(oppositeLine);
		}
	}

	private static void highlightDiffLineDiferences(DiffLines left, DiffLines right) {
		highlightDifferences(left, right);
	}

	public static void highlightDifferences(List<ValidatableLine> left,
			List<ValidatableLine> right) {

		if (left.size() != right.size()) {
			// update this method to handle different sizes if there is a use case (see the
			// history)
			throw new IllegalArgumentException("Line list size must be the same");
		}

		int sharedLength = Math.min(left.size(), right.size());
		for (int i = 0; i < sharedLength; i++) {
			ValidatableLine line = left.get(i);
			ValidatableLine otherLine = right.get(i);

			line.setValidationLine(otherLine);
		}
	}
}
