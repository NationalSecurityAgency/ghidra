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

import ghidra.app.util.html.PlaceHolderLine;
import ghidra.app.util.html.ValidatableLine;
import ghidra.util.exception.AssertException;

import java.util.ArrayList;
import java.util.List;

/**
 * A class that knows how to traverse a set a lines that are being used to generate a diff.
 */
class DiffLinesValidator {
	private final List<ValidatableLine> myLines;
	private int marker = 0;
	private DataTypeDiffInput input;
	private boolean isLeft;

	DiffLinesValidator(DataTypeDiffInput input, boolean isLeft) {
		this.input = input;
		this.isLeft = isLeft;
		this.myLines = new ArrayList<>(input.getLines());
	}

	DiffLines getValidatedLines() {
		if (!isDone()) {
			throw new AssertException("Cannot get validated lines before validation is finished");
		}

		return new DiffLines(input, myLines);
	}

	@Override
	public String toString() {
		return "Diff Validator (" + (isLeft ? "left" : "right") + ")\n" + toString(myLines);
	}

	private String toString(List<?> list) {
		StringBuffer buffer = new StringBuffer("[ ");
		for (int i = 0; i < list.size(); i++) {
			buffer.append(markup(i, list.get(i).toString()));
			if (i + 1 < list.size()) {
				buffer.append(", ");
			}
		}

		buffer.append(" ]");
		return buffer.toString();
	}

	private String markup(int lineNumber, String string) {
		if (lineNumber != marker) {
			return string;
		}

		String flag = " ****** ";
		String[] lines = string.split("\n");
		StringBuilder buffy = new StringBuilder();
		for (String line : lines) {
			if (line.trim().isEmpty()) {
				buffy.append(line).append('\n'); // whitespace
				continue;
			}
			buffy.append(flag).append(line).append(flag).append('\n');
			flag = "        ";
		}

		return buffy.toString();
	}

	PlaceHolderLine insertMismatchPlaceholder(int index, ValidatableLine oppositeLine) {
		PlaceHolderLine placeHolder = input.createPlaceHolder(oppositeLine);
		insertLine(index, placeHolder);
		return placeHolder;
	}

	private <T extends ValidatableLine> void insertLine(int markerPosition, ValidatableLine line) {
		myLines.add(markerPosition, line);
	}

	int getMarkerPosition() {
		return marker;
	}

	/** 
	 * Push forward the current marker position.  The marker starts at the beginning and 
	 * only moves forward past validated lines.
	 */
	public void increment() {
		marker++;

		// keep walking our list until we find an unvalidated line
		while (marker < myLines.size()) {
			ValidatableLine line = myLines.get(marker);
			if (!line.isValidated()) {
				return;
			}
			marker++;
		}
	}

	ValidatableLine getLine() {
		while (marker < myLines.size()) {
			ValidatableLine line = myLines.get(marker);
			if (!(line instanceof PlaceHolderLine)) {
				return line;
			}
			if (!line.isValidated()) {
				return line;
			}
			marker++; // skip over place holder lines
		}

		return null;
	}

	Integer findNextMatch(ValidatableLine line) {
		int searchPosition = 0;
		while (searchPosition < myLines.size()) {
			ValidatableLine myNextLine = myLines.get(searchPosition);
			if (line.matches(myNextLine)) {
				return searchPosition;
			}
			searchPosition++;
		}
		return null;
	}

	boolean isDone() {
		return marker >= myLines.size();
	}

	ValidatableLine getLine(int index) {
		return myLines.get(index);
	}

	int indexOf(ValidatableLine sourceLine) {
		return myLines.indexOf(sourceLine);
	}

	int size() {
		return myLines.size();
	}
}
