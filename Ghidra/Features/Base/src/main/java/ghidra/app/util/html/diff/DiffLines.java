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

import java.util.*;

/**
 * A class that holds lines that will be used to generate diffs.  It also has a reference to 
 * the source of the data so that it can create the correct type of empty lines as needed.
 */
public class DiffLines extends ArrayList<ValidatableLine> {

	private DataTypeDiffInput input;

	public DiffLines(DataTypeDiffInput input) {
		this.input = input;
		this.addAll(input.getLines());
	}

	public DiffLines(DataTypeDiffInput input, List<ValidatableLine> validatedLines) {
		this.input = input;
		this.addAll(validatedLines);
	}

	void removeLeadingEmptyRows() {
		Iterator<ValidatableLine> iterator = iterator();
		for (; iterator.hasNext();) {
			ValidatableLine line = iterator.next();
			if (line instanceof PlaceHolderLine) {
				iterator.remove();
			}
			else {
				return; // stop at the first real line
			}
		}
	}

	DiffLines createEmptyClone() {
		return new DiffLines(input, new ArrayList<ValidatableLine>());
	}

	/** Replace the content of this diff with the given content */
	void installNewLines(DiffLines newLines) {
		if (input != newLines.input) {
			throw new AssertException(
				"Can only install new diff lines from a clone of the original");
		}

		clear();
		addAll(newLines);
	}

	private PlaceHolderLine createPlaceHolderLine(ValidatableLine oppositeLine) {
		return input.createPlaceHolder(oppositeLine);
	}

	void insertPlaceholder(ValidatableLine oppositeLine) {
		insertPlaceholder(size(), oppositeLine);
	}

	void insertPlaceholder(int index, ValidatableLine oppositeLine) {
		add(index, createPlaceHolderLine(oppositeLine));
	}

	@Override
	public String toString() {
		StringBuilder buffy = new StringBuilder("[\n");
		for (ValidatableLine line : this) {
			buffy.append(line.toString()).append('\n');
		}
		buffy.append(']');
		return buffy.toString();
	}
}
