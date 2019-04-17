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

import static ghidra.program.util.string.FoundString.DefinedState.DEFINED;

import java.util.Iterator;

import ghidra.program.model.listing.*;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.util.string.FoundString;

/**
 * Class to find and iterate over existing defined strings even if they are
 * in arrays or structures.  It recursively descends into arrays and structures looking
 * for strings.
 * <p>
 * Basic Algorithm: Uses a defined data iterator to find all defined data in a program.  For
 * each defined data, strings are searched as follows:
 * <ol>
 *   <li> is it a string?  if so, add to the queue of results
 *   <li> is it an array?  if so, are they non-primitive elements?  if so, recursively search them for strings.
 *   <li> is it a composite (structure or union)? if so, recursively search each element of the structure.
 * </ol>
 * <p>
 * This class maintains a queue of all strings found at any given top-level data element.  When
 * the queue is empty, it uses the defined data iterator to find the next top-level data element, filling
 * the resultQueue with any string found by recursively searching that data element.
 * <p>
 * The iterator is over when the resultQueue is empty and the defined data iterator's hasNext() method is false.
 */
public class DefinedStringIterator implements Iterator<FoundString> {

	private boolean isWordModelInitialized;
	private DataIterator stringDataIterator;
	private Program program;

	DefinedStringIterator(Program program, boolean isWordModelInitialized) {
		this.program = program;
		this.isWordModelInitialized = isWordModelInitialized;
		this.stringDataIterator = DefinedDataIterator.definedStrings(program);
	}

	@Override
	public boolean hasNext() {
		return stringDataIterator.hasNext();
	}

	@Override
	public FoundString next() {
		Data data = stringDataIterator.next();
		return createFoundString(data);
	}

	private FoundString createFoundString(Data data) {
		if (isWordModelInitialized) {
			FoundStringWithWordStatus result = new FoundStringWithWordStatus(data.getAddress(),
				data.getLength(), data.getBaseDataType(), DEFINED);
			setIsWordStatus(result);
			return result;
		}
		return new FoundString(data.getAddress(), data.getLength(), data.getBaseDataType(),
			DEFINED);
	}

	/**
	 * Uses the StringsAnalyzer model to determine if the given string is a high confidence word.
	 */
	private void setIsWordStatus(FoundStringWithWordStatus foundString) {
		String string = foundString.getString(program.getMemory());
		if (string == null) {
			foundString.setIsHighConfidenceWord(false);
			return;
		}

		StringAndScores candidateString =
			new StringAndScores(string, NGramUtils.isLowerCaseModel());

		// Don't bother continuing if string length is shorter than model's absolute min length
		if (candidateString.getScoredStringLength() >= NGramUtils.getMinimumStringLength()) {
			NGramUtils.scoreString(candidateString);
			foundString.setIsHighConfidenceWord(candidateString.isScoreAboveThreshold());
		}
	}
}
