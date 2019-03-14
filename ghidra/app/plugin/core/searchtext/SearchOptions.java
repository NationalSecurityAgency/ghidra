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

/**
 * Simple class to hold options for searching the text in Program.
 */
public class SearchOptions implements Cloneable {

	private final String text;
	private final boolean functions;
	private final boolean comments;
	private final boolean labels;
	private final boolean instructionMnemonics;
	private final boolean instructionOperands;
	private final boolean dataMnemonics;
	private final boolean dataOperands;
	private final boolean caseSensitive;
	private final boolean direction; // true --> Forward; false --> Backward
	private final boolean searchAll; // true --> search all the fields
	private final boolean includeNonLoadedBlocks;

	/** true --> do the search of the program database, vs. a string search of the fields */
	private final boolean databaseSearch;
	private int progress; // state information for progress

	/**
	 * Constructor
	 * @param text string to match 
	 * @param functions true to search for function text
	 * @param comments true to search comments
	 * @param labels true to search labels
	 * @param instructionsMnemonic true to search instruction mnemonics
	 * @param instructionsOperand true to search instruction operands
	 * @param dataMnemonic true to search data mnemonics
	 * @param dataValue true to search data values
	 * @param caseSensitive true if search is to be case sensitive
	 * @param direction true means forward, false means backward search 
	 */
	public SearchOptions(String text, boolean quickSearch, boolean functions, boolean comments,
			boolean labels, boolean instructionMnemonics, boolean instructionOperands,
			boolean dataMnemonics, boolean dataOperands, boolean caseSensitive, boolean direction,
			boolean includeNonLoadedBlocks, boolean searchAll) {
		this.text = text;
		this.databaseSearch = quickSearch;
		this.functions = functions;
		this.comments = comments;
		this.labels = labels;
		this.instructionMnemonics = instructionMnemonics;
		this.instructionOperands = instructionOperands;
		this.dataMnemonics = dataMnemonics;
		this.dataOperands = dataOperands;
		this.caseSensitive = caseSensitive;
		this.direction = direction;
		this.searchAll = searchAll;
		this.includeNonLoadedBlocks = includeNonLoadedBlocks;
	}

	/**
	 * Constructor used when all fields should be searched. The direction
	 * is forward.
	 * @param text string to match
	 */
	SearchOptions(String text, boolean caseSensitive, boolean direction,
			boolean includeNonLoadedBlocks) {
		this(text, false, false, false, false, false, false, false, false, caseSensitive,
			direction, includeNonLoadedBlocks, true);
	}

	/**
	 * Get the text that is the pattern to search for.
	 */
	public String getText() {
		return text;
	}

	/**
	 * Return true if functions should be searched/
	 */
	public boolean searchFunctions() {
		return functions;
	}

	/**
	 * Return true if labels should be searched.
	 */
	public boolean searchLabels() {
		return labels;
	}

	/**
	 * Return true if comments should be searched.
	 */
	public boolean searchComments() {
		return comments;
	}

	/**
	 * Return true if instruction mnemonics should be searched.
	 */
	public boolean searchBothInstructionMnemonicAndOperands() {
		return instructionMnemonics & instructionOperands;
	}

	public boolean searchInstructionMnemonics() {
		return instructionMnemonics;
	}

	public boolean searchInstructionOperands() {
		return instructionOperands;
	}

	public boolean searchOnlyInstructionMnemonics() {
		return instructionMnemonics && !instructionOperands;
	}

	public boolean searchOnlyInstructionOperands() {
		return instructionOperands && !instructionMnemonics;
	}

	/**
	 * Return true if data mnemonics should be searched.
	 */
	public boolean searchBothDataMnemonicsAndOperands() {
		return dataMnemonics & dataOperands;
	}

	public boolean searchDataMnemonics() {
		return dataMnemonics;
	}

	public boolean searchDataOperands() {
		return dataOperands;
	}

	public boolean searchOnlyDataMnemonics() {
		return dataMnemonics && !dataOperands;
	}

	public boolean searchOnlyDataOperands() {
		return dataOperands && !dataMnemonics;
	}

	/**
	 * Return true is search should be case sensitive.
	 */
	public boolean isCaseSensitive() {
		return caseSensitive;
	}

	/**
	 * Return true if search is being done in the forward direction.
	 */
	public boolean isForward() {
		return direction;
	}

	boolean searchAllFields() {
		return searchAll;
	}

	boolean includeNonLoadedMemoryBlocks() {
		return includeNonLoadedBlocks;
	}

	/**
	 * Return whether the quick search option is on.
	 */
	boolean isProgramDatabaseSearch() {
		return databaseSearch;
	}

	/**
	 * Set the progress value; used in subsequent searches to update the
	 * monitor.
	 * @param progress
	 */
	void setProgress(int progress) {
		this.progress = progress;
	}

	/**
	 * Get the progress value to add on to it for updating the progress in
	 * the search monitor.
	 * @return
	 */
	int getProgress() {
		return progress;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (caseSensitive ? 1231 : 1237);
		result = prime * result + (comments ? 1231 : 1237);
		result = prime * result + (dataMnemonics ? 1231 : 1237);
		result = prime * result + (dataOperands ? 1231 : 1237);
		result = prime * result + (direction ? 1231 : 1237);
		result = prime * result + (functions ? 1231 : 1237);
		result = prime * result + (instructionMnemonics ? 1231 : 1237);
		result = prime * result + (instructionOperands ? 1231 : 1237);
		result = prime * result + (labels ? 1231 : 1237);
		result = prime * result + (databaseSearch ? 1231 : 1237);
		result = prime * result + (searchAll ? 1231 : 1237);
		result = prime * result + ((text == null) ? 0 : text.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SearchOptions other = (SearchOptions) obj;
		if (caseSensitive != other.caseSensitive)
			return false;
		if (comments != other.comments)
			return false;
		if (dataMnemonics != other.dataMnemonics)
			return false;
		if (dataOperands != other.dataOperands)
			return false;
		if (direction != other.direction)
			return false;
		if (functions != other.functions)
			return false;
		if (instructionMnemonics != other.instructionMnemonics)
			return false;
		if (instructionOperands != other.instructionOperands)
			return false;
		if (labels != other.labels)
			return false;
		if (databaseSearch != other.databaseSearch)
			return false;
		if (searchAll != other.searchAll)
			return false;
		if (text == null) {
			if (other.text != null)
				return false;
		}
		else if (!text.equals(other.text))
			return false;
		return true;
	}
}
