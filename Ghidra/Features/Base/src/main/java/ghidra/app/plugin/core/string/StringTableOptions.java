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

import ghidra.program.model.address.AddressSetView;

public class StringTableOptions {
	private int minStringSize = 5;
	private int alignment = 1;
	private boolean includeAllCharSizes = true;
	private boolean nullTerminationRequired = true;
	private boolean includeUndefinedStrings = true;
	private boolean includeDefinedStrings = true;
	private boolean onlyShowWordStrings = false;
	private AddressSetView addressSet = null;
	private boolean requirePascal = false;
	private boolean includePartiallyDefinedStrings = true;
	private boolean includeConflictingStrings = true;
	private String wordModelFile = "";
	private boolean wordModelInitialized = false;
	private boolean loadedBlocksOnly = false;

	public boolean useLoadedBlocksOnly() {
		return loadedBlocksOnly;
	}

	public void setUseLoadedBlocksOnly(boolean loadedBlocksOnly) {
		this.loadedBlocksOnly = loadedBlocksOnly;
	}

	public int getMinStringSize() {
		return minStringSize;
	}

	public int getAlignment() {
		return alignment;
	}

	public boolean getIncludeAllCharSizes() {
		return includeAllCharSizes;
	}

	public String getWordModelFile() {
		return wordModelFile;
	}

	public boolean getWordModelInitialized() {
		return wordModelInitialized;
	}

	public boolean isNullTerminationRequired() {
		return nullTerminationRequired;
	}

	public boolean includeUndefinedStrings() {
		return includeUndefinedStrings;
	}

	public boolean includeDefinedStrings() {
		return includeDefinedStrings;
	}

	public boolean includePartiallyDefinedStrings() {
		return includePartiallyDefinedStrings;
	}

	public boolean includeConflictingStrings() {
		return includeConflictingStrings;
	}

	public boolean onlyShowWordStrings() {
		return onlyShowWordStrings;
	}

	public void setNullTerminationRequired(boolean required) {
		nullTerminationRequired = required;
	}

	public void setMinStringSize(int minStringSize) {
		this.minStringSize = minStringSize;
	}

	public void setAlignment(int alignment) {
		this.alignment = alignment;
	}

	public void setIncludeAllCharSizes(boolean includeAllCharSizes) {
		this.includeAllCharSizes = includeAllCharSizes;
	}

	public void setIncludeUndefinedStrings(boolean includeUndefinedStrings) {
		this.includeUndefinedStrings = includeUndefinedStrings;
	}

	public void setIncludeDefinedStrings(boolean includeDefinedStrings) {
		this.includeDefinedStrings = includeDefinedStrings;
	}

	public void setOnlyShowWordStrings(boolean onlyShowWordStrings) {
		this.onlyShowWordStrings = onlyShowWordStrings;
	}

	public AddressSetView getAddressSet() {
		return addressSet;
	}

	public void setAddressSet(AddressSetView addressSet) {
		this.addressSet = addressSet;
	}

	public void setRequirePascal(boolean requirePascal) {
		this.requirePascal = requirePascal;
	}

	public boolean isPascalRequired() {
		return requirePascal;
	}

	public void setIncludePartiallyDefinedStrings(boolean includePartiallyDefinedStrings) {
		this.includePartiallyDefinedStrings = includePartiallyDefinedStrings;
	}

	public void setIncludeConflictingStrings(boolean includeConflictingStrings) {
		this.includeConflictingStrings = includeConflictingStrings;
	}

	public void setWordModelFile(String wordModelFile) {
		this.wordModelFile = wordModelFile;
	}

	public void setWordModelInitialized(boolean wordModelInitialized) {
		this.wordModelInitialized = wordModelInitialized;
	}

	public StringTableOptions copy() {
		StringTableOptions options = new StringTableOptions();
		options.setMinStringSize(minStringSize);
		options.setAddressSet(addressSet);
		options.setAlignment(alignment);
		options.setRequirePascal(requirePascal);
		options.setNullTerminationRequired(nullTerminationRequired);
		options.setIncludeAllCharSizes(includeAllCharSizes);
		options.setIncludeConflictingStrings(includeConflictingStrings);
		options.setIncludeUndefinedStrings(includeUndefinedStrings);
		options.setIncludeDefinedStrings(includeDefinedStrings);
		options.setIncludePartiallyDefinedStrings(includePartiallyDefinedStrings);
		options.setOnlyShowWordStrings(onlyShowWordStrings);
		options.setWordModelFile(wordModelFile);
		options.setWordModelInitialized(wordModelInitialized);

		return options;
	}
}
