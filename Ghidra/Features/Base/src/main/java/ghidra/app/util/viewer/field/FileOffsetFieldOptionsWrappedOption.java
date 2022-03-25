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
package ghidra.app.util.viewer.field;

import ghidra.framework.options.CustomOption;
import ghidra.framework.options.SaveState;

/**
* An option class that allows the user to edit a related group of options pertaining to
* File Offset field display
*/
public class FileOffsetFieldOptionsWrappedOption implements CustomOption {

	private static final String SHOW_FILENAME = "ShowFilename";
	private static final String USE_HEX = "UseHex";

	private static final boolean DEFAULT_SHOW_FILENAME = false;
	private static final boolean DEFAULT_USE_HEX = true;

	private boolean showFilename = DEFAULT_SHOW_FILENAME;
	private boolean useHex = DEFAULT_USE_HEX;

	/**
	 * Default constructor, required for persistence
	 */
	public FileOffsetFieldOptionsWrappedOption() {
	}

	/**
	 * Returns whether or not to show the filename
	 * 
	 * @return True if the filename is to be shown; otherwise, false
	 */
	public boolean showFilename() {
		return showFilename;
	}

	/**
	 * Sets whether or not to show the filename
	 * 
	 * @param showFilename True to show the filename, false to hide it
	 */
	public void setShowFilename(boolean showFilename) {
		this.showFilename = showFilename;
	}

	/**
	 * Returns whether or not to display the file offset in hexadecimal
	 * 
	 * @return True if the file offset is to be displayed in hexadecimal; otherwise, false
	 */
	public boolean useHex() {
		return useHex;
	}

	/**
	 * Sets whether or not to display the file offset in hexadecimal
	 * 
	 * @param useHex True to display the file offset in hexadecimal, false for decimal
	 */
	public void setUseHex(boolean useHex) {
		this.useHex = useHex;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof FileOffsetFieldOptionsWrappedOption)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		FileOffsetFieldOptionsWrappedOption otherOption = (FileOffsetFieldOptionsWrappedOption) obj;
		return showFilename == otherOption.showFilename && useHex == otherOption.useHex;
	}

	@Override
	public int hashCode() {
		int prime = 31;
		int result = 1;
		result = prime * result + (showFilename ? 1 : 0);
		result = prime * result + (useHex ? 1 : 0);
		return result;
	}

//==================================================================================================
//Persistence
//==================================================================================================
	@Override
	public void readState(SaveState saveState) {
		showFilename = saveState.getBoolean(SHOW_FILENAME, showFilename);
		useHex = saveState.getBoolean(USE_HEX, useHex);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putBoolean(SHOW_FILENAME, showFilename);
		saveState.putBoolean(USE_HEX, useHex);
	}
}
