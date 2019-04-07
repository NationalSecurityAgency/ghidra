/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
 * address field display.
 */
public class AddressFieldOptionsWrappedOption implements CustomOption {
	private static final String PAD_WITH_ZEROS = "PadWithZeros";
	private static final String MIN_HEXL_DIGITS = "MinHexDigits";
	private static final String RIGHT_JUSTIFY = "RightJustify";
	private static final String SHOW_BLOCK_NAME = "ShowBlockName";

	private static final boolean DEFAULT_PAD_WITH_ZEROS = false;
	private static final boolean DEFAULT_SHOW_BLOCK_NAME = false;
	private static final boolean DEFAULT_RIGHT_JUSTIFY = true;
	private static final int DEFAULT_MIN_HEX_DIGITS = 8;

	// init with default values
	private boolean padWithZeros = DEFAULT_PAD_WITH_ZEROS;
	private boolean showBlockName = DEFAULT_SHOW_BLOCK_NAME;
	private boolean rightJustify = DEFAULT_RIGHT_JUSTIFY;
	private int minHexDigits = DEFAULT_MIN_HEX_DIGITS;

	public AddressFieldOptionsWrappedOption() {
		// required for persistence
	}

	public boolean padWithZeros() {
		return padWithZeros;
	}

	public int getMinimumHexDigits() {
		return minHexDigits;
	}

	public boolean rightJustify() {
		return rightJustify;
	}

	public boolean showBlockName() {
		return showBlockName;
	}

	public void setPadWithZeros(boolean padWithZeros) {
		this.padWithZeros = padWithZeros;
	}

	public void setMinimumHexDigits(int numDigits) {
		this.minHexDigits = numDigits;
	}

	public void setShowBlockName(boolean b) {
		showBlockName = b;
	}

	public void setRightJustify(boolean b) {
		rightJustify = b;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AddressFieldOptionsWrappedOption)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		AddressFieldOptionsWrappedOption otherOption = (AddressFieldOptionsWrappedOption) obj;
		return (padWithZeros == otherOption.padWithZeros) &&
			(minHexDigits == otherOption.minHexDigits) &&
			(rightJustify == otherOption.rightJustify) &&
			(showBlockName == otherOption.showBlockName);
	}

	@Override
	public int hashCode() {
		int prime = 31;
		int result = 1;
		result = prime * result + (padWithZeros ? 1 : 0);
		result = prime * result + (rightJustify ? 1 : 0);
		result = prime * result + (showBlockName ? 1 : 0);
		result = prime * result + minHexDigits;
		return result;
	}

//==================================================================================================
// Persistence
//==================================================================================================
	@Override
	public void readState(SaveState saveState) {
		padWithZeros = saveState.getBoolean(PAD_WITH_ZEROS, padWithZeros);
		minHexDigits = saveState.getInt(MIN_HEXL_DIGITS, minHexDigits);
		rightJustify = saveState.getBoolean(RIGHT_JUSTIFY, rightJustify);
		showBlockName = saveState.getBoolean(SHOW_BLOCK_NAME, showBlockName);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putBoolean(PAD_WITH_ZEROS, padWithZeros);
		saveState.putInt(MIN_HEXL_DIGITS, minHexDigits);
		saveState.putBoolean(RIGHT_JUSTIFY, rightJustify);
		saveState.putBoolean(SHOW_BLOCK_NAME, showBlockName);
	}
}
