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
package docking.widgets.textfield.integer;

import java.math.BigInteger;

import docking.widgets.textfield.FixedSizeIntegerTextField;
import docking.widgets.textfield.IntegerTextField;

/**
 * Input formats for entering integers into a text field such as the {@link IntegerTextField} or
 * {@link FixedSizeIntegerTextField}
 */
public enum IntegerFormat {
	DEC("Dec", "decimal", "", 10, false),
	HEX("Hex", "hexadecimal", "0x", 16, false),
	OCT("Oct", "octal", "0O", 8, false),
	BIN("Bin", "binary", "0b", 2, false),

	U_DEC("uDec", "unsigned decimal", "", 10, true),
	U_HEX("uHex", "unsigned hexadecimal", "0x", 16, true),
	U_OCT("uOct", "unsigned octal", "0O", 8, true),
	U_BIN("uBin", "unsigned binary", "0b", 2, true);

	private String name;
	private String longName;
	private String prefix;
	private int radix;
	private boolean isUnsigned;

	private IntegerFormat(String name, String description, String prefix, int radix,
			boolean isUnsigned) {
		this.name = name;
		this.longName = description;
		this.prefix = prefix;
		this.radix = radix;
		this.isUnsigned = isUnsigned;
	}

	/**
	 * {@return the short name of this number format}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return a descriptive name of this number format}
	 */
	public String getDescription() {
		return longName;
	}

	/**
	 * Converts the given value into a string representation corresponding to this number format.
	 * @param value the value to format into a string
	 * @return A string representation of the given value.
	 */
	public String format(BigInteger value) {
		return value.toString(radix);
	}

	/**
	 * Parses the given string into a BigInteger or null if the string is not properly structured
	 * for this number format.
	 * @param text the text to parse into a BigInteger
	 * @return the BigInteger interpretation of the given string for this number format.
	 */
	public BigInteger parse(String text) {
		try {
			return new BigInteger(text, radix);
		}
		catch (NumberFormatException e) {
			// failed to parse, return null
		}
		return null;
	}

	/**
	 * {@return the prefix associated with this format} 
	 */
	public String getPrefix() {
		return prefix;
	}

	/**
	 * Return true if this format is intended only for non-negative values. This is more of a hint
	 * to the client text field to determine if "-" characters are allowed to be entered. 
	 * @return true if this format is for unsigned numbers
	 */
	public boolean isUnsigned() {
		return isUnsigned;
	}
}
