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
package docking.widgets.textfield;

import static docking.widgets.textfield.integer.IntegerFormat.*;

import java.math.BigInteger;

import docking.widgets.textfield.integer.AbstractIntegerTextField;
import docking.widgets.textfield.integer.IntegerFormat;

/**
 * TextField for entering integer numbers in one of several number formats. By default, this class
 * uses the {@link IntegerFormat#DEC} and the {@link IntegerFormat#HEX}, but it can be constructed
 * with any of the formats defined in {@link IntegerFormat}.
 *
 * <P>
 * This field does continuous checking, so you can't enter a bad value.
 *
 * <P>
 * Internally, values are maintained using BigIntegers so this field can contain numbers as large as
 * desired. There are convenience methods for getting the value as either an int or long. If using
 * these convenience methods, you should also set the max allowed value so that users can't enter a
 * value larger than can be represented by the {@link #getIntValue()} or {@link #getLongValue()}
 * methods as appropriate.
 *
 * <P>
 * There are several configuration options as follows:
 * <UL>
 * <LI>Max value - This value must be positive and will restrict the input to values less than or
 * equal to this value.</LI>
 * <LI>Min value - This value must be generally be negative and will restrict the input to values
 * greater than or equal to this value. As a special case, the min value can be set to 1.</LI>
 * <LI>Use number prefix - If this mode is on, then non-decimal values must be typed with its 
 * prefix(i.e., 0x for hex). When requiring non-decimal prefix, the field is permitted to auto
 * switch formats based on the prefix (or lack thereof). When the use prefix is off, the only way
 * to switch formats is to use the ctrl-M action.</LI>
 * <LI>Show the number mode as hint text - If showing number mode is on, the format short name
 * is displayed lightly in the bottom right portion of the text field.
 * See {@link #setShowNumberMode(boolean)}</LI>
 * </UL>
 *
 */

public class IntegerTextField extends AbstractIntegerTextField {
	private IntegerFormat hex;
	private IntegerFormat decimal;

	public IntegerTextField() {
		this(5, null);
	}

	public IntegerTextField(int columns) {
		this(columns, null);
	}

	public IntegerTextField(int columns, long initialValue) {
		this(columns, BigInteger.valueOf(initialValue));
	}

	public IntegerTextField(int columns, BigInteger initialValue) {
		super(columns, initialValue, DEC, HEX);
		decimal = allFormats.get(0);
		hex = allFormats.get(1);
	}

	@Override
	public void setMaxValue(BigInteger maxValue) {
		super.setMaxValue(maxValue);
	}

	@Override
	public void setMinValue(BigInteger minValue) {
		super.setMinValue(minValue);
	}

	/**
	 * Sets the radix mode to Hex.
	 *
	 * <P>
	 * If the field is currently in decimal mode, the current text will be change from displaying
	 * the current value from decimal to hex.
	 * @deprecated use {@link #setFormat(IntegerFormat)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public void setHexMode() {
		setFormat(hex);
	}

	/**
	 * Sets the mode to Decimal.
	 *
	 * <P>
	 * If the field is currently in hex mode, the current text will be change from displaying the
	 * current value from hex to decimal.
	 * @deprecated use {@link #setFormat(IntegerFormat)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public void setDecimalMode() {
		setFormat(decimal);
	}

	/**
	 * Returns true if in hex mode, false if in another mode.
	 *
	 * @return true if in hex mode, false if in decimal mode.
	 * @deprecated use {@link #getFormat()} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public boolean isHexMode() {
		return currentFormat == hex;
	}

	/**
	 * Sets whether on not the field supports the 0x prefix for hex numbers. This method is 
	 * deprecated since it now supports addition input modes other than hex or decimal. Turning
	 * the prefix on for hex will also turn it on for other non-decimal modes as well.
	 *
	 * <P>
	 * If 0x is supported, hex numbers will be displayed with the 0x prefix. Also, when typing, you
	 * must type 0x first to enter a hex number, otherwise it will only allow digits 0-9. If the 0x
	 * prefix option is turned off, then hex numbers are displayed without the 0x prefix and you
	 * can't change the decimal/hex mode by typing 0x. The field will either be in decimal or hex
	 * mode and the typed text will be interpreted appropriately for the mode.
	 *
	 * @param usePrefix true to use the 0x convention for hex.
	 * @deprecated use {@link #setUseNumberPrefix(boolean)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public void setAllowsHexPrefix(boolean usePrefix) {
		setUseNumberPrefix(usePrefix);
	}

	/**
	 * Sets whether or not negative numbers are accepted.
	 *
	 * @param b if true, negative numbers are allowed.
	 * @deprecated use {@link #setMinValue(BigInteger)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public void setAllowNegativeValues(boolean b) {
		BigInteger currentValue = getValue();
		setMinValue(b ? null : BigInteger.ZERO);
		if (!b) {
			if (currentValue != null && currentValue.signum() < 0) {
				currentValue = null;
			}
		}
		setValue(currentValue);
	}
}
