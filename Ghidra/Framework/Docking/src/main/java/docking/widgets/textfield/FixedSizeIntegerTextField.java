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
 * TextField for entering numbers where the values are restricted to those that can be represented
 * by a specific number of bits. For example, if the bit size is eight, signed values
 * must be between -128 and 127 and unsigned values must be between 0 and 255. By
 * default, this class uses all the formats from the {@link IntegerFormat} enum class except for
 * signed octal and signed binary. 
 *
 * <P>
 * This field does continuous checking, so you can't enter a bad value.
 *<P>
 * The bitSize can be changed on this field which will cause its min and max values to change to
 * the appropriate values for that bit size and signedness of the current {@link IntegerFormat}.
 * Also, if the current value doesn't fit in the new bit size, it will be reset to having no
 * value (textfield is blank).
 * <P>
 * Internally, values are maintained using BigIntegers so this class can accommodate any bit size
 * desired. There are convenience methods for getting the value as either an int or long. You 
 * should only use these convenience methods if you know the current bit size fits in either a 
 * int or long respectively.
 *
 * <P>
 * There are several configuration options as follows:
 * <UL>
 * <LI>Bit Size - This value must be 1 or greater and determines the minimum and maximum allowed
 * input values when combined with the current format signedness.</LI>
 * <LI>Use number prefix - If this mode is on, then non-decimal values must be typed with its 
 * prefix(i.e., 0x for hex). When requiring non-decimal prefix, the field is permitted to auto
 * switch formats based on the prefix (or lack thereof). When the "use prefix" option is off, the
 * only way to switch formats is to use the built-in ctrl-M action.</LI>
 * <LI>Show the number mode as hint text - If showing number mode is on, the format short name
 * is displayed lightly in the bottom right portion of the text field.
 * See {@link #setShowNumberMode(boolean)}</LI>
 * </UL>
 *
 */
public class FixedSizeIntegerTextField extends AbstractIntegerTextField {

	private int bitSize;
	private BigInteger minSignedValue;
	private BigInteger minUnsignedValue;
	private BigInteger maxSignedValue;
	private BigInteger maxUnsignedValue;

	/**
	 * Constructor
	 * @param columns the number of character positions for the preferred size of the text field
	 * @param bitSize the initial bit size
	 */
	public FixedSizeIntegerTextField(int columns, int bitSize) {
		this(columns, bitSize, null);
	}

	/**
	 * Constructor
	 * @param columns the number of character positions for the preferred size of the text field
	 * @param bitSize the initial bit size
	 * @param initialValue the value to initialize the field to
	 */
	public FixedSizeIntegerTextField(int columns, int bitSize, long initialValue) {
		this(columns, bitSize, BigInteger.valueOf(initialValue));
	}

	/**
	 * Constructor
	 * @param columns the number of character positions for the preferred size of the text field
	 * @param bitSize the initial bit size
	 * @param initialValue the value to initialize the field to
	 */
	public FixedSizeIntegerTextField(int columns, int bitSize, BigInteger initialValue) {
		super(columns, initialValue, DEC, U_DEC, HEX, U_HEX, U_OCT, U_BIN);
		setBitSize(bitSize);
	}

	/**
	 * Sets the bit size for this field, which effectively sets the min and max values for this 
	 * field when combined with the signedness of the currently selected {@link IntegerFormat}.
	 * @param bitSize the number of bits that will be used to store this value, effectively
	 * determining its min and max value 
	 */
	public void setBitSize(int bitSize) {
		if (bitSize < 1) {
			throw new IllegalArgumentException("Bit size must be greater than 0");
		}
		minUnsignedValue = BigInteger.ZERO;
		maxUnsignedValue = BigInteger.TWO.pow(bitSize).subtract(BigInteger.ONE);
		minSignedValue = BigInteger.TWO.pow(bitSize - 1).negate();
		maxSignedValue = BigInteger.TWO.pow(bitSize - 1).subtract(BigInteger.ONE);

		BigInteger value = getValue();
		this.bitSize = bitSize;
		updateMinMax();
		setValue(value);
	}

	/**
	 * {@return the current bit size for this field}
	 */
	public int getBitSize() {
		return bitSize;
	}

	@Override
	public void setValue(BigInteger newValue) {
		if (newValue != null && !isInBounds(newValue)) {
			if (currentFormat.isUnsigned()) {
				newValue = maybeConvertToUnsigned(newValue);
			}
			else {
				newValue = maybeConvertToSigned(newValue);
			}
		}
		super.setValue(newValue);
	}

	private BigInteger maybeConvertToUnsigned(BigInteger value) {
		// conversion only makes sense if value is a negative number in the signed range
		if (value.compareTo(minSignedValue) >= 0 && value.compareTo(BigInteger.ZERO) < 0) {
			return value.add(BigInteger.TWO.pow(bitSize));
		}
		return value;
	}

	private BigInteger maybeConvertToSigned(BigInteger value) {
		// conversion only makes sense if value is a positive number in the unsigned range
		if (value.compareTo(BigInteger.ZERO) > 0 && value.compareTo(maxUnsignedValue) <= 0) {
			return value.subtract(BigInteger.TWO.pow(bitSize));
		}
		return value;
	}

	private void updateMinMax() {
		if (currentFormat.isUnsigned()) {
			setMinValue(minUnsignedValue);
			setMaxValue(maxUnsignedValue);
		}
		else {
			setMinValue(minSignedValue);
			setMaxValue(maxSignedValue);
		}
	}

	@Override
	public void setFormat(IntegerFormat format) {
		BigInteger value = getValue();
		super.setFormat(format);
		updateMinMax();
		setValue(value);
	}
}
