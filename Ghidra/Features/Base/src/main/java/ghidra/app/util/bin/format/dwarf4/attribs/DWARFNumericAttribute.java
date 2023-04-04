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
package ghidra.app.util.bin.format.dwarf4.attribs;

import ghidra.program.model.scalar.Scalar;

/**
 * DWARF numeric attribute.
 */
public class DWARFNumericAttribute extends Scalar implements DWARFAttributeValue {

	private final boolean ambiguous;

	/**
	 * Creates a new numeric value, using 64 bits and marked as signed
	 * 
	 * @param value long 64 bit value
	 */
	public DWARFNumericAttribute(long value) {
		this(64, value, true, false);
	}

	/**
	 * Creates a new numeric value, using the specific bitLength and value.
	 * 
	 * @param bitLength number of bits, valid values are 1..64, or 0 if value is also 0
	 * @param value value of the scalar, any bits that are set above bitLength will be ignored
	 * @param signed true for a signed value, false for an unsigned value.
	 */
	public DWARFNumericAttribute(int bitLength, long value, boolean signed) {
		this(bitLength, value, signed, false);
	}

	/**
	 * Creates a new numeric value, using the specific bitLength and value.
	 * 
	 * @param bitLength number of bits, valid values are 1..64, or 0 if value is also 0
	 * @param value value of the scalar, any bits that are set above bitLength will be ignored
	 * @param signed true for a signed value, false for an unsigned value.
	 * @param ambiguous true for value with ambiguous signedness ({@code signed} parameter should
	 * not be trusted), false for value where the {@code signed} parameter is known to be correct
	 */
	public DWARFNumericAttribute(int bitLength, long value, boolean signed, boolean ambiguous) {
		super(bitLength, value, signed);
		this.ambiguous = ambiguous;
	}

	/**
	 * {@return boolean flag, if true this value's signedness is up to the user of the value,
	 * if false the signedness was determined when the value was constructed}
	 */
	public boolean isAmbiguousSignedness() {
		return ambiguous;
	}

	/**
	 * {@return the value, forcing the signedness of ambiguous values using the specified hint} 
	 * @param signednessHint true to default to a signed value, false to default to an 
	 * unsigned value
	 */
	public long getValueWithSignednessHint(boolean signednessHint) {
		return getValue(ambiguous ? signednessHint : isSigned());
	}

	@Override
	public String toString() {
		return String.format("DWARFNumericAttribute: %d [%08x]", getValue(), getValue());
	}
}
