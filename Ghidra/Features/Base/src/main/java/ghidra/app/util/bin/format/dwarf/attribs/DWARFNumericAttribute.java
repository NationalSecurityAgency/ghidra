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
package ghidra.app.util.bin.format.dwarf.attribs;

import java.io.IOException;

import ghidra.app.util.bin.InvalidDataException;
import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionNames;
import ghidra.program.model.scalar.Scalar;

/**
 * DWARF numeric attribute.
 */
public class DWARFNumericAttribute implements DWARFAttributeValue {

	private final Scalar value;
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
		this.value = new Scalar(bitLength, value, signed);
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
		return value.getValue(ambiguous ? signednessHint : value.isSigned());
	}

	public boolean isHighbitSet() {
		return value.bitLength() > 0 ? value.testBit(value.bitLength() - 1) : false;
	}

	public long getValue() {
		return value.getValue();
	}

	public long getUnsignedValue() {
		return value.getUnsignedValue();
	}

	public int getUnsignedIntExact() throws IOException {
		long x = value.getUnsignedValue();
		if (x < 0 || Integer.MAX_VALUE < x) {
			throw new InvalidDataException(
				"Value out of range for positive java 32 bit unsigned int: %d [0x%d]".formatted(x,
					x));
		}
		return (int) x;
	}

	public String toElementLocationString(String elementType, String sectionName, int index,
			long offset, int ver) {
		String indexStr = index >= 0 ? " (idx %d)".formatted(index) : "";
		return "%s v%d %s:%x%s".formatted(elementType, ver, sectionName, offset, indexStr);
	}

	@Override
	public String getValueString(DWARFCompilationUnit cu, DWARFAttributeDef<?> def) {

		short ver = cu.getDWARFVersion();
		DWARFForm form = def.getAttributeForm();
		if (form.isClass(DWARFAttributeClass.address)) {
			return "addr v%d 0x%x".formatted(ver, getUnsignedValue());
		}
		else if (form.isClass(DWARFAttributeClass.rnglist)) {
			String sectionName =
				ver < 5 ? DWARFSectionNames.DEBUG_RANGES : DWARFSectionNames.DEBUG_RNGLISTS;
			return toElementLocationString("rnglist", sectionName, -1, getUnsignedValue(), ver) +
				" offset: " + getUnsignedValue();
		}
		else if (form.isClass(DWARFAttributeClass.loclist)) {
			String sectionName =
				ver < 5 ? DWARFSectionNames.DEBUG_LOC : DWARFSectionNames.DEBUG_LOCLISTS;
			return toElementLocationString("loclist", sectionName, -1, getUnsignedValue(), ver);
		}

		String orStr =
			ambiguous && isHighbitSet() ? " or " + value.getValue(!value.isSigned()) : "";
		return "%d%s [%s]".formatted(getValue(), orStr, value.toString(16, true, false, "", ""));
	}

	@Override
	public String toString() {
		String orStr =
			ambiguous && isHighbitSet() ? " or " + value.getValue(!value.isSigned()) : "";
		return "%d%s [%s]".formatted(getValue(), orStr, value.toString(16, true, false, "", ""));
	}

}
