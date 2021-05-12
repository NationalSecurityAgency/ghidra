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
package ghidra.app.plugin.exceptionhandlers.gcc.datatype;

import ghidra.docking.settings.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;

/**
 * LEB128 is an integer compression system resulting in variable-length byte sequence.
 * An abstract base class for a little endian base 128 integer data type.
 */
public abstract class AbstractLeb128DataType extends BuiltIn implements Dynamic {

	/** The maximum length in bytes of a leb128 data type. */
	public static final int MAX_LEB128_ENCODED_VALUE_LEN = 8;

	private static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF_HEX;
	private static final PaddingSettingsDefinition PADDING = PaddingSettingsDefinition.DEF;

	private static SettingsDefinition[] SETTINGS_DEFS = { FORMAT, PADDING };

	private final boolean signed;

	/**
	 * Base constructor for a little endian based 128 data type.
	 * @param name name of the leb128 data type that extends this class.
	 * @param signed true if it is signed. false if unsigned.
	 * @param dtm the data type manager to associate with this data type.
	 */
	public AbstractLeb128DataType(String name, boolean signed, DataTypeManager dtm) {
		super(null, name, dtm);
		this.signed = signed;
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	@Override
	public String getDescription() {
		return "Dwarf LEB128-Encoded Number";
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {

		if (maxLength < 1 || maxLength > MAX_LEB128_ENCODED_VALUE_LEN) {
			maxLength = MAX_LEB128_ENCODED_VALUE_LEN;
		}

		byte[] data = new byte[maxLength];
		int availBytes = buf.getBytes(data, 0);
		int numRead = 0;
		byte curByte = 0;
		while ((numRead < availBytes) && (numRead < data.length)) {
			curByte = data[numRead];
			numRead++;
			if ((curByte & 0x80) == 0) {
				break; // End of LEB128.
			}
		}
		return numRead;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			return null;
		}
		int numRead = 0;
		int shift = 0;
		byte curByte = 0;
		long val = 0;

		if (data.length >= 1) {
			do {
				curByte = data[numRead];
				numRead++;
				val |= ((curByte & 0x7f) << shift);
				shift += 7;
			}
			while ((curByte & 0x80) != 0 && numRead < data.length);

			if (signed && ((curByte & 0x40) != 0)) {
				// val |= (-1 << (shift - 7)) << 7;
				val |= -1 << shift;
			}

		}

		return new Scalar(numRead * 8, val, signed);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {

		int format = FORMAT.getFormat(settings);
		boolean padded = PADDING.isPadded(settings);

		int size = getLength(buf, length);
		if (size <= 0 && length <= 0) {
			return "??";
		}

		Scalar val = (Scalar) getValue(buf, settings, length);
		if (val == null) {
			return "??";
		}

		int radix;
		String prefix = "";
		String postfix = "";
		switch (format) {
			default:
			case FormatSettingsDefinition.HEX:
				radix = 16;
				postfix = "h";
				break;
			case FormatSettingsDefinition.DECIMAL:
				radix = 10;
				break;
			case FormatSettingsDefinition.BINARY:
				radix = 2;
				postfix = "b";
				break;
			case FormatSettingsDefinition.OCTAL:
				radix = 8;
				postfix = "o";
				break;
		}

		String valStr = val.toString(radix, padded, true /* showSign */, prefix, "");
		return valStr.toUpperCase() + postfix;
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

	@Override
	public boolean canSpecifyLength() {
		return false;
	}

}
