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
package ghidra.app.util.bin.format.pdb;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;

/**
 * <code>PdbMember</code> convey PDB member information used for datatype
 * reconstruction. The <i>memberDataTypeName</i> is expected to include
 * namespace prefixes when relevant.  When representing bitfields the 
 * <i>memberName</i> is used to convey bit-size and bit-offset information
 * (e.g., fieldname:SSSS[:XXXX] where SSSS corresponds to the bit-size
 * and XXXX corresponds to an optional bit-offset).
 */
public class DefaultPdbMember extends PdbMember {

	private final String name;

	private boolean isBitField;
	private int bitFieldSize = -1;
	private int bitFieldOffset = -1;

	private final PdbDataTypeParser dataTypeParser;

	/**
	 * Default PDB member construction
	 * @param name member field name.  For bitfields this also conveys the bit-size
	 * and optionally the bit-offset.
	 * @param dataTypeName field datatype or the base datatype associated with a bitfield
	 * @param offset
	 * @param dataTypeParser
	 */
	DefaultPdbMember(String name, String dataTypeName, int offset,
			PdbDataTypeParser dataTypeParser) {
		super(getMemberName(name), dataTypeName, offset);
		this.name = name;
		parseBitField();
		this.dataTypeParser = dataTypeParser;
	}

	@Override
	public String toString() {
		String str = super.toString();
		if (isBitField) {
			str += ", bitSize=" + bitFieldSize + ", bitOffset=" + bitFieldOffset;
		}
		return str;
	}

	private static String getMemberName(String name) {
		int bitFieldColonIndex = name != null ? name.indexOf(':') : -1;
		if (bitFieldColonIndex >= 0) {
			return name.substring(0, bitFieldColonIndex);
		}
		return name;
	}

	@Override
	protected WrappedDataType getDataType() throws CancelledException {
		WrappedDataType wrappedDt = dataTypeParser.findDataType(getDataTypeName());
		if (wrappedDt != null && isBitField) {
			if (wrappedDt.isZeroLengthArray()) {
				return null;
			}
			PdbBitField bitFieldDt;
			try {
				DataType baseDataType =
					wrappedDt.getDataType().clone(dataTypeParser.getProgramDataTypeManager());
				bitFieldDt = new PdbBitField(baseDataType, bitFieldSize, bitFieldOffset);
			}
			catch (InvalidDataTypeException e) {
				Msg.error(this, "PDB parse error: " + e.getMessage());
				return null;
			}
			wrappedDt = new WrappedDataType(bitFieldDt, false);
		}
		return wrappedDt;
	}

	private void parseBitField() {
		int bitFieldColonIndex = name != null ? name.indexOf(':') : -1;
		if (bitFieldColonIndex >= 0) {

			isBitField = true;

			String bitSizeOffsetStr = name.substring(bitFieldColonIndex + 1);

			try {
				int colonIndex = bitSizeOffsetStr.indexOf(':');
				if (colonIndex > 0) {
					bitFieldOffset = (int) NumericUtilities.parseNumber(
						bitSizeOffsetStr.substring(colonIndex + 1));
					bitSizeOffsetStr = bitSizeOffsetStr.substring(0, colonIndex);
				}
				bitFieldSize = (int) NumericUtilities.parseNumber(bitSizeOffsetStr);
			}
			catch (NumberFormatException e) {
				// ignore
			}
		}
	}

}
