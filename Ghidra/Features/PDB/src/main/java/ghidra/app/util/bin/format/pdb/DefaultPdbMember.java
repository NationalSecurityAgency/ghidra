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
 * (e.g., fieldname:SSSS:XXXX where SSSS corresponds to the bit-size
 * and XXXX corresponds to an bit-offset).  If bit-offset information is
 * absent parsing will proceed and {@link PdbDataTypeParser#setMissingBitOffsetError()}
 * will be notified.
 */
public class DefaultPdbMember extends PdbMember {

	final PdbKind kind;

	private boolean isBitField;
	private int bitFieldSize = -1;
	private int bitFieldOffset = -1;

	private final PdbDataTypeParser dataTypeParser;

	/**
	 * Default PDB member construction
	 * @param name member field name.  For bitfields this also conveys the bit-size
	 * and optionally the bit-offset.
	 * @param dataTypeName field datatype or the base datatype associated with a bitfield
	 * @param offset member offset
	 * @param kind kind of member (only {@link PdbKind#MEMBER} are supported as composite members)
	 * @param dataTypeParser PDB datatype parser
	 */
	DefaultPdbMember(String name, String dataTypeName, int offset, PdbKind kind,
			PdbDataTypeParser dataTypeParser) {
		super(getMemberName(name, kind), dataTypeName, offset, null);
		this.kind = kind;
		this.dataTypeParser = dataTypeParser;
		parseBitField(name);
	}

	/**
	 * Kind of member record.  Only those records with a Member kind
	 * are currently considered for inclusion within a composite.
	 * @return PDB kind
	 */
	public PdbKind getKind() {
		return kind;
	}

	@Override
	public String toString() {
		String str = super.toString();
		if (isBitField) {
			str += ", bitSize=" + bitFieldSize + ", bitOffset=" + bitFieldOffset;
		}
		return str;
	}

	private static String getMemberName(String name, PdbKind kind) {
		if (name == null) {
			return null;
		}
		if (kind == PdbKind.MEMBER) {
			// Strip bitfield data if present (see parseBitField method)
			int bitFieldColonIndex = name.indexOf(':');
			if (bitFieldColonIndex >= 0) {
				return name.substring(0, bitFieldColonIndex);
			}
		}
		// name may contain namespace prefix for non-Member class members
		int lastColonIndex = name.lastIndexOf(':');
		if (lastColonIndex > 0) {
			name = name.substring(lastColonIndex + 1);
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
				bitFieldDt = new PdbBitField(baseDataType, bitFieldSize,
					bitFieldOffset >= 0 ? bitFieldOffset : 0);
			}
			catch (InvalidDataTypeException e) {
				Msg.error(this, "PDB parse error: " + e.getMessage());
				return null;
			}
			wrappedDt = new WrappedDataType(bitFieldDt, false, false);
		}
		return wrappedDt;
	}

	private void parseBitField(String name) {
		if (name == null || kind != PdbKind.MEMBER) {
			return;
		}
		int bitFieldColonIndex = name.indexOf(':');
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
				else {
					dataTypeParser.setMissingBitOffsetError();
				}
				bitFieldSize = (int) NumericUtilities.parseNumber(bitSizeOffsetStr);
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Invalid PDB bitfield specification: " + name);
			}
		}
	}

}
