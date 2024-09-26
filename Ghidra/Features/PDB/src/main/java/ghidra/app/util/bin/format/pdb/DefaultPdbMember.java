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

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.SymbolPathParser;
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
		if (StringUtils.isBlank(name)) {
			return name;
		}
		if (kind == PdbKind.MEMBER) {
			// Strip bitfield data if present (see parseBitField method)
			int bitFieldColonIndex = getBitfieldIndex(name);
			if (bitFieldColonIndex >= 0) {
				return name.substring(0, bitFieldColonIndex);
			}
		}
		// name may contain namespace prefix for non-Member class members
		List<String> names = SymbolPathParser.parse(name);
		return names.get(names.size() - 1);
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
		int bitFieldColonIndex = getBitfieldIndex(name);
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

	/**
	 * Returns the index of the bit-field component of the mixed name field that is composed of
	 * a standard namespace name and an optional (non-namespace name compliant) bit-field
	 * component passed on from the native pdb.exe parser.
	 * <p>
	 * Assumes format: nameWithMixOfEmbeddedAndNonEmbeddedNamespaceDelimeters[:bfBitLen:bfBitOff].
	 * <p>
	 * The bfBitLen and bfBitOff fields are represented as hex with "0x" prefixes.
	 * <p>
	 * Note: we are unaware of any circumstance where, if there is a bit-field component, that
	 * there could also be a name with namespace delimiters; however, this method ensures that
	 * we can process any name from the pdb.exe
	 * @param name the name to parse
	 * @return the index of the bit-field component, which is the index of the first of two
	 * singleton colon characters, or -1 if there is no bit-field component
	 */
	private static int getBitfieldIndex(String name) {
		int loc = name.lastIndexOf(':');
		// Minimum location of last singleton ':" is 5 as in this example: "a:0x1:0x0"
		if (loc < 5) {
			return -1;
		}
		if (name.charAt(loc - 1) == ':') { // means we found "::"
			return -1;
		}
		loc = name.lastIndexOf(':', loc - 1);
		// Since we found a single colon above, not finding a singleton colon here would prove
		//  to be a malformed format
		if (loc > 0 && name.charAt(loc - 1) != ':') {
			return loc;
		}
		return -1;
	}
}
