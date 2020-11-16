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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of Enum type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class EnumMsType extends AbstractEnumMsType {

	public static final int PDB_ID = 0x1507;

	protected String mangledName;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public EnumMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		count = reader.parseUnsignedShortVal();
		property = new MsProperty(reader);
		underlyingRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		fieldDescriptorListRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		//TODO: has more... guessing below... commented out some other conditions, but we
		// might want to investigate if any data hits them.
		if (reader.hasMoreNonPad()) {
			name = reader.parseString(pdb, StringParseType.StringNt);
			if (reader.hasMoreNonPad()) {
				// Additional parsing
				mangledName = reader.parseString(pdb, StringParseType.StringNt);
			}
//			else if (reader.hasMore()) {
//			}
		}
//		else {
//		}
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the mangled name field
	 * @return Mangled name.
	 */
	public String getMangledName() {
		return mangledName;
	}

}
