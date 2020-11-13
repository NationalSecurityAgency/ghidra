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
 * This class represents the <B>16MsType</B> flavor of C/C++ Struct type.
 * <P>
 * Note that class, struct, and interface are very closed related and have many of the same
 *  constructs and parsing procedures.  However, they are separate.  If any of the internals
 *  of one of these is changed, it is highly suggested that the others be changed as well as
 *  there is not code-shared between these other than by code duplication.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class Structure16MsType extends AbstractStructureMsType {

	public static final int PDB_ID = 0x0005;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public Structure16MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		count = reader.parseUnsignedShortVal();
		fieldDescriptorListRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		property = new MsProperty(reader);
		derivedFromListRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		vShapeTableRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		Numeric numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		size = numeric.getIntegral();
		name = reader.parseString(pdb, StringParseType.StringSt);
		// no mangled name
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

}
