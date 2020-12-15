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

/*
 * TODO this record type is a guess, using only data (no documentation) in its crafting.
 * Thus, it can be cleaned up using trusted, msft-originated documentation if it becomes
 * available and/or using more data analysis and/or non-trusted documentation.
 * We are fairly certain that 0x1608 is some sort of class, but it could be a typedef class.
 */
/**
 * This class represents the VS19 <B>MsType</B> flavor of C++ Class type. (At this time,
 * PDB_ID is guessed to be a class similar to {@link ClassMsType}, eliminating
 * the redundant count field, and adding other unknown field parsing.)
 * <P>
 * Note that class, struct, and interface are very closed related and have many of the same
 *  constructs and parsing procedures.  However, they are separate.  If any of the internals
 *  of one of these is changed, it is highly suggested that the others be changed as well as
 *  there is not code-shared between these other than by code duplication.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class Class19MsType extends AbstractClassMsType {

	public static final int PDB_ID = 0x1608;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public Class19MsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		property = new MsProperty(reader);
		int x = reader.parseUnsignedShortVal(); //unknown
		fieldDescriptorListRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		derivedFromListRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		vShapeTableRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		//TODO: has more... guessing below... commented out some other conditions, but we
		// might want to investigate if any data hits them.
		Numeric numericUnknown = new Numeric(reader); //unknown. Might even be just a short.
		Numeric numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		size = numeric.getIntegral();
		if (reader.hasMoreNonPad()) {
			name = reader.parseString(pdb, StringParseType.StringNt);
			if (reader.hasMoreNonPad()) {
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

}
