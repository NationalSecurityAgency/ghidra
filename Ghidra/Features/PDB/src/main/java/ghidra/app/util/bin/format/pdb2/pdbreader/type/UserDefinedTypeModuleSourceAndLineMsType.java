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
 * This class represents the <B>MsType</B> flavor of User Defined Type Module Source and Lines type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class UserDefinedTypeModuleSourceAndLineMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1607;

	private RecordNumber udtRecordNumber;
	private int sourceFileNameStringOffset;
	private int lineNumber;
	private int module;

	// TODO: For continued work with hash.
	//public static Set<Integer> sourceIdIndexList = new HashSet<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public UserDefinedTypeModuleSourceAndLineMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		udtRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		sourceFileNameStringOffset = reader.parseInt();
		lineNumber = reader.parseInt();
		module = reader.parseUnsignedShortVal();
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the line number within the file.
	 * @return the line number within the file.
	 */
	public int getLineNumber() {
		return lineNumber;
	}

	/**
	 * Returns the module number of the file.
	 * @return the module number of the file.
	 */
	public int getModuleNumber() {
		return module;
	}

	/**
	 * Returns the offset of the source file name in the strings table.
	 * @return the offset of the source file name in the strings table.
	 */
	public int getSourceFileNameOffset() {
		return sourceFileNameStringOffset;
	}

	/**
	 * Returns the source file name.
	 * @return the source file name.
	 */
	public String getSourceFileName() {
		return pdb.getNameStringFromOffset(sourceFileNameStringOffset);
	}

	/**
	 * Returns the record number of the UDT.
	 * @return the record number of the UDT.
	 */
	public RecordNumber getUdtRecordNumber() {
		return udtRecordNumber;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No good API.
		// TODO: Think their hash stuff might be superfluous... will see...
		// TODO: output module # for now.  Might need name lookup later.
		builder.append(UserDefinedTypeModuleSourceAndLineMsType.class.getSimpleName());
		builder.append(", module: ");
		builder.append(module);
		builder.append(", line: ");
		builder.append(lineNumber);
		builder.append(", sourceFileName: ");
		// I believe the following is correct source of string.  API unclear.
		builder.append(getSourceFileName());
		builder.append(", type: ");
		builder.append(pdb.getTypeRecord(udtRecordNumber));
	}

}
