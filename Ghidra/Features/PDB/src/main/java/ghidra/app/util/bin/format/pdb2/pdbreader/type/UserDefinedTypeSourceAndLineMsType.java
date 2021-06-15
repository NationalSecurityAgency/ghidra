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
 * This class represents the <B>MsType</B> flavor of User Defined Type Source and Lines type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class UserDefinedTypeSourceAndLineMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1606;

	private RecordNumber udtRecordNumber;
	private RecordNumber sourceFileNameStringIdRecordNumber;
	private int lineNumber;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public UserDefinedTypeSourceAndLineMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		udtRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		sourceFileNameStringIdRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.ITEM, 32);
		lineNumber = reader.parseInt();
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
	 * Returns the source file name String ID Record Number.
	 * @return the source file name String ID Record Number.
	 */
	public RecordNumber getSourceFileNameStringIdRecordNumber() {
		return sourceFileNameStringIdRecordNumber;
	}

	/**
	 * Returns the source file name.
	 * @return the source file name.  null if problem recovering name.
	 */
	public String getSourceFileName() {
		StringIdMsType stringIdType =
			pdb.getTypeRecord(getSourceFileNameStringIdRecordNumber(), StringIdMsType.class);
		if (stringIdType == null) {
			return null;
		}
		return stringIdType.getString();
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
		builder.append(UserDefinedTypeSourceAndLineMsType.class.getSimpleName());
		builder.append(", line: ");
		builder.append(lineNumber);
		builder.append(", SourceFileNameStringIdIndex: ");
		builder.append(getSourceFileName());
		builder.append(", type: ");
		builder.append(pdb.getTypeRecord(udtRecordNumber));
	}

}
