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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of Build Information type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class BuildInfoMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1603;

	public static final int BUILDINFO_CURRENT_DIRECTORY = 0;
	public static final int BUILDINFO_BUILD_TOOL = 1;
	public static final int BUILDINFO_SOURCE_FILE = 2;
	public static final int BUILDINFO_PROGRAM_DATABASE_FILE = 3;
	public static final int BUILDINFO_COMMAND_ARGUMENTS = 4;

	private static final String[] BUILDINFO_STRING = new String[5];
	static {
		BUILDINFO_STRING[0] = "CurrentDirectory: ";
		BUILDINFO_STRING[1] = "BuildTool: ";
		BUILDINFO_STRING[2] = "SourceFile: ";
		BUILDINFO_STRING[3] = "ProgramDatabaseFile: ";
		BUILDINFO_STRING[4] = "CommandArguments: ";
	}

	private int count;
	private List<RecordNumber> argsCodeItemRecordNumbers = new ArrayList<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public BuildInfoMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		count = reader.parseUnsignedShortVal();
		for (int i = 0; i < count; i++) {
			int codeItemId = reader.parseInt();
			RecordNumber itemRecordNumber = RecordNumber.make(RecordCategory.ITEM, codeItemId);
			argsCodeItemRecordNumbers.add(itemRecordNumber);
		}
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		//No API for output.
		DelimiterState ds = new DelimiterState("", ", ");
		for (int i = 0; (i < count) && (i < BUILDINFO_STRING.length); i++) {
			StringBuilder myBuilder = new StringBuilder();
			myBuilder.append(BUILDINFO_STRING[i]);
			myBuilder.append(pdb.getTypeRecord(argsCodeItemRecordNumbers.get(i)));
			builder.append(ds.out(true, myBuilder.toString()));
		}
	}

}
