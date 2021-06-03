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
 * This class represents the <B>MsType</B> flavor of Virtual Function Table type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class VirtualFunctionTableMsType extends AbstractMsType {

	public static final int PDB_ID = 0x151d;

	private RecordNumber ownerRecordNumber;
	private RecordNumber baseVirtualFunctionTableRecordNumber;
	private int vfptrOffsetRelToObjectLayout;
	private int namesArrayLength;
	private String vftableName;
	private List<String> names = new ArrayList<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public VirtualFunctionTableMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		ownerRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		baseVirtualFunctionTableRecordNumber =
			RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		vfptrOffsetRelToObjectLayout = reader.parseInt();
		namesArrayLength = reader.parseInt();
		PdbByteReader namesReader = reader.getSubPdbByteReader(namesArrayLength);
		boolean first = true;
		while (namesReader.hasMore()) {
			String name = namesReader.parseNullTerminatedString(
				pdb.getPdbReaderOptions().getOneByteCharset());
			if (first) {
				first = false;
				vftableName = name;
			}
			else {
				names.add(name);
			}
		}
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		//No API.
		builder.append("VFTable for [");
		builder.append(pdb.getTypeRecord(ownerRecordNumber));
		builder.append("<vfptr_offset=");
		builder.append(vfptrOffsetRelToObjectLayout);
		builder.append(">");
		if (baseVirtualFunctionTableRecordNumber != RecordNumber.NO_TYPE) {
			builder.append(" : ");
			builder.append(pdb.getTypeRecord(baseVirtualFunctionTableRecordNumber));
		}
		builder.append("] ");
		builder.append(vftableName);
		builder.append(": {");

		DelimiterState ds = new DelimiterState("", ",");
		for (String name : names) {
			builder.append(ds.out(true, name)); // Method names.
		}
		builder.append("}");
	}

}
