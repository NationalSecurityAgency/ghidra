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
package ghidra.app.util.bin.format.omf.omf51;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Omf51FixupRecord extends OmfRecord {

	/**
	 * OMF-51 fixup metadata
	 * 
	 * @param refLoc The reference location
	 * @param refType The reference type
	 * @param operand the fixup operand
	 */
	public static record Omf51Fixup(int refLoc, byte refType, int operand) {}

	private List<Omf51Fixup> fixups = new ArrayList<>();

	/**
	 * Creates a new {@link Omf51FixupRecord} record
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51FixupRecord(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			int refLoc = dataReader.readNextUnsignedByte();
			byte refType = dataReader.readNextByte();
			int operand = dataReader.readNextUnsignedShort();
			fixups.add(new Omf51Fixup(refLoc, refType, operand));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		StructureDataType fixupStruct = new StructureDataType("Omf51Fixup", 0);
		fixupStruct.add(BYTE, "ref_loc", null);
		fixupStruct.add(BYTE, "ref_type", null);
		fixupStruct.add(WORD, "operand", null);
		struct.add(new ArrayDataType(fixupStruct, fixups.size(), fixupStruct.getLength()), "fixup",
			null);
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * Gets a {@link List} of fixups
	 * 
	 * @return A {@link List} of fixups
	 */
	public List<Omf51Fixup> getFixups() {
		return fixups;
	}
}
