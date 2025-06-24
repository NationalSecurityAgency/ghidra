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

public class Omf51ExternalDefsRecord extends OmfRecord {

	private boolean largeExtId;
	private List<Omf51ExternalDef> defs = new ArrayList<>();
	
	/**
	 * Creates a new {@link Omf51ExternalDefsRecord} record
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param largeExtId True if the external ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51ExternalDefsRecord(BinaryReader reader, boolean largeExtId) throws IOException {
		super(reader);
		this.largeExtId = largeExtId;
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			defs.add(new Omf51ExternalDef(dataReader, largeExtId));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		
		for (Omf51ExternalDef def : defs) {
			struct.add(BYTE, "blockType", null);
			struct.add(largeExtId ? WORD : BYTE, "extId", null);
			struct.add(BYTE, "info", null);
			struct.add(BYTE, "unused", null);
			struct.add(def.getName().toDataType(), def.getName().getDataTypeSize(), "name", null);
		}
		
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * {@return the list of external definitions}
	 */
	public List<Omf51ExternalDef> getDefinitions() {
		return defs;
	}
}
