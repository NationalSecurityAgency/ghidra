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

public class Omf51LibraryDictionaryRecord extends OmfRecord {

	private List<List<OmfString>> moduleSymbolMap = new ArrayList<>();

	/**
	 * Creates a new {@link Omf51LibraryDictionaryRecord}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51LibraryDictionaryRecord(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		List<OmfString> symbols = new ArrayList<>();

		while (dataReader.getPointerIndex() < dataEnd) {
			byte len = dataReader.peekNextByte();
			if (len == 0) {
				dataReader.readNextByte();
				moduleSymbolMap.add(symbols);
				symbols = new ArrayList<>();
			}
			else {
				symbols.add(OmfUtils.readString(dataReader));
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		Integer moduleIndex = 0;
		for (List<OmfString> symbols : moduleSymbolMap) {
			for (OmfString symbol : symbols) {
				struct.add(symbol.toDataType(), symbol.getDataTypeSize(),
					"symbol%d".formatted(moduleIndex), null);
			}

			struct.add(BYTE, "terminator%d".formatted(moduleIndex), null);
			moduleIndex++;
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * {@return the symbol names partitioned by module}
	 */
	public List<List<OmfString>> getModuleSymbolMap() {
		return moduleSymbolMap;
	}
}
