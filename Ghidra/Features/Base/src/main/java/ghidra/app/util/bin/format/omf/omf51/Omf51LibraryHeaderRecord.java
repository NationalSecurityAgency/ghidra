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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Omf51LibraryHeaderRecord extends OmfRecord {

	public static final int BLOCK_SIZE = 128;

	private short moduleCount;
	private short blockNumber;
	private short byteNumber;

	/**
	 * Creates a new {@link Omf51LibraryHeaderRecord} record
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51LibraryHeaderRecord(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		moduleCount = dataReader.readNextShort();
		blockNumber = dataReader.readNextShort();
		byteNumber = dataReader.readNextShort();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		struct.add(WORD, "moduleCount", null);
		struct.add(WORD, "blockNumber", null);
		struct.add(WORD, "byteNumber", null);
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * {@return the module count}
	 */
	public short getModuleCount() {
		return moduleCount;
	}

	/**
	 * {@return the module names block number}
	 */
	public short getModNamesBlockNumber() {
		return blockNumber;
	}

	/**
	 * {@return the module names byte number}
	 */
	public short getModNamesByteNumber() {
		return byteNumber;
	}

	/**
	 * {@return the module names file offset}
	 */
	public int getModNamesOffset() {
		return (blockNumber * BLOCK_SIZE) + byteNumber;
	}
}
