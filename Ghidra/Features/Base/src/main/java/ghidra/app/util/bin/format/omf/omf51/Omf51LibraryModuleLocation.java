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
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.omf.OmfUtils;
import ghidra.program.model.data.*;

public class Omf51LibraryModuleLocation {

	public static final int BLOCK_SIZE = 128;

	private int blockNumber;
	private int byteNumber;

	/**
	 * Creates a new {@link Omf51LibraryModuleLocation}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the segment definition
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51LibraryModuleLocation(BinaryReader reader) throws IOException {
		blockNumber = reader.readNextUnsignedShort();
		byteNumber = reader.readNextUnsignedShort();
	}

	/**
	 * {@return the block number}
	 */
	public int getBlockNumber() {
		return blockNumber;
	}

	/**
	 * {@return the byte number}
	 */
	public int getByteNumber() {
		return byteNumber;
	}

	/**
	 * {@return the offset into the library}
	 */
	public int getOffset() {
		return (blockNumber * BLOCK_SIZE) + byteNumber;
	}

	public static DataType toDataType() {
		StructureDataType struct = new StructureDataType("Omf51LibraryModuleLocation", 0);
		struct.add(StructConverter.WORD, "blockNumber", null);
		struct.add(StructConverter.WORD, "byteNumber", null);
		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}
