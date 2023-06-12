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
package ghidra.app.util.bin.format.swift.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift TargetEnumDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetEnumDescriptor extends TargetTypeContextDescriptor {

	private int numPayloadCasesAndPayloadSizeOffset;
	private int numEmptyCases;

	/**
	 * Creates a new {@link TargetEnumDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetEnumDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		numPayloadCasesAndPayloadSizeOffset = reader.readNextInt();
		numEmptyCases = reader.readNextInt();
	}

	/**
	 * Gets the number of non-empty cases in the enum are in the low 24 bits; the offset of the 
	 * payload size in the metadata record in words, if any, is stored in the high 8 bits;
	
	 * @return The number of non-empty cases in the enum and the offset of the payload size
	 */
	public int getNumPayloadCasesAndPayloadSizeOffset() {
		return numPayloadCasesAndPayloadSizeOffset;
	}

	/**
	 * Gets the number of empty cases in the enum
	 * 
	 * @return The number of empty cases in the enum
	 */
	public int getNumEmptyCases() {
		return numEmptyCases;
	}

	@Override
	public String getStructureName() {
		return TargetEnumDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "enum descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(DWORD, "NumPayloadCasesAndPayloadSizeOffset",
			"The number of non-empty cases in the enum are in the low 24 bits; the offset of the payload size in the metadata record in words, if any, is stored in the high 8 bits.");
		struct.add(DWORD, "NumEmptyCases", "The number of empty cases in the enum");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
