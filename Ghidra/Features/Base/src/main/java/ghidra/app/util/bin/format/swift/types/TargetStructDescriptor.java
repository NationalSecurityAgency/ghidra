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
 * Represents a Swift TargetStructDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetStructDescriptor extends TargetTypeContextDescriptor {

	private int numFields;
	private int fieldOffsetVectorOffset;

	/**
	 * Creates a new {@link TargetStructDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetStructDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		numFields = reader.readNextInt();
		fieldOffsetVectorOffset = reader.readNextInt();
	}

	/**
	 * Gets the number of stored properties in the struct. If there is a field offset vector, 
	 * this is its length.
	
	 * @return The number of stored properties in the struct. If there is a field offset vector, 
	 *   this is its length.
	 */
	public int getNumFields() {
		return numFields;
	}

	/**
	 * Gets the offset of the field offset vector for this struct's stored properties in its 
	 * metadata, if any. 0 means there is no field offset vector.
	 * 
	 * @return The offset of the field offset vector for this struct's stored properties in its 
	 *   metadata, if any. 0 means there is no field offset vector.
	 */
	public int getFieldOffsetVectorOffset() {
		return fieldOffsetVectorOffset;
	}

	@Override
	public String getStructureName() {
		return TargetStructDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "struct descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(DWORD, "NumFields",
			"The number of stored properties in the struct. If there is a field offset vector, this is its length.");
		struct.add(DWORD, "FieldOffsetVectorOffset",
			"The offset of the field offset vector for this struct's stored properties in its metadata, if any. 0 means there is no field offset vector.");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
