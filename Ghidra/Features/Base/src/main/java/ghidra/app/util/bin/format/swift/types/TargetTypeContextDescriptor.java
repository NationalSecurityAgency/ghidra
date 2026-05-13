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
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetTypeContextDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetTypeContextDescriptor extends TargetContextDescriptor {

	private String name;
	private int accessFunctionPtr;
	private int fields;

	/**
	 * Creates a new {@link TargetTypeContextDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetTypeContextDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		name = reader.readNext(SwiftUtils::relativeString);
		accessFunctionPtr = reader.readNextInt();
		fields = reader.readNextInt();
	}

	/**
	 * {@return the name of the type}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the pointer to the metadata access function for this type}
	 */
	public int getAccessFunctionPtr() {
		return accessFunctionPtr;
	}

	/**
	 * {@return the pointer to the field descriptor for the type, if any}
	 */
	public int getFields() {
		return fields;
	}

	/**
	 * {@return this {@link TargetTypeContextDescriptor}'s {@link FieldDescriptor}, or {@code null}
	 * if it doesn't have one}
	 * 
	 * @param fieldDescriptors A {@link Map} of {@link FieldDescriptor}'s keyed by their base
	 *   addresses
	 */
	public FieldDescriptor getFieldDescriptor(Map<Long, FieldDescriptor> fieldDescriptors) {
		FieldDescriptor fieldDescriptor =
			fieldDescriptors.get(getBase() + TargetContextDescriptor.SIZE + 8 + fields);
		return fieldDescriptor != null ? fieldDescriptor : null;
	}

	@Override
	public String getStructureName() {
		return getMyStructureName();
	}

	@Override
	public String getDescription() {
		return "type context descriptor";
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * {@return this class's structure name (will not be affected by subclass's name)}
	 */
	private final String getMyStructureName() {
		return TargetTypeContextDescriptor.class.getSimpleName();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getMyStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(SwiftUtils.PTR_STRING, "Name", "The name of the type");
		struct.add(SwiftUtils.PTR_RELATIVE, "AccessFunctionPtr",
			"A pointer to the metadata access function for this type");
		struct.add(SwiftUtils.PTR_RELATIVE, "Fields",
			"A pointer to the field descriptor for the type, if any");
		return struct;
	}
}
