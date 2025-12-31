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
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetMethodOverrideDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetMethodOverrideDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link TargetMethodOverrideDescriptor} structure
	 */
	public static final int SIZE = 8;

	private int classPtr;
	private int methodPtr;
	private int impl;

	/**
	 * Creates a new {@link TargetMethodOverrideDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetMethodOverrideDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		classPtr = reader.readNextInt();
		methodPtr = reader.readNextInt();
		impl = reader.readNextInt();
	}

	/**
	 * {@return the class containing the base method}
	 */
	public int getClassPtr() {
		return classPtr;
	}

	/**
	 * {@return the base method}
	 */
	public int getMethodPtr() {
		return methodPtr;
	}

	/**
	 * {@return the implementation of the override}
	 */
	public int getImpl() {
		return impl;
	}

	@Override
	public String getStructureName() {
		return TargetMethodOverrideDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "method override descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(SwiftUtils.PTR_RELATIVE_MASKED, "Class",
			"The class containing the base method.");
		struct.add(SwiftUtils.PTR_RELATIVE_MASKED, "Method", "The base method.");
		struct.add(SwiftUtils.PTR_RELATIVE, "Impl", "The implementation of the override");
		return struct;
	}
}
