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
 * Represents a Swift {@code TargetMethodDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetMethodDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link TargetMethodDescriptor} structure
	 */
	public static final int SIZE = 8;

	private MethodDescriptorFlags flags;
	private int impl;

	/**
	 * Creates a new {@link TargetMethodDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetMethodDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = new MethodDescriptorFlags(reader);
		impl = reader.readNextInt();
	}

	/**
	 * {@return the flags}
	 */
	public MethodDescriptorFlags getFlags() {
		return flags;
	}

	/**
	 * {@return the method implementation's relative offset}
	 */
	public int getImpl() {
		return impl;
	}

	@Override
	public String getStructureName() {
		return TargetMethodDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "method descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(flags.toDataType(), "Flags", "Flags describing the method");
		struct.add(SwiftUtils.PTR_RELATIVE, "Impl", "The method implementation");
		return struct;
	}
}
