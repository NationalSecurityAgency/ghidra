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
 * Represents a Swift {@code TargetContextDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetContextDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link TargetContextDescriptor} structure
	 */
	public static final int SIZE = 8;

	protected ContextDescriptorFlags flags;
	private int parent;

	/**
	 * Create a new {@link TargetContextDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetContextDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = new ContextDescriptorFlags(reader);
		parent = reader.readNextInt();
	}

	/**
	 * {@return the flags}
	 */
	public ContextDescriptorFlags getFlags() {
		return flags;
	}

	/**
	 * {@return the parent's relative offset}
	 */
	public int getParent() {
		return parent;
	}

	@Override
	public String getStructureName() {
		return getMyStructureName();
	}

	@Override
	public String getDescription() {
		return "context descriptor";
	}

	/**
	 * {@return this class's structure name (will not be affected by subclass's name)}
	 */
	private final String getMyStructureName() {
		return TargetContextDescriptor.class.getSimpleName();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getMyStructureName(), 0);
		struct.add(flags.toDataType(), "Flags",
			"Flags describing the context, including its kind and format version");
		struct.add(SwiftUtils.PTR_RELATIVE_MASKED, "Parent",
			"The parent context, or null if this is a top-level context");
		return struct;
	}

}
