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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift TargetContextDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetContextDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link TargetContextDescriptor} structure
	 */
	public static final int SIZE = 8;

	private int flags;
	private int parent;

	/**
	 * Create a new {@link TargetContextDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetContextDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = reader.readNextInt();
		parent = reader.readNextInt();
	}

	/**
	 * Gets the flags
	 * 
	 * @return The flags
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Gets the parent's relative offset
	 * 
	 * @return The parent's relative offset
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
	 * Gets this class's structure name (will not be affected by subclass's name)
	 * 
	 * @return This class's structure name
	 */
	private final String getMyStructureName() {
		return TargetContextDescriptor.class.getSimpleName();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getMyStructureName(), 0);
		struct.add(DWORD, "Flags",
			"Flags describing the context, including its kind and format version");
		struct.add(SwiftUtils.PTR_RELATIVE, "Parent",
			"The parent context, or null if this is a top-level context");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
