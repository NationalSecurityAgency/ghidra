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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code GenericRequirementFlags} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class GenericRequirementFlags extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link GenericRequirementFlags} structure
	 */
	public static final int SIZE = 4;

	private int flags;

	/**
	 * Create a new {@link GenericRequirementFlags}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public GenericRequirementFlags(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = reader.readNextInt();
	}

	/**
	 * {@return the flags}
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * {@return the {@link GenericRequirementKind}}
	 */
	public GenericRequirementKind getKind() {
		return GenericRequirementKind.valueOf(flags & 0x1f);
	}

	/**
	 * {@return whether or not the subject type of the requirement is a pack}
	 */
	public boolean isPackRequirement() {
		return (flags & 0x20) != 0;
	}

	/**
	 * {@return whether or not the subject type of the requirement has a key argument}
	 */
	public boolean hasKeyArgument() {
		return (flags & 0x80) != 0;
	}

	/**
	 * {@return whether or not the subject type of the requirement is a value}
	 */
	public boolean isValueRequirement() {
		return (flags & 0x100) != 0;
	}

	@Override
	public String getStructureName() {
		return GenericRequirementFlags.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "generic requirement flags";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(GenericRequirementKind.values()[0].toDataType(), 5, "kind", null);
			struct.addBitField(BOOL, 1, "isPackRequirement",
				"If true, the subject type of the requirement is a pack.");
			struct.addBitField(BOOL, 1, "legacy",
				"Don't set 0x40 for compatibility with pre-Swift 5.8 runtimes");
			struct.addBitField(BOOL, 1, "hasKeyArgument", null);
			struct.addBitField(BOOL, 1, "isValueRequirement",
				"If true, the subject type of the requirement is a value.");
			struct.addBitField(DWORD, 23, "reserved", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
