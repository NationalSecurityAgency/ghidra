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
 * Represents a Swift {@code ExtraClassDescriptorFlags} enum
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class ExtraClassDescriptorFlags extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link ExtraClassDescriptorFlags} structure
	 */
	public static final int SIZE = 4;

	private int flags;

	/**
	 * Creates a new {@link ExtraClassDescriptorFlags}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public ExtraClassDescriptorFlags(BinaryReader reader) throws IOException {
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
	 * {@return whether or not the context descriptor includes a pointer to an Objective-C resilient class stub structure}
	 * <p>
	 * Only meaningful for class descriptors when Objective-C interop is enabled.
	 */
	public boolean hasObjcResilientClassStub() {
		return (flags & 0x1) != 0;
	}

	@Override
	public String getStructureName() {
		return ExtraClassDescriptorFlags.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "extra class descriptor flags";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(BOOL, 1, "HasObjCResilientClassStub",
				"Set if the context descriptor includes a pointer to an Objective-C resilient class stub structure. Only meaningful for class descriptors when Objective-C interop is enabled.");
			struct.addBitField(DWORD, 31, "reserved", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
