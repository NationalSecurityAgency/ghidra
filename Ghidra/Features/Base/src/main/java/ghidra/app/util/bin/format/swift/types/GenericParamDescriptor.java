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
 * Represents a Swift {@code GenericParamDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class GenericParamDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link GenericParamDescriptor} structure
	 */
	public static final int SIZE = 1;

	private int value;

	/**
	 * Create a new {@link GenericParamDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public GenericParamDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		value = reader.readNextUnsignedByte();
	}

	/**
	 * {@return the value}
	 */
	public int getValue() {
		return value;
	}

	/**
	 * {@return the {@link GenericParamKind}}
	 */
	public GenericParamKind getKind() {
		return GenericParamKind.valueOf(value & 0x3f);
	}

	/**
	 * {@return whether or not the subject type of the requirement has a key argument}
	 */
	public boolean hasKeyArgument() {
		return (value & 0x80) != 0;
	}

	@Override
	public String getStructureName() {
		return GenericParamDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "generic param descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(GenericParamKind.values()[0].toDataType(), 7, "kind", null);
			struct.addBitField(BOOL, 1, "HasKeyArgument", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
