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
 * Represents a Swift {@code MethodDescriptorFlags} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class MethodDescriptorFlags extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link MethodDescriptorFlags} structure
	 */
	public static final int SIZE = 4;

	private int flags;

	/**
	 * Create a new {@link MethodDescriptorFlags}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public MethodDescriptorFlags(BinaryReader reader) throws IOException {
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
	 * {@return the {@link MethodDescriptorKind}}
	 */
	public MethodDescriptorKind getKind() {
		return MethodDescriptorKind.valueOf(flags & 0x0f);
	}

	/**
	 * {@return whether or not the method is an instance method}
	 */
	public boolean isInstance() {
		return (flags & 0x10) != 0;
	}

	/**
	 * {@return whether or not the method is dynamic}
	 */
	public boolean isDynamic() {
		return (flags & 0x20) != 0;
	}

	/**
	 * {@return whether or not the method is async}
	 */
	public boolean isAnsyc() {
		return (flags & 0x40) != 0;
	}

	/**
	 * {@return the extra descriminator}
	 */
	public int getExtraDescriminator() {
		return (flags >> 16) & 0xffff;
	}

	@Override
	public String getStructureName() {
		return MethodDescriptorFlags.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "method descriptor flags";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(MethodDescriptorKind.values()[0].toDataType(), 4, "kind", null);
			struct.addBitField(BOOL, 1, "IsInstance", null);
			struct.addBitField(BOOL, 1, "IsDynamic", null);
			struct.addBitField(BOOL, 1, "IsAsync", null);
			struct.addBitField(DWORD, 9, "reserved", null);
			struct.addBitField(DWORD, 16, "ExtraDescriminator", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
