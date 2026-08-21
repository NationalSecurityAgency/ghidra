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
public class GenericContextDescriptorFlags extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link GenericContextDescriptorFlags} structure
	 */
	public static final int SIZE = 2;

	private short flags;

	/**
	 * Create a new {@link GenericContextDescriptorFlags}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public GenericContextDescriptorFlags(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = reader.readNextShort();
	}

	/**
	 * {@return the flags}
	 */
	public short getFlags() {
		return flags;
	}

	/**
	 * {@return whether or not the generic context has at least one type parameter pack, in which
	 * case the generic context will have a trailing GenericPackShapeHeader}
	 */
	public boolean hasTypePacks() {
		return (flags & 0x1) != 0;
	}

	/**
	 * {@return whether or not the generic context has any conditional conformances to inverted
	 * protocols, in which case the generic context will have a trailing InvertibleProtocolSet and
	 * conditional requirements}
	 */
	public boolean hasConditionalInvertedProtocols() {
		return (flags & 0x2) != 0;
	}

	/**
	 * {@return whether or not the generic context has at least one value parameter, in which case
	 * the generic context will have a trailing GenericValueHeader}
	 */
	public boolean hasValues() {
		return (flags & 0x4) != 0;
	}

	@Override
	public String getStructureName() {
		return GenericContextDescriptorFlags.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "generic context descriptor flags";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(BOOL, 1, "TypePacks",
				"Has at least one type parameter pack and a trailing GenericPackShapeHeader.");
			struct.addBitField(BOOL, 1, "ConditionalInvertedProtocols",
				"Has any conditional conformances to inverted protocols and a trailing InvertibleProtocolSet and conditional requirements.");
			struct.addBitField(BOOL, 1, "Values",
				"Has at least one value parameter, and a trailing GenericValueHeader.");
			struct.addBitField(WORD, 13, "reserved", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
