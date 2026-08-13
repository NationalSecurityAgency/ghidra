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
 * Represents a Swift {@code ConformanceFlags} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class ConformanceFlags extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link ConformanceFlags} structure
	 */
	public static final int SIZE = 4;

	private int flags;

	/**
	 * Create a new {@link ConformanceFlags}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public ConformanceFlags(BinaryReader reader) throws IOException {
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
	 * {@return the {@link TypeReferenceKind}}
	 */
	public TypeReferenceKind getKind() {
		return TypeReferenceKind.valueOf((flags >> 3) & 0x3);
	}

	/**
	 * {@return whether or not it is retroactive}
	 */
	public boolean isRetroactive() {
		return ((flags >> 6) & 0x1) != 0;
	}

	/**
	 * {@return whether or not it is synthesized non-unique}
	 */
	public boolean isSynthesizedNonUnique() {
		return ((flags >> 7) & 0x1) != 0;
	}

	/**
	 * {@return the number of conditional requirements}
	 */
	public int getNumConditionalRequirements() {
		return (flags >> 8) & 0x8;
	}

	/**
	 * {@return whether or not it has resilient witnesses}
	 */
	public boolean hasResilientWitnesses() {
		return ((flags >> 16) & 0x1) != 0;
	}

	/**
	 * {@return whether or not it a generic witness table}
	 */
	public boolean hasGenericWitnessTable() {
		return ((flags >> 17) & 0x1) != 0;
	}

	/**
	 * {@return whether or not it is conformance of protocol}
	 */
	public boolean isConformanceOfProtocol() {
		return ((flags >> 18) & 0x1) != 0;
	}

	/**
	 * {@return whether or not it has global actor isolation}
	 */
	public boolean hasGlobalActorIsolation() {
		return ((flags >> 19) & 0x1) != 0;
	}

	/**
	 * {@return the number of conditional pack descriptors}
	 */
	public int getNumConditionalPackDescriptor() {
		return (flags >> 24) & 0x8;
	}

	@Override
	public String getStructureName() {
		return ConformanceFlags.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "conformance flags";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(DWORD, 3, "UnusedLowBits", "historical conformance kind");
			struct.addBitField(getKind().toDataType(), 3, "TypeMetadataKind",
				"8 type reference kinds");
			struct.addBitField(BOOL, 1, "IsRetroactive", null);
			struct.addBitField(BOOL, 1, "IsSynthesizedNonUnique", null);
			struct.addBitField(DWORD, 8, "NumConditionalRequirements", null);
			struct.addBitField(BOOL, 1, "HasResilientWitnesses", null);
			struct.addBitField(BOOL, 1, "HasGenericWitnessTable", null);
			struct.addBitField(BOOL, 1, "IsConformanceOfProtocol", null);
			struct.addBitField(BOOL, 1, "HasGlobalActorIsolation", null);
			struct.addBitField(DWORD, 4, "reserved", null);
			struct.addBitField(DWORD, 8, "NumConditionalPackDescriptor", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
