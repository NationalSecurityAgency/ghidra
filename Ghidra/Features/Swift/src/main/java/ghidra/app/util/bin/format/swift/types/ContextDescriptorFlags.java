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
 * Represents a Swift {@code ContextDescriptorFlags} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class ContextDescriptorFlags extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link ContextDescriptorFlags} structure
	 */
	public static final int SIZE = 4;

	private int flags;

	/**
	 * Create a new {@link ContextDescriptorFlags}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public ContextDescriptorFlags(BinaryReader reader) throws IOException {
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
	 * {@return the {@link ContextDescriptorKind}}
	 */
	public ContextDescriptorKind getKind() {
		return ContextDescriptorKind.valueOf(flags & 0x1f);
	}

	/**
	 * {@return whether or not the context has information about invertable protocols, which will 
	 * show up as a trailing field in the context descriptor}
	 */
	public boolean hasInvertableProtocols() {
		return (flags & 0x20) != 0;
	}

	/**
	 * {@return whether this is a unique record describing the referenced context}
	 */
	public boolean isUnique() {
		return (flags & 0x40) != 0;
	}

	/**
	 * {@return whether the context being described is generic}
	 */
	public boolean isGeneric() {
		return (flags & 0x80) != 0;
	}

	/**
	 * {@return whether there's something unusual about how the metadata is initialized}
	 */
	public MetadataInitializationKind getMetadataInitialization() {
		return MetadataInitializationKind.valueOf((flags >> 16) & 0x3);
	}

	/**
	 * {@return whether or not the type has extended import information}
	 */
	public boolean hasImportInfo() {
		return ((flags >> 18) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the generic type descriptor has a pointer to a list of canonical 
	 * prespecializations, or the non-generic type descriptor has a pointer to its singleton 
	 * metadata}
	 */
	public boolean hasCanonicalMetadataPrespecializationsOrSingletonMetadataPonter() {
		return ((flags >> 19) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the metadata contains a pointer to a layout string}
	 */
	public boolean hasLayoutString() {
		return ((flags >> 20) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the class has a default override table}
	 */
	public boolean hasClassDefaultOverrideTable() {
		return ((flags >> 22) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the class is an actor}
	 */
	public boolean isClassActor() {
		return ((flags >> 23) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the class is a default actor}
	 */
	public boolean isClassDefaultActor() {
		return ((flags >> 24) & 0x1) != 0;
	}

	/**
	 * {@return the kind of reference that this class makes to its resilient superclass descriptor. 
	 * A TypeReferenceKind.}
	 */
	public int getClassResilientSuperclassReferenceKind() {
		return (flags >> 25) & 0x7;
	}

	/**
	 * {@return whether the immediate class members in this metadata are allocated at negative 
	 * offsets}
	 */
	public boolean areClassImmediateMembersNegative() {
		return ((flags >> 28) & 0x1) != 0;
	}

	/**
	 * {@return Whether or not the context descriptor is for a class with resilient ancestry}
	 */
	public boolean hasClassResilientSuperclass() {
		return ((flags >> 29) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the context descriptor includes metadata for dynamically installing 
	 * method overrides at metadata instantiation time}
	 */
	public boolean hasClassOverrideTable() {
		return ((flags >> 30) & 0x1) != 0;
	}

	/**
	 * {@return whether or not the context descriptor includes metadata for dynamically constructing
	 * a class's vtables at metadata instantiation time}
	 */
	public boolean hasClassVTable() {
		return ((flags >> 31) & 0x1) != 0;
	}

	@Override
	public String getStructureName() {
		return ContextDescriptorFlags.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "context descriptor flags";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(ContextDescriptorKind.values()[0].toDataType(), 5, "kind",
				"Kind of context descriptor");
			struct.addBitField(BOOL, 1, "hasInvertableProtocols",
				"Whether or not the context has information about invertable protocols, which will show up as a trailing field in the context descriptor.");
			struct.addBitField(BOOL, 1, "isUnique",
				"Whether this is a unique record describing the referenced context.");
			struct.addBitField(BOOL, 1, "isGeneric",
				"Whether the context being described is generic.");
			struct.addBitField(DWORD, 8, "reserved", null);
			struct.addBitField(MetadataInitializationKind.values()[0].toDataType(), 2,
				"MetadataInitialization",
				"Whether there's something unusual about how the metadata is initialized.");
			struct.addBitField(BOOL, 1, "HasImportInfo",
				"Set if the type has extended import information.");
			struct.addBitField(BOOL, 1,
				"HasCanonicalMetadataPrespecializationsOrSingletonMetadataPonter",
				"Set if the generic type descriptor has a pointer to a list of canonical prespecializations, or the non-generic type descriptor has a pointer to its singleton metadata.");
			struct.addBitField(BOOL, 1, "HasLayoutString",
				"Set if the metadata contains a pointer to a layout string.");
			struct.addBitField(DWORD, 1, "reserved", null);
			struct.addBitField(BOOL, 1, "Class_HasDefaultOverrideTable", null);
			struct.addBitField(BOOL, 1, "Class_IsActor", "Set if the class is an actor.");
			struct.addBitField(BOOL, 1, "Class_IsDefaultActor",
				"Set if the class is a default actor class.");
			struct.addBitField(DWORD, 3, "Class_ResilientSuperclassReferenceKind",
				"The kind of reference that this class makes to its resilient superclass descriptor. A TypeReferenceKind.");
			struct.addBitField(BOOL, 1, "Class_AreImmediateMembersNegative",
				"Whether the immediate class members in this metadata are allocated at negative offsets.");
			struct.addBitField(BOOL, 1, "Class_HasResilientSuperclass",
				"Set if the context descriptor is for a class with resilient ancestry.");
			struct.addBitField(BOOL, 1, "Class_HasOverrideTable",
				"Set if the context descriptor includes metadata for dynamically installing method overrides at metadata instantiation time.");
			struct.addBitField(BOOL, 1, "Class_HasVTable",
				"Set if the context descriptor includes metadata for dynamically constructing a class's vtables at metadata instantiation time.");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		return struct;
	}
}
