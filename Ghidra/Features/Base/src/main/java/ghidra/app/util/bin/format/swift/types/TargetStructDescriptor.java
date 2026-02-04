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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetStructDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetStructDescriptor extends TargetTypeContextDescriptor {

	private int numFields;
	private int fieldOffsetVectorOffset;

	// Trailing objects
	private TargetTypeGenericContextDescriptorHeader genericHeader;
	private TargetSingletonMetadataInitialization singleton;
	private TargetForeignMetadataInitialization foreign;
	private InvertibleProtocolSet invertibleProtocolSet;

	/**
	 * Creates a new {@link TargetStructDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetStructDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		numFields = reader.readNextInt();
		fieldOffsetVectorOffset = reader.readNextInt();

		if (flags.isGeneric()) {
			genericHeader = new TargetTypeGenericContextDescriptorHeader(reader);
		}

		switch (flags.getMetadataInitialization()) {
			case NoMetadataInitialization:
				break;
			case SingletonMetadataInitialization:
				singleton = new TargetSingletonMetadataInitialization(reader, flags);
				break;
			case ForeignMetadataInitialization:
				foreign = new TargetForeignMetadataInitialization(reader);
				break;
		}

		if (flags.isGeneric() &&
			flags.hasCanonicalMetadataPrespecializationsOrSingletonMetadataPonter()) {
			throw new IOException("Unimplemented TargetCanonicalSpecializedMetadatas detected.");
		}

		if (flags.hasInvertableProtocols()) {
			invertibleProtocolSet = new InvertibleProtocolSet(reader);
		}

		if (!flags.isGeneric() &&
			flags.hasCanonicalMetadataPrespecializationsOrSingletonMetadataPonter()) {
			throw new IOException("Unimplemented TargetSingletonMetadataPointer detected.");
		}
	}

	/**
	 * {@return the number of stored properties in the struct (if there is a field offset vector, 
	 * this is its length}
	 */
	public int getNumFields() {
		return numFields;
	}

	/**
	 * {@return the offset of the field offset vector for this struct's stored properties in its 
	 * metadata, if any. 0 means there is no field offset vector}
	 */
	public int getFieldOffsetVectorOffset() {
		return fieldOffsetVectorOffset;
	}

	/**
	 * {@return the {@link TargetTypeGenericContextDescriptorHeader}, or {@code null} if it doesn't 
	 * exist}
	 */
	public TargetTypeGenericContextDescriptorHeader getGenericHeader() {
		return genericHeader;
	}

	/**
	 * {@return the {@link TargetSingletonMetadataInitialization}, or {@code null} if it doesn't
	 * exist}
	 */
	public TargetSingletonMetadataInitialization getTargetSingletonMetadataInitialization() {
		return singleton;
	}

	/**
	 * {@return the {@link TargetForeignMetadataInitialization}, or {@code null} if it doesn't
	 * exist}
	 */
	public TargetForeignMetadataInitialization getTargetForeignMetadataInitialization() {
		return foreign;
	}

	/**
	 * {@return the {@link InvertibleProtocolSet}, or {@code null} if it doens't exist}
	 */
	public InvertibleProtocolSet getInvertibleProtocolSet() {
		return invertibleProtocolSet;
	}

	@Override
	public List<SwiftTypeMetadataStructure> getTrailingObjects() {
		List<SwiftTypeMetadataStructure> ret = new ArrayList<>();
		if (genericHeader != null) {
			ret.add(genericHeader);
			ret.addAll(genericHeader.getTrailingObjects());
		}
		if (singleton != null) {
			ret.add(singleton);
		}
		if (foreign != null) {
			ret.add(foreign);
		}
		if (invertibleProtocolSet != null) {
			ret.add(invertibleProtocolSet);
		}
		return ret;
	}

	@Override
	public String getStructureName() {
		return TargetStructDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "struct descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(DWORD, "NumFields",
			"The number of stored properties in the struct. If there is a field offset vector, this is its length.");
		struct.add(DWORD, "FieldOffsetVectorOffset",
			"The offset of the field offset vector for this struct's stored properties in its metadata, if any. 0 means there is no field offset vector.");
		return struct;
	}

}
