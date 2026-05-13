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
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetClassDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetClassDescriptor extends TargetTypeContextDescriptor {

	private int superclassType;
	private int metadataNegativeSizeInWords;
	private int resilientMetadataBounds;
	private int metadataPositiveSizeInWords;
	private ExtraClassDescriptorFlags extraClassFlags;
	private int numImmediateMembers;
	private int numFields;
	private int fieldOffsetVectorOffset;

	// Trailing Objects
	private TargetTypeGenericContextDescriptorHeader genericHeader;
	private TargetResilientSuperclass resilientSuperclass;
	private TargetSingletonMetadataInitialization singleton;
	private TargetForeignMetadataInitialization foreign;
	private TargetVTableDescriptorHeader vtableHeader;
	private List<TargetMethodDescriptor> methodDescriptors = new ArrayList<>();
	private TargetOverrideTableHeader overrideHeader;
	private List<TargetMethodOverrideDescriptor> methodOverrideDescriptors = new ArrayList<>();
	private TargetObjCResilientClassStubInfo objcResilientClassStub;
	private InvertibleProtocolSet invertibleProtocolSet;

	/**
	 * Creates a new {@link TargetClassDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetClassDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		superclassType = reader.readNextInt();
		resilientMetadataBounds = reader.readNextInt();
		metadataNegativeSizeInWords = resilientMetadataBounds; // union
		extraClassFlags = new ExtraClassDescriptorFlags(reader);
		metadataPositiveSizeInWords = extraClassFlags.getFlags(); // union
		numImmediateMembers = reader.readNextInt();
		numFields = reader.readNextInt();
		fieldOffsetVectorOffset = reader.readNextInt();

		if (flags.isGeneric()) {
			genericHeader = new TargetTypeGenericContextDescriptorHeader(reader);
		}

		if (flags.hasClassResilientSuperclass()) {
			resilientSuperclass = new TargetResilientSuperclass(reader);
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

		if (flags.hasClassVTable()) {
			vtableHeader = new TargetVTableDescriptorHeader(reader);
			for (int i = 0; i < vtableHeader.getVTableSize(); i++) {
				methodDescriptors.add(new TargetMethodDescriptor(reader));
			}
		}

		if (flags.hasClassOverrideTable()) {
			overrideHeader = new TargetOverrideTableHeader(reader);
			for (int i = 0; i < overrideHeader.getNumEntries(); i++) {
				methodOverrideDescriptors.add(new TargetMethodOverrideDescriptor(reader));
			}
		}

		if (flags.hasClassResilientSuperclass() &&
			extraClassFlags.hasObjcResilientClassStub()) {
			objcResilientClassStub = new TargetObjCResilientClassStubInfo(reader);
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
		
		if (flags.hasClassDefaultOverrideTable()) {
			throw new IOException("Unimplemented TargetMethodDefaultOverride detected.");
		}
	}

	/**
	 * {@return the type of the superclass, expressed as a mangled type name that can refer to the 
	 * generic arguments of the subclass type}
	 */
	public int getSuperclassType() {
		return superclassType;
	}

	/**
	 * {@return a reference to a cache holding the metadata's extents if this descriptor has a
	 * resilient superclass; otherwise, 0}
	 */
	public int getResilientMetadataBounds() {
		return flags.hasClassResilientSuperclass() ? resilientMetadataBounds : 0;
	}

	/**
	 * {@return the negative size of metadata objects of this class (in words) if this descriptor 
	 * does not have a resilient superclass}
	 */
	public int getMetadataNegativeSizeInWords() {
		return !flags.hasClassResilientSuperclass() ? metadataNegativeSizeInWords : 0;
	}

	/**
	 * {@return flags used to do things like indicate the presence of an Objective-C resilient class
	 * stub if this descriptor has a resilient superclass; otherwise, {@code null}}
	 */
	public ExtraClassDescriptorFlags getExtraClassDescriptorFlags() {
		return flags.hasClassResilientSuperclass() ? extraClassFlags : null;
	}

	/**
	 * {@return the positive size of metadata objects of this class (in words) if this descriptor 
	 * does not have a resilient superclass}
	 */
	public int getMetadataPositiveSizeInWords() {
		return !flags.hasClassResilientSuperclass() ? metadataPositiveSizeInWords : 0;
	}

	/**
	 * {@return the number of additional members added by this class to the class metadata}
	 */
	public int getNumImmediateMembers() {
		return numImmediateMembers;
	}

	/**
	 * {@return the number of stored properties in the class, not including its superclasses}
	 * <p>
	 * If there is a field offset vector, this is its length.
	 */
	public int getNumFields() {
		return numFields;
	}

	/**
	 * {@return the offset of the field offset vector for this class's stored properties in its
	 * metadata, in words (0 means there is no field offset vector)}
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
	 * {@return the {@link TargetResilientSuperclass}, or {@code null} if it doesn't exist}
	 */
	public TargetResilientSuperclass getResilientSuperclass() {
		return resilientSuperclass;
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
	 * {@return the {@link TargetVTableDescriptorHeader}, or {@code null} if it doesn't exist}
	 */
	public TargetVTableDescriptorHeader getVTableDescriptorHeader() {
		return vtableHeader;
	}

	/**
	 * {@return the {@link List} of method descriptors}
	 */
	public List<TargetMethodDescriptor> getMethodDescriptors() {
		return methodDescriptors;
	}

	/**
	 * {@return the {@link TargetOverrideTableHeader}, or {@code null} if it doesn't exist}
	 */
	public TargetOverrideTableHeader getTargetOverrideTableHeader() {
		return overrideHeader;
	}

	/**
	 * {@return the {@link List} of method override descriptors}
	 */
	public List<TargetMethodOverrideDescriptor> getMethodOverrideDescriptors() {
		return methodOverrideDescriptors;
	}

	/**
	 * {@return the {@link TargetObjCResilientClassStubInfo}, or {@code null} if it doesn't exist}
	 */
	public TargetObjCResilientClassStubInfo getObjcResilientClassStub() {
		return objcResilientClassStub;
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
		if (resilientSuperclass != null) {
			ret.add(resilientSuperclass);
		}
		if (singleton != null) {
			ret.add(singleton);
		}
		if (foreign != null) {
			ret.add(foreign);
		}
		if (vtableHeader != null) {
			ret.add(vtableHeader);
			ret.addAll(methodDescriptors);
		}
		if (overrideHeader != null) {
			ret.add(overrideHeader);
			ret.addAll(methodOverrideDescriptors);
		}
		if (objcResilientClassStub != null) {
			ret.add(objcResilientClassStub);
		}
		if (invertibleProtocolSet != null) {
			ret.add(invertibleProtocolSet);
		}
		return ret;
	}

	@Override
	public String getStructureName() {
		return TargetClassDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "class descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		UnionDataType union1 = new UnionDataType(CATEGORY_PATH,
			"Union_MetadataNegativeSizeInWords_ResilientMetadataBounds");
		union1.add(DWORD, "MetadataNegativeSizeInWords",
			"If this descriptor does not have a resilient superclass, this is the negative size of metadata objects of this class (in words)");
		union1.add(SwiftUtils.PTR_RELATIVE, "ResilientMetadataBounds",
			"If this descriptor has a resilient superclass, this is a reference to a cache holding the metadata's extends.");

		UnionDataType union2 =
			new UnionDataType(CATEGORY_PATH, "Union_MetadataPositiveSizeInWords/ExtraClassFlags");
		union2.add(DWORD, "MetadataPositiveSizeInWords",
			"If this descriptor does not have a resilient superclass, this is the positive size of metadata objects of this class (in words)");
		union2.add(extraClassFlags.toDataType(), "ExtraClassFlags",
			"Otherwise, these flags are used to do things like indicating the presence of an Objective-C resilient class stub.");

		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(SwiftUtils.PTR_STRING, "SuperclassType",
			"The type of the superclass, expressed as a mangled type name that can refer to the generic arguments of the subclass type");
		struct.add(union1, "MetadataNegativeSizeInWords/ResilientMetadataBounds", null);
		struct.add(union2, "MetadataPositiveSizeInWords/ExtraClassFlags", null);
		struct.add(DWORD, "NumImmediateMembers",
			"The number of additional members added by this class to the class metadata");
		struct.add(DWORD, "NumFields",
			"The number of stored properties in the class, not including its superclasses. If there is a field offset vector, this is its length.");
		struct.add(DWORD, "FieldOffsetVectorOffset",
			"The offset of the field offset vector for this class's stored properties in its metadata, in words. 0 means there is no field offset vector.");
		return struct;
	}
}
