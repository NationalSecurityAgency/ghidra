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
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift TargetClassDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetClassDescriptor extends TargetTypeContextDescriptor {

	private int superclassType;
	private int metadataNegativeSizeInWords;
	private int metadataPositiveSizeInWords;
	private int numImmediateMembers;
	private int numFields;

	/**
	 * Creates a new {@link TargetClassDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetClassDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		superclassType = reader.readNextInt();
		metadataNegativeSizeInWords = reader.readNextInt();
		metadataPositiveSizeInWords = reader.readNextInt();
		numImmediateMembers = reader.readNextInt();
		numFields = reader.readNextInt();
	}

	/**
	 * Gets the type of the superclass, expressed as a mangled type name that can refer to the 
	 * generic arguments of the subclass type
	 * 
	 * @return The type of the superclass, expressed as a mangled type name that can refer to the 
	 *   generic arguments of the subclass type
	 */
	public int getSuperclassType() {
		return superclassType;
	}

	/**
	 * If this descriptor does not have a resilient superclass, this is the negative size of 
	 * metadata objects of this class (in words). If this descriptor has a resilient superclass, 
	 * this is a reference to a cache holding the metadata's extents.
	 * 
	 * @return The negative size of metadata objects of this class (in words) or a reference to a 
	 *   cache holding the metadata's extents
	 */
	public int getMetadataNegativeSizeInWords() {
		return metadataNegativeSizeInWords;
	}

	/**
	 * If this descriptor does not have a resilient superclass, this is the positive size of 
	 * metadata objects of this class (in words). Otherwise, these flags are used to do things like 
	 * indicate the presence of an Objective-C resilient class stub.
	 * 
	 * @return The positive size of metadata objects of this class (in words) or flags used to do
	 *   things like indicate the presence of an Objective-C resilient class stub.
	 */
	public int getMetadataPositiveSizeInWords() {
		return metadataPositiveSizeInWords;
	}

	/**
	 * Gets the number of additional members added by this class to the class metadata
	 * 
	 * @return The number of additional members added by this class to the class metadata
	 */
	public int getNumImmediateMembers() {
		return numImmediateMembers;
	}
	
	/**
	 * Gets the number of stored properties in the class, not including its superclasses. If there 
	 * is a field offset vector, this is its length.
	 * 
	 * @return The number of stored properties in the class, not including its superclasses. 
	 *   If there is a field offset vector, this is its length.
	 */
	public int getNumFields() {
		return numFields;
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
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(SwiftUtils.PTR_STRING, "SuperclassType",
			"The type of the superclass, expressed as a mangled type name that can refer to the generic arguments of the subclass type");
		struct.add(DWORD, "MetadataNegativeSizeInWords",
			"If this descriptor does not have a resilient superclass, this is the negative size of metadata objects of this class (in words)");
		struct.add(DWORD, "MetadataPositiveSizeInWords",
			"If this descriptor does not have a resilient superclass, this is the positive size of metadata objects of this class (in words)");
		struct.add(DWORD, "NumImmediateMembers",
			"The number of additional members added by this class to the class metadata");
		struct.add(DWORD, "NumFields",
			"The number of stored properties in the class, not including its superclasses. If there is a field offset vector, this is its length.");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
