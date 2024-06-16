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
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift AssociatedTypeRecord structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class AssociatedTypeRecord extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of an {@link AssociatedTypeRecord} structure
	 */
	public static final int SIZE = 8;

	private String name;
	private String substitutedTypeName;

	/**
	 * Creates a new {@link AssociatedTypeRecord}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public AssociatedTypeRecord(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		name = reader.readNext(SwiftUtils::relativeString);
		substitutedTypeName = reader.readNext(SwiftUtils::relativeString);
	}

	/**
	 * Gets the name
	 * 
	 * @return The name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the substituted type name
	 * 
	 * @return The substituted type name
	 */
	public String getSubstitutedTypeName() {
		return substitutedTypeName;
	}

	@Override
	public String getStructureName() {
		return AssociatedTypeRecord.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "associated type record";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(SwiftUtils.PTR_STRING, "Name", "");
		struct.add(SwiftUtils.PTR_STRING, "SubstitutedTypeName", "");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
