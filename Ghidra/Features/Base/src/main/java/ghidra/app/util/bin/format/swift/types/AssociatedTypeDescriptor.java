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
 * Represents a Swift AssociatedTypeDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class AssociatedTypeDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of an {@link AssociatedTypeDescriptor} structure
	 */
	public static final int SIZE = 16;

	private String conformingTypeName;
	private String protocolTypeName;
	private int numAssociatedTypes;
	private int associatedTypeRecordSize;

	private List<AssociatedTypeRecord> associatedTypeRecords = new ArrayList<>();

	/**
	 * Creates a new {@link AssociatedTypeDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public AssociatedTypeDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		conformingTypeName = reader.readNext(SwiftUtils::relativeString);
		protocolTypeName = reader.readNext(SwiftUtils::relativeString);
		numAssociatedTypes = reader.readNextInt();
		associatedTypeRecordSize = reader.readNextInt();

		for (int i = 0; i < numAssociatedTypes; i++) {
			associatedTypeRecords.add(new AssociatedTypeRecord(reader));
		}
	}

	/**
	 * Gets the conforming type name
	 * 
	 * @return The conforming type name
	 */
	public String getConformingTypeName() {
		return conformingTypeName;
	}

	/**
	 * Gets the protocol type name
	 * 
	 * @return The protocol type name
	 */
	public String getProtocolTypeName() {
		return protocolTypeName;
	}

	/**
	 * Gets the number of associated types
	 * 
	 * @return The number of associated types
	 */
	public int getNumAssociatedTypes() {
		return numAssociatedTypes;
	}

	/**
	 * Gets the associated type record size
	 * 
	 * @return The associated type record size
	 */
	public int getAssociatedTypeRecordSize() {
		return associatedTypeRecordSize;
	}

	/**
	 * Gets the {@link List} of {@link AssociatedTypeRecord}s
	 * 
	 * @return The {@link List} of {@link AssociatedTypeRecord}s
	 */
	public List<AssociatedTypeRecord> getAssociatedTypeRecords() {
		return associatedTypeRecords;
	}

	@Override
	public String getStructureName() {
		return AssociatedTypeDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "associated type descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(SwiftUtils.PTR_STRING, "ConformingTypeName", "");
		struct.add(SwiftUtils.PTR_STRING, "ProtocolTypeName", "");
		struct.add(DWORD, "NumAssociatedTypes", "");
		struct.add(DWORD, "AssociatedTypeRecordSize", "");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
