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
 * Represents a Swift FieldDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class FieldDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link FieldDescriptor} structure
	 */
	public static final int SIZE = 16;

	private String mangledTypeName;
	private int superclass;
	private int kind;
	private int fieldRecordSize;
	private int numFields;

	private List<FieldRecord> fieldRecords = new ArrayList<>();

	/**
	 * Creates a new {@link FieldDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public FieldDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		mangledTypeName = reader.readNext(SwiftUtils::relativeString);
		superclass = reader.readNextInt();
		kind = reader.readNextUnsignedShort();
		fieldRecordSize = reader.readNextUnsignedShort();
		numFields = reader.readNextInt();

		for (int i = 0; i < numFields; i++) {
			fieldRecords.add(new FieldRecord(reader));
		}
	}

	/**
	 * Gets the mangled type name
	 * 
	 * @return The mangled type name
	 */
	public String getMangledTypeName() {
		return mangledTypeName;
	}

	/**
	 * Gets the superclass
	 * 
	 * @return The superclass
	 */
	public int getSuperclass() {
		return superclass;
	}

	/**
	 * Gets the kind
	 * 
	 * @return The kind
	 */
	public int getKind() {
		return kind;
	}

	/**
	 * Gets the field record size
	 * 
	 * @return The field record size
	 */
	public int getFieldRecordSize() {
		return fieldRecordSize;
	}

	/**
	 * Gets the number of fields
	 * 
	 * @return The number of fields
	 */
	public int getNumFields() {
		return numFields;
	}

	/**
	 * Gets the {@link List} of {@link FieldRecord}s
	 * 
	 * @return The {@link List} of {@link FieldRecord}s
	 */
	public List<FieldRecord> getFieldRecords() {
		return fieldRecords;
	}

	@Override
	public String getStructureName() {
		return FieldDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "field descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(SwiftUtils.PTR_STRING, "MangledTypeName", "");
		struct.add(SwiftUtils.PTR_RELATIVE, "Superclass", "");
		struct.add(WORD, "Kind", "");
		struct.add(WORD, "FieldRecordSize", "");
		struct.add(DWORD, "NumFields", "");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
