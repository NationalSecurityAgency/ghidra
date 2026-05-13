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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code FieldRecord} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class FieldRecord extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link FieldRecord} structure
	 */
	public static final int SIZE = 12;

	private int flags;
	private String mangledTypeName;
	private String fieldName;

	/**
	 * Creates a new {@link FieldRecord}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public FieldRecord(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = reader.readNextInt();
		mangledTypeName = reader.readNext(SwiftUtils::relativeString);
		fieldName = reader.readNext(SwiftUtils::relativeString);
	}

	/**
	 * {@return the flags}
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * {@return the mangled type name}
	 */
	public String getMangledTypeName() {
		return mangledTypeName;
	}

	/**
	 * {@return the field name}
	 */
	public String getFieldName() {
		return fieldName;
	}

	@Override
	public String getStructureName() {
		return FieldRecord.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "field record";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(DWORD, "Flags", "");
		struct.add(SwiftUtils.PTR_STRING, "MangledTypeName", "");
		struct.add(SwiftUtils.PTR_STRING, "FieldName", "");
		return struct;
	}

}
