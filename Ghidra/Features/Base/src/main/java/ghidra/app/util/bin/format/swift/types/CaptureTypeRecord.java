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
 * Represents a Swift CaptureTypeRecord structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class CaptureTypeRecord extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link CaptureTypeRecord} structure
	 */
	public static final int SIZE = 4;

	private String mangledTypeName;

	/**
	 * Creates a new {@link CaptureTypeRecord}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public CaptureTypeRecord(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		mangledTypeName = reader.readNext(SwiftUtils::relativeString);

	}

	/**
	 * Gets the mangled type name
	 * 
	 * @return The mangled type name
	 */
	public String getMangledTypeName() {
		return mangledTypeName;
	}

	@Override
	public String getStructureName() {
		return CaptureTypeRecord.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "capture type record";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(SwiftUtils.PTR_STRING, "MangledTypeName", "");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
