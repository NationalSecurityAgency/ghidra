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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetOverrideTableHeader} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetOverrideTableHeader extends SwiftTypeMetadataStructure {

	private long numEntries;

	/**
	 * Creates a new {@link TargetOverrideTableHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetOverrideTableHeader(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		numEntries = reader.readNextUnsignedInt();
	}

	/**
	 * {@return the number of MethodOverrideDescriptor records following the vtable override header
	 * in the class's nominal type descriptor}
	 */
	public long getNumEntries() {
		return numEntries;
	}

	@Override
	public String getStructureName() {
		return TargetOverrideTableHeader.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "override table header";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(DWORD, "NumEntries",
			"The number of MethodOverrideDescriptor records following the vtable override header in the class's nominal type descriptor.");
		return struct;
	}
}
