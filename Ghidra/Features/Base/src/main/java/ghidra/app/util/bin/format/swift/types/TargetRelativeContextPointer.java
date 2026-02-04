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
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetRelativeContextPointer} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataRef.h">swift/ABI/MetadataRef.h</a> 
 */
public class TargetRelativeContextPointer extends SwiftTypeMetadataStructure {

	private int value;

	/**
	 * Creates a new {@link TargetRelativeContextPointer}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetRelativeContextPointer(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		value = reader.readNextInt();
	}

	/**
	 * {@return the pointer value}
	 */
	public long getValue() {
		return value;
	}

	@Override
	public String getStructureName() {
		return TargetRelativeContextPointer.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "relative context pointer";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return SwiftUtils.PTR_RELATIVE_MASKED;
	}
}
