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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetRelativeContextPointer} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetRelativeProtocolRequirementPointer extends SwiftTypeMetadataStructure {

	public static final TypeDef dataType =
		new PointerTypedefBuilder(Pointer32DataType.dataType, null)
				.type(PointerType.RELATIVE)
				.bitMask(~1)
				.build();

	private int value;

	/**
	 * Creates a new {@link TargetRelativeProtocolRequirementPointer}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetRelativeProtocolRequirementPointer(BinaryReader reader) throws IOException {
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
		return TargetRelativeProtocolRequirementPointer.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "relative protocol requirement pointer";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dataType;
	}
}
