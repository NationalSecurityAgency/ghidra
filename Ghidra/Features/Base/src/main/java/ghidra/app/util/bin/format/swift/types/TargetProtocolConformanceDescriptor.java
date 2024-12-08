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
 * Represents a Swift TargetProtocolConformanceDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetProtocolConformanceDescriptor extends SwiftTypeMetadataStructure {
	
	private int protocolDescriptor;
	private int nominalTypeDescriptor;
	private int protocolWitnessTable;
	private int conformanceFlags;

	/**
	 * Creates a new {@link TargetProtocolConformanceDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetProtocolConformanceDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		protocolDescriptor = reader.readNextInt();
		nominalTypeDescriptor = reader.readNextInt();
		protocolWitnessTable = reader.readNextInt();
		conformanceFlags = reader.readNextInt();
	}

	/**
	 * Gets the protocol being conformed to
	 * 
	 * @return The protocol being conformed to
	 */
	public int getProtocolDescriptor() {
		return protocolDescriptor;
	}

	/**
	 * Gets some description of the type that conforms to the protocol
	 * 
	 * @return Some description of the type that conforms to the protocol
	 */
	public int getNominalTypeDescriptor() {
		return nominalTypeDescriptor;
	}

	/**
	 * Gets the witness table pattern, which may also serve as the witness table
	 * 
	 * @return The witness table pattern, which may also serve as the witness table
	 */
	public int getProtocolWitnessTable() {
		return protocolWitnessTable;
	}

	/**
	 * Gets various flags, including the kind of conformance
	 * 
	 * @return Various flags, including the kind of conformance
	 */
	public int getConformanceFlags() {
		return conformanceFlags;
	}

	@Override
	public String getStructureName() {
		return TargetProtocolConformanceDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "protocol conformance descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(DWORD, "ProtocolDescriptor", "The protocol being conformed to");
		struct.add(SwiftUtils.PTR_RELATIVE, "NominalTypeDescriptor",
			"Some description of the type that conforms to the protocol");
		struct.add(DWORD, "ProtocolWitnessTable",
			"The witness table pattern, which may also serve as the witness table");
		struct.add(DWORD, "ConformanceFlags", "Various flags, including the kind of conformance");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
