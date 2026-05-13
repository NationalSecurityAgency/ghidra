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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetProtocolConformanceDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetProtocolConformanceDescriptor extends SwiftTypeMetadataStructure {
	
	private int protocol;
	private int typeRef;
	private int witnessTablePattern;
	private ConformanceFlags flags;

	// Trailing objects
	private TargetRelativeContextPointer retroactiveContext;
	private TargetResilientWitnessHeader resilientWitnessHeader;
	private List<TargetResilientWitness> resilientWitnesses = new ArrayList<>();
	private TargetGenericWitnessTable genericWitnessTable;

	/**
	 * Creates a new {@link TargetProtocolConformanceDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetProtocolConformanceDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		protocol = reader.readNextInt();
		typeRef = reader.readNextInt();
		witnessTablePattern = reader.readNextInt();
		flags = new ConformanceFlags(reader);
		
		if (flags.isRetroactive()) {
			retroactiveContext = new TargetRelativeContextPointer(reader);
		}

		if (flags.hasResilientWitnesses()) {
			resilientWitnessHeader = new TargetResilientWitnessHeader(reader);
			for (int i = 0; i < resilientWitnessHeader.getNumWitnesses(); i++) {
				resilientWitnesses.add(new TargetResilientWitness(reader));
			}
		}

		if (flags.hasGenericWitnessTable()) {
			genericWitnessTable = new TargetGenericWitnessTable(reader);
		}
	}

	/**
	 * {@return the protocol being conformed to}
	 */
	public int getProtocol() {
		return protocol;
	}

	/**
	 * {@return some description of the type that conforms to the protocol}
	 */
	public int getTypeRef() {
		return typeRef;
	}

	/**
	 * {@return the witness table pattern, which may also serve as the witness table}
	 */
	public int getWitnessTablePattern() {
		return witnessTablePattern;
	}

	/**
	 * {@return various flags, including the kind of conformance}
	 */
	public ConformanceFlags getConformanceFlags() {
		return flags;
	}
	
	/**
	 * {@return the {@link TargetRelativeContextPointer retroactive context}, or {@code null} if it 
	 * doesn't exist}
	 */
	public TargetRelativeContextPointer getRetroactiveContext() {
		return retroactiveContext;
	}

	/**
	 * {@return the {@link TargetResilientWitnessHeader}, or {@code null} if it doesn't exist}
	 */
	public TargetResilientWitnessHeader getResilientWitnessHeader() {
		return resilientWitnessHeader;
	}

	/**
	 * {@return the {@link List} of resilient witnesses}
	 */
	public List<TargetResilientWitness> getResilientWitnesses() {
		return resilientWitnesses;
	}

	/**
	 * {@return the {@link TargetGenericWitnessTable}, or {@code null} if it doesn't exist}
	 */
	public TargetGenericWitnessTable getGenericWitnessTable() {
		return genericWitnessTable;
	}

	@Override
	public List<SwiftTypeMetadataStructure> getTrailingObjects() {
		List<SwiftTypeMetadataStructure> ret = new ArrayList<>();
		if (retroactiveContext != null) {
			ret.add(retroactiveContext);
		}
		if (resilientWitnessHeader != null) {
			ret.add(resilientWitnessHeader);
			ret.addAll(resilientWitnesses);
		}
		if (genericWitnessTable != null) {
			ret.add(genericWitnessTable);
		}
		return ret;
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
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(SwiftUtils.PTR_RELATIVE_MASKED, "Protocol", "The protocol being conformed to");
		struct.add(SwiftUtils.PTR_RELATIVE, "TypeRef",
			"Some description of the type that conforms to the protocol");
		struct.add(DWORD, "WitnessTablePattern",
			"The witness table pattern, which may also serve as the witness table");
		struct.add(flags.toDataType(), "Flags", "Various flags, including the kind of conformance");
		return struct;
	}

}
