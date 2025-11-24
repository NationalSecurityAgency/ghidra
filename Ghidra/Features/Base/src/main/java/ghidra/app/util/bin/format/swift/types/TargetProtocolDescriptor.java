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
 * Represents a Swift {@code TargetProtocolDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetProtocolDescriptor extends TargetContextDescriptor {

	private String name;
	private int numRequirementsInSig;
	private int numRequirements;
	private int associatedTypeNames;

	private List<TargetGenericRequirementsDescriptor> requirementsInSig = new ArrayList<>();
	private List<TargetProtocolRequirement> requirements = new ArrayList<>();

	/**
	 * Creates a new {@link TargetProtocolDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetProtocolDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		name = reader.readNext(SwiftUtils::relativeString);
		numRequirementsInSig = reader.readNextInt();
		numRequirements = reader.readNextInt();
		associatedTypeNames = reader.readNextInt();

		for (int i = 0; i < numRequirementsInSig; i++) {
			requirementsInSig.add(new TargetGenericRequirementsDescriptor(reader));
		}
		for (int i = 0; i < numRequirements; i++) {
			requirements.add(new TargetProtocolRequirement(reader));
		}
	}

	/**
	 * {@return the name of the protocol}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the number of generic requirements in the requirement signature of the protocol}
	 */
	public int getNumRequirementsInSignature() {
		return numRequirementsInSig;
	}

	/**
	 * {@return the number of requirements in the protocol}
	 */
	public int getNumRequirements() {
		return numRequirements;
	}

	/**
	 * @return the associated type names}
	 */
	public int getAssociatedTypeNames() {
		return associatedTypeNames; // TODO: it's a list...improve
	}

	/**
	 * {@return a {@link List} of generic requirements in the requirement signature of the protocol}
	 */
	public List<TargetGenericRequirementsDescriptor> getRequirementsInSignature() {
		return requirementsInSig;
	}

	/**
	 * {@return a {@link List} of requirements in the protocol}
	 */
	public List<TargetProtocolRequirement> getRequirements() {
		return requirements;
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public List<SwiftTypeMetadataStructure> getTrailingObjects() {
		List<SwiftTypeMetadataStructure> ret = new ArrayList<>();
		ret.addAll(requirementsInSig);
		ret.addAll(requirements);
		return ret;
	}

	@Override
	public String getStructureName() {
		return TargetProtocolDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "protocol descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(SwiftUtils.PTR_STRING, "Name", "The name of the protocol");
		struct.add(DWORD, "NumRequirementsInSignature",
			"The number of generic requirements in the requirement signature of the protocol");
		struct.add(DWORD, "NumRequirements", "The number of requirements in the protocol");
		struct.add(SwiftUtils.PTR_RELATIVE, "AssociatedTypeNames",
			"Associated type names, as a space-separated list in the same order as the requirements");
		return struct;
	}

}
