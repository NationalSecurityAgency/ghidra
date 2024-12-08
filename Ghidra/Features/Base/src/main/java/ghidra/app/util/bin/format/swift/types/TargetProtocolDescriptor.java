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
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift TargetProtocolDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public final class TargetProtocolDescriptor extends TargetContextDescriptor {

	private String name;
	private int numRequirementsInSig;
	private int numRequirements;
	private int associatedTypeNames;

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
	}

	/**
	 * Gets the name of the protocol
	 * 
	 * @return The name of the protocol
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the number of generic requirements in the requirement signature of the protocol
	 * 
	 * @return The number of generic requirements in the requirement signature of the protocol
	 */
	public int getNumRequirementsInSignature() {
		return numRequirementsInSig;
	}

	/**
	 * Gets the number of requirements in the protocol
	 * 
	 * @return The number of requirements in the protocol
	 */
	public int getNumRequirements() {
		return numRequirements;
	}

	/**
	 * Gets the associated type names
	 * 
	 * @return The associated type names
	 */
	public int getAssociatedTypeNames() {
		return associatedTypeNames; // TODO: it's a list...improve
	}

	@Override
	public String toString() {
		return name;
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
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(super.toDataType(), super.getStructureName(), "");
		struct.add(SwiftUtils.PTR_STRING, "Name", "The name of the protocol");
		struct.add(DWORD, "NumRequirementsInSignature",
			"The number of generic requirements in the requirement signature of the protocol");
		struct.add(DWORD, "NumRequirements", "The number of requirements in the protocol");
		struct.add(DWORD, "AssociatedTypeNames",
			"Associated type names, as a space-separated list in the same order as the requirements");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}

}
