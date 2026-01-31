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

public class TargetResilientWitness extends SwiftTypeMetadataStructure {

	private TargetRelativeProtocolRequirementPointer requirement;
	private int impl;

	/**
	 * Creates a new {@link TargetResilientWitness}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetResilientWitness(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		requirement = new TargetRelativeProtocolRequirementPointer(reader);
		impl = reader.readNextInt();
	}

	/**
	 * {@return the requirement}
	 */
	public TargetRelativeProtocolRequirementPointer getRequirement() {
		return requirement;
	}

	/**
	 * {@return the implementation}
	 */
	public int getImpl() {
		return impl;
	}

	@Override
	public String getStructureName() {
		return TargetResilientWitness.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "resilient witness";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		UnionDataType union = new UnionDataType(CATEGORY_PATH,
			"Union_Impl_FuncImpl");
		union.add(SwiftUtils.PTR_RELATIVE, "Impl", null);
		union.add(SwiftUtils.PTR_RELATIVE, "FuncImpl", null);

		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(TargetRelativeProtocolRequirementPointer.dataType, "Requirement", null);
		struct.add(union, "Implementation", null);
		return struct;
	}
}
