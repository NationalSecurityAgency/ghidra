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

public class TargetProtocolRequirement extends SwiftTypeMetadataStructure {

	private ProtocolRequirementFlags flags;
	private int impl;

	/**
	 * Creates a new {@link TargetProtocolRequirement}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetProtocolRequirement(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = new ProtocolRequirementFlags(reader);
		impl = reader.readNextInt();
	}

	/**
	 * {@return the flags}
	 */
	public ProtocolRequirementFlags getFlags() {
		return flags;
	}

	/**
	 * {@return the optional default implementation of the protocol}
	 */
	public int getImpl() {
		return impl;
	}

	@Override
	public String getStructureName() {
		return TargetProtocolRequirement.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "protocol requirement";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		UnionDataType union = new UnionDataType(CATEGORY_PATH,
			"Union_DefaultFuncImplementation_DefaultImplementation");
		union.add(SwiftUtils.PTR_RELATIVE, "DefaultFuncImplementation", null);
		union.add(SwiftUtils.PTR_RELATIVE, "DefaultImplementation", null);

		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(flags.toDataType(), "Flags", null);
		struct.add(union, "Implementation", "The optional default implementation.");
		return struct;
	}
}
