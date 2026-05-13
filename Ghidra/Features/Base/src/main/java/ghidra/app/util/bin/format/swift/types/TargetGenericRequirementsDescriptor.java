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

public class TargetGenericRequirementsDescriptor extends SwiftTypeMetadataStructure {

	private GenericRequirementFlags flags;
	private int param;
	private int thing;
	private GenericRequirementLayoutKind layout;
	private int genericParamIndex;
	private int protocols; // TODO: Make this a real InvertibleProtocolSet

	/**
	 * Creates a new {@link TargetGenericRequirementsDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetGenericRequirementsDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = new GenericRequirementFlags(reader);
		param = reader.readNextInt();
		thing = reader.readNextInt();
		layout = GenericRequirementLayoutKind.valueOf(thing); // union
		genericParamIndex = thing & 0xffff; // union
		protocols = (thing) & 0xffff; // union
	}

	/**
	 * {@return the flags}
	 */
	public GenericRequirementFlags getFlags() {
		return flags;
	}

	/**
	 * {@return the type that's constrained, described as a mangled name}
	 */
	public int getParam() {
		return param;
	}

	/**
	 * {@return the thing (same-type, class, protocol, conformance) the param is constrained to}
	 */
	public int getThing() {
		return thing;
	}

	/**
	 * {@return the layout if the requirement has Layout kind; otherwise, {@code null}}
	 */
	public GenericRequirementLayoutKind getLayout() {
		return layout;
	}

	/**
	 * {@return the index of the generic parameter whose set of invertible protocols has disabled
	 * checks}
	 * <p>
	 * Only valid if the requirement has {@link GenericRequirementKind#IntertedProtocol} kind
	 */
	public int getGenericParamIndex() {
		return genericParamIndex;
	}

	/**
	 * {@return the set of invertible protocols whose check is disabled}
	 * <p>
	 * Only valid if the requirement has {@link GenericRequirementKind#IntertedProtocol} kind
	 */
	public int getProtocols() {
		return protocols;
	}

	@Override
	public String getStructureName() {
		return TargetGenericRequirementsDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "generic requirements descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType invertedProtocolsStruct = new StructureDataType(CATEGORY_PATH, "InvertedProtocols", 0);
		invertedProtocolsStruct.add(WORD, "GenericParamIndex",
			"The index of the generic parameter to which this applies.");
		invertedProtocolsStruct.add(WORD, "Protocols",
			"The set of invertiable protocols whose check is disabled.");
		
		UnionDataType union =
			new UnionDataType(CATEGORY_PATH, "Union_TargetGenericRequirementsDescriptor");
		union.add(SwiftUtils.PTR_RELATIVE, "Type", "A mangled representation of the same-type or base class the param is constrained to.");
		union.add(SwiftUtils.PTR_RELATIVE, "Protocol", "The protocol the param is constrained to.");
		union.add(SwiftUtils.PTR_RELATIVE, "Conformance", "The conformance the param is constrained to use.");
		union.add(GenericRequirementLayoutKind.values()[0].toDataType(), "Layout",
			"The kind of layout constraint.");
		union.add(invertedProtocolsStruct, invertedProtocolsStruct.getName(), null);

		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(flags.toDataType(), "Flags", null);
		struct.add(SwiftUtils.PTR_RELATIVE, "Param",
			"The type that's constrained, described as a mangled name.");
		struct.add(union, union.getName(), null);
		return struct;
	}
}
