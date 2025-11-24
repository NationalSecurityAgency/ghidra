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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetGenericContextDescriptorHeader} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/GenericContext.h">swift/ABI/GenericContext.h</a> 
 */
public class TargetGenericContextDescriptorHeader extends SwiftTypeMetadataStructure {

	private int numParams;
	private int numRequirements;
	private int numKeyArguments;
	private GenericContextDescriptorFlags flags;

	private List<GenericParamDescriptor> params = new ArrayList<>();
	private List<TargetGenericRequirementsDescriptor> requirements = new ArrayList<>();

	/**
	 * Creates a new {@link TargetGenericContextDescriptorHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetGenericContextDescriptorHeader(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		numParams = reader.readNextUnsignedShort();
		numRequirements = reader.readNextUnsignedShort();
		numKeyArguments = reader.readNextUnsignedShort();
		flags = new GenericContextDescriptorFlags(reader);

		for (int i = 0; i < numParams; i++) {
			params.add(new GenericParamDescriptor(reader));
		}

		// It seems we have to round to the next 4 byte boundary after reading the params???
		reader.setPointerIndex((reader.getPointerIndex() + 3) & (~3));

		for (int i = 0; i < numRequirements; i++) {
			requirements.add(new TargetGenericRequirementsDescriptor(reader));
		}
	}

	/**
	 * {@return the number of (source-written) generic parameters, and thus the number of 
	 * GenericParamDescriptors associated with this context}
	 */
	public int getNumParams() {
		return numParams;
	}

	/**
	 * {@return the number of GenericRequirementDescriptors in this generic signature}
	 */
	public int getNumRequirements() {
		return numRequirements;
	}

	/**
	 * {@return the size of the "key" area of the argument layout, in words}
	 * <p>
	 * Key arguments include shape classes, generic parameters, and conformance requirements which
	 * are part of the identity of the context.
	 */
	public int getNumKeyArguments() {
		return numKeyArguments;
	}

	/**
	 * {@return the flags}
	 */
	public GenericContextDescriptorFlags getFlags() {
		return flags;
	}

	/**
	 * {@return the {@link List} of generic parameter descriptors}
	 */
	public List<GenericParamDescriptor> getParams() {
		return params;
	}

	/**
	 * {@return the {@link List} of generic requirements descriptors}
	 */
	public List<TargetGenericRequirementsDescriptor> getRequirements() {
		return requirements;
	}

	@Override
	public List<SwiftTypeMetadataStructure> getTrailingObjects() {
		List<SwiftTypeMetadataStructure> ret = new ArrayList<>();
		ret.addAll(params);
		ret.addAll(requirements);
		return ret;
	}

	@Override
	public String getStructureName() {
		return TargetGenericContextDescriptorHeader.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "generic context descriptor header";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(WORD, "NumParams",
			"The number of (source-written) generic parameters, and thus the number of GenericParamDescriptors associated with this context.");
		struct.add(WORD, "NumRequirements",
			"The number of GenericRequirementDescriptors in this generic signature.");
		struct.add(WORD, "NumKeyArguments",
			"The size of the key area of the argument layout, in words.");
		struct.add(flags.toDataType(), "Flags", "");
		return struct;
	}
}
