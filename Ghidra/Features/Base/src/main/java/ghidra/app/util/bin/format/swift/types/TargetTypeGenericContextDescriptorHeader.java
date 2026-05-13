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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetTypeGenericContextDescriptorHeader} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetTypeGenericContextDescriptorHeader extends SwiftTypeMetadataStructure {

	private int instantiationCache;
	private int defaultInstallationPattern;
	private TargetGenericContextDescriptorHeader base;

	/**
	 * Creates a new {@link TargetTypeGenericContextDescriptorHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetTypeGenericContextDescriptorHeader(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		instantiationCache = reader.readNextInt();
		defaultInstallationPattern = reader.readNextInt();
		base = new TargetGenericContextDescriptorHeader(reader);
	}

	/**
	 * {@return the metadata instantiation cache}
	 */
	public int getInstantiationCache() {
		return instantiationCache;
	}

	/**
	 * {@return the default instantiation pattern}
	 */
	public int getDefaultInstallationPattern() {
		return defaultInstallationPattern;
	}

	/**
	 * {@return the base header}
	 */
	public TargetGenericContextDescriptorHeader getBaseHeader() {
		return base;
	}

	@Override
	public List<SwiftTypeMetadataStructure> getTrailingObjects() {
		return base.getTrailingObjects();
	}

	@Override
	public String getStructureName() {
		return TargetTypeGenericContextDescriptorHeader.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "type generic context descriptor header";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(SwiftUtils.PTR_RELATIVE, "InstantiationCache",
			"The metadata instantiation cache.");
		struct.add(SwiftUtils.PTR_RELATIVE, "DefaultInstantiationPattern",
			"The default instantiation pattern.");
		struct.add(base.toDataType(), "Base", "The base header.");
		return struct;
	}
}
