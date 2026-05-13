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
 * Represents a Swift {@code TargetSingletonMetadataInitialization} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetSingletonMetadataInitialization extends SwiftTypeMetadataStructure {

	private ContextDescriptorFlags flags;

	private int initializationCache;
	private int incompleteMetadata;
	private int resilientPattern;
	private int completionFunction;

	/**
	 * Creates a new {@link TargetSingletonMetadataInitialization}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @param flags The {@link ContextDescriptorFlags}
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetSingletonMetadataInitialization(BinaryReader reader, ContextDescriptorFlags flags)
			throws IOException {
		super(reader.getPointerIndex());
		this.flags = flags;
		initializationCache = reader.readNextInt();
		incompleteMetadata = reader.readNextInt();
		resilientPattern = incompleteMetadata;
		completionFunction = reader.readNextInt();
	}

	/**
	 * {@return the initialization cache}
	 */
	public int getInitializationCache() {
		return initializationCache;
	}

	/**
	 * {@return the incomplete metadata for structs, enums, and classes if there is no resilient
	 * ancestry; otherwise, 0}
	 */
	public int getIncompleteMetadata() {
		return !flags.hasClassResilientSuperclass() ? incompleteMetadata : 0;
	}

	/**
	 * {@return a pattern used to allocation and initialize metadata for this class if there is a
	 * resilient superclass; otherwise, 0}
	 */
	public int getResilientPattern() {
		return flags.hasClassResilientSuperclass() ? resilientPattern : 0;
	}

	/**
	 * {@return the completion function (the pattern will always be null, even for a resilient 
	 * class)}
	 */
	public int getCompletionFunction() {
		return completionFunction;
	}

	@Override
	public String getStructureName() {
		return TargetSingletonMetadataInitialization.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "singleton metadata initialization";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		UnionDataType union =
			new UnionDataType(CATEGORY_PATH, "Union_IncompleteMetadata_ResilientPattern");
		union.add(SwiftUtils.PTR_RELATIVE, "IncompleteMetadata",
			"The incomplete metadata, for structs, enums and classes without resilient ancestry.");
		union.add(SwiftUtils.PTR_RELATIVE, "ResilientPattern",
			"If the classes descriptor has a resilient superclass, this points at a pattern used to allcoate and initialize metadata for this class, since its size and contents is not known at compile time.");

		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(SwiftUtils.PTR_RELATIVE, "InitializationCache", "The initialization cache.");
		struct.add(union, union.getName(), null);
		struct.add(SwiftUtils.PTR_RELATIVE, "CompletionFunction",
			"The completion function. The pattern will always be null, even for a resilient class.");
		return struct;
	}
}
