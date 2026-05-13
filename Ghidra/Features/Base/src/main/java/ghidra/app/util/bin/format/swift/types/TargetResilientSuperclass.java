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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code TargetResilientSuperclass} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h">swift/ABI/Metadata.h</a> 
 */
public class TargetResilientSuperclass extends SwiftTypeMetadataStructure {

	private int superclass;

	/**
	 * Create a new {@link TargetResilientSuperclass}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetResilientSuperclass(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		superclass = reader.readNextInt();
	}

	/**
	 * {@return the superclass of this class, or 0 if there isn't one}
	 */
	public int getSuperclass() {
		return superclass;
	}

	@Override
	public String getStructureName() {
		return getMyStructureName();
	}

	@Override
	public String getDescription() {
		return "resilient superclass";
	}

	/**
	 * {@return this class's structure name (will not be affected by subclass's name)}
	 */
	private final String getMyStructureName() {
		return TargetResilientSuperclass.class.getSimpleName();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getMyStructureName(), 0);
		struct.add(SwiftUtils.PTR_RELATIVE, "Superclass", "The superclass of this class.");
		return struct;
	}

}
