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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code InvertibleProtocolSet} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.h">swift/ABI/InvertibleProtocols.h</a> 
 */
public class InvertibleProtocolSet extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link InvertibleProtocolSet} structure
	 */
	public static final int SIZE = 2;

	private short bits;

	/**
	 * Create a new {@link InvertibleProtocolSet}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public InvertibleProtocolSet(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		bits = reader.readNextShort();
	}

	/**
	 * {@return the raw bits}
	 */
	public short getRawBits() {
		return bits;
	}

	@Override
	public String getStructureName() {
		return InvertibleProtocolSet.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "invertible protocol set";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(InvertibleProtocolKind.values()[0].toDataType(), "bits", "The storage bits");
		return struct;
	}
}
