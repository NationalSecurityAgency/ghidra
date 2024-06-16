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
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift MultiPayloadEnumDescriptor structure
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class MultiPayloadEnumDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link MultiPayloadEnumDescriptor} structure.  This size does not
	 * take into account the size of the <code>contents</code> array.
	 * 
	 * @see #getContentsSize()
	 */
	public static final int SIZE = 4;

	private String typeName;
	private int[] contents;

	/**
	 * Creates a new {@link MultiPayloadEnumDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public MultiPayloadEnumDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		typeName = reader.readNext(SwiftUtils::relativeString);
		int size = (reader.readNextInt() >> 16) & 0xffff;
		reader.setPointerIndex(reader.getPointerIndex() - 4);
		contents = reader.readNextIntArray(size);
	}

	/**
	 * Gets the type name
	 * 
	 * @return The type name
	 */
	public String getTypeName() {
		return typeName;
	}

	/**
	 * Gets the contents
	 * 
	 * @return The contents
	 */
	public int[] getContents() {
		return contents;
	}

	/**
	 * Gets the size of the contents in bytes
	 * 
	 * @return The size of the contents in bytes
	 */
	public long getContentsSize() {
		return contents.length * Integer.BYTES;
	}

	@Override
	public String getStructureName() {
		return MultiPayloadEnumDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "multipayload enum descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return SwiftUtils.PTR_STRING;
	}
}
