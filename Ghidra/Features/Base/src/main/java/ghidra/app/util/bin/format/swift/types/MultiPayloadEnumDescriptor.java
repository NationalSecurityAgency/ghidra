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
 * Represents a Swift {@code MultiPayloadEnumDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class MultiPayloadEnumDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link MultiPayloadEnumDescriptor} structure.  This size does not
	 * take into account the size of the {@code contents} array.
	 * 
	 * @see #getContentsSize()
	 */
	public static final int SIZE = 4;

	/**
	 * How many bytes it requires to peek at size of the {@code contents} array
	 */
	public static final int PEEK_SIZE = 8;

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
	 * {@return the type name}
	 */
	public String getTypeName() {
		return typeName;
	}

	/**
	 * {@return the contents}
	 */
	public int[] getContents() {
		return contents;
	}

	/**
	 * {@return the size of the contents in bytes}
	 */
	public long getContentsSize() {
		return contents.length * Integer.BYTES;
	}

	/**
	 * {@return the size of the contents in bytes, without reading the contents}
	 * <p>
	 * This method will leave the {@link BinaryReader}'s position unaffected.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public static int peekContentsSize(BinaryReader reader) throws IOException {
		long origIndex = reader.getPointerIndex();
		try {
			reader.readNext(SwiftUtils::relativeString);
			return (reader.readNextInt() >> 16) & 0xffff;
		}
		finally {
			reader.setPointerIndex(origIndex);
		}
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
