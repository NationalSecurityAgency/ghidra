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
package ghidra.app.util.bin.format.pe.cli.streams;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.app.util.datatype.microsoft.GuidDataType;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * The GUID stream points to a sequence of 128-bit GUIDs.  There might be unreachable
 * GUIDs stored in the stream.
 */
public class CliStreamGuid extends CliAbstractStream {

	private int numGuids;

	/**
	 * Gets the name of this stream.
	 * 
	 * @return The name of this stream.
	 */
	public static String getName() {
		return "#GUID";
	}

	/**
	 * Creates a new GUID stream.
	 * 
	 * @param header The stream header associated with this stream.
	 * @param offset The reader offset where this stream starts. 
	 * @param rva The relative virtual address where this stream starts.
	 * @param reader A reader that is used to read the stream.
	 * @throws IOException if there is a problem reading the stream.
	 */
	public CliStreamGuid(CliStreamHeader header, long offset, int rva, BinaryReader reader)
			throws IOException {
		super(header, offset, rva, reader);
		
		numGuids = header.getSize() / GuidDataType.SIZE;
	}
		
	@Override
	public boolean parse() throws IOException {
		return true;
	}

	/**
	 * Gets the GUID at the given index.
	 * 
	 * @param index The index of the GUID to get.
	 * @return The string at the given index.  Could be null if the index was invalid or
	 *   there was a problem reading the GUID.
	 */
	public GUID getGuid(int index) {

		if (index < 0 || index >= numGuids * GuidDataType.SIZE) {
			return null;
		}

		try {
			reader.setPointerIndex(offset + index);
			return new GUID(reader);
		}
		catch (IOException e) {
			return null;
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(new CategoryPath(PATH), header.getName(), 0);
		DataType guidDT = new GuidDataType();
		for (int i = 0; i < numGuids; i++) {
			struct.add(guidDT, "[" + Integer.toHexString(i) + "]", null);
		}
		return struct;
	}
}
