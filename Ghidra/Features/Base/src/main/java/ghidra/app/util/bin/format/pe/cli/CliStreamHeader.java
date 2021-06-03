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
package ghidra.app.util.bin.format.pe.cli;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeMarkupable;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * A structure used by a {@link CliMetadataRoot} describe a {@link CliAbstractStream}.
 * <p>
 * Note that this type of "header" isn't found at the start of the stream, but as
 * elements of a list of headers at the end of a {@link CliMetadataRoot}.  They 
 * are kind of like PE section headers.
 */
public class CliStreamHeader implements StructConverter, PeMarkupable {
	
	private static String NAME = "CLI_Stream_Header";
	private static String PATH = "/PE/CLI/Streams/Headers";

	private CliMetadataRoot metadataRoot;
	private CliAbstractStream stream;
	
	private int offset;
	private int size;
	private String name;
	private int nameLen;
	
	/**
	 * Constructs a new CLI Stream Header datatype.
	 * 
	 * @param metadataRoot the metadata root.
	 * @param reader A binary reader set to start reading at the start of this header.
	 * @throws IOException if there is a problem reading the header.
	 */
	public CliStreamHeader(CliMetadataRoot metadataRoot, BinaryReader reader)
			throws IOException {
		this.metadataRoot = metadataRoot;
		
		long headerStartIndex = reader.getPointerIndex();

		this.offset = reader.readNextInt();
		this.size = reader.readNextInt();
		
		// name is an ASCII string aligned to the next 4-byte boundary
		long startIndex = reader.getPointerIndex();
		this.name = reader.readNextAsciiString();
		long endIndex = reader.getPointerIndex(); // Gives us the index of the byte after the first null terminator
		long stringBytes = endIndex - startIndex;
		long bytesToRoundUp = 0;
		if ((stringBytes % 4) != 0) {
			bytesToRoundUp += 4 - (stringBytes % 4);
		}
		this.nameLen = (int) (stringBytes + bytesToRoundUp);
		
		int totalLen = 2 * DWordDataType.dataType.getLength() + this.nameLen;

		reader.setPointerIndex(headerStartIndex + totalLen);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, IOException, MemoryAccessException {
		if (stream != null) {
			stream.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME + "_" + name, 0);
		struct.setCategoryPath(new CategoryPath(PATH));
		struct.add(DWORD, "offset", null);
		struct.add(DWORD, "size", null);
		struct.add(new ArrayDataType(CharDataType.dataType, this.nameLen, 1), "name", null);
		return struct;
	}

	/**
	 * Gets the {@link CliMetadataRoot} that contains us.
	 * 
	 * @return The {@link CliMetadataRoot} that contains us.
	 */
	public CliMetadataRoot getMetadataRoot() {
		return metadataRoot;
	}
	
	/**
	 * Gets the {@link CliAbstractStream} that this is a header for.
	 * 
	 * @return The {@link CliAbstractStream} that this is a header for.  Could be null if we
	 *   don't support the stream type.
	 */
	public CliAbstractStream getStream() {
		return stream;
	}

	/**
	 * Gets the offset.  This is not a file offset, but an offset that gets added to 
	 * the metadata header's offset to obtain a file offset.
	 * 
	 * @return The offset.
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Gets the size of this header's stream.
	 * 
	 * @return The size of this header's stream.
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Gets the name of this header's stream.
	 * 
	 * @return The name of this header's stream.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the name length.
	 * <p>
	 * The name length may be larger than necessary because the name string is must
	 * be aligned to the next 4-byte boundary.
	 * 
	 * @return The name length.
	 */
	public int getNameLength() {
		return nameLen;
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Sets this header's stream.
	 * 
	 * @param stream The stream associated with this header.
	 */
	protected void setStream(CliAbstractStream stream) {
		this.stream = stream;
	}
}
