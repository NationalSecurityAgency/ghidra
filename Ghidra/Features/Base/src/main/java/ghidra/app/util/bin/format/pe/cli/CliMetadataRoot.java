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
import java.nio.charset.Charset;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeMarkupable;
import ghidra.app.util.bin.format.pe.cli.streams.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * The header of a {@link CliMetadataDirectory}.
 */
public class CliMetadataRoot implements StructConverter, PeMarkupable {

	public static final String NAME = "CLI_METADATA_HEADER";
	public static final String PATH = "/PE/CLI";
    
	private BinaryReader reader;
    private long fileOffset;
    private int rva;
    
    private int signature;
    private short majorVersion;
    private short minorVersion;
    private int reserved;
	private int versionLength;
    private String version;
    private short flags;
    private short streamsCount;
	private Map<String, CliStreamHeader> streamHeaderMap;
	private CliStreamHeader metadataHeader;

	private CliStreamGuid guidStream;
	private CliStreamUserStrings userStringsStream;
	private CliStreamStrings stringsStream;
	private CliStreamBlob blobStream;
	private CliStreamMetadata metadataStream;
    
    /**
	 * Constructs a new CLI Metadata Root datatype. Matches ISO 23271 II.24.2.
	 * 
	 * @param reader A binary reader set to start reading at the start of this header.
	 * @param rva The RVA of this header.
	 * @throws IOException if there is a problem reading the header.
	 */
	public CliMetadataRoot(BinaryReader reader, int rva)
			throws IOException {
		this.reader = reader;
		this.fileOffset = reader.getPointerIndex();
		this.rva = rva;
		
		this.signature = reader.readNextInt();
		this.majorVersion = reader.readNextShort();
		this.minorVersion = reader.readNextShort();
		this.reserved = reader.readNextInt();
		this.versionLength = reader.readNextInt();
		if (versionLength > 0 && versionLength < NTHeader.MAX_SANE_COUNT) {
			this.version =
				new String(reader.readNextByteArray(this.versionLength), Charset.forName("UTF-8"));
		}
		this.flags = reader.readNextShort();
		this.streamsCount = reader.readNextShort();

		this.streamHeaderMap = new LinkedHashMap<>();
		for (short i = 0; i < this.streamsCount; i++) {
			CliStreamHeader streamHeader = new CliStreamHeader(this, reader);
			streamHeaderMap.put(streamHeader.getName(), streamHeader);
			if (streamHeader.getName().equals(CliStreamMetadata.getName())) {
				metadataHeader = streamHeader;
			}
		}
	}

	public boolean parse() throws IOException {
		boolean success = true;
	
		// #GUID
		CliStreamHeader header = streamHeaderMap.get(CliStreamGuid.getName());
		if (header != null) {
			guidStream = new CliStreamGuid(header, getFileOffset() + header.getOffset(),
				getRva() + header.getOffset(), reader);
			header.setStream(guidStream);
			success &= guidStream.parse();
		}

		// #US
		header = streamHeaderMap.get(CliStreamUserStrings.getName());
		if (header != null) {
			userStringsStream = new CliStreamUserStrings(header,
				getFileOffset() + header.getOffset(), getRva() + header.getOffset(), reader);
			header.setStream(userStringsStream);
			success &= userStringsStream.parse();
		}

		// #Strings
		header = streamHeaderMap.get(CliStreamStrings.getName());
		if (header != null) {
			stringsStream = new CliStreamStrings(header, getFileOffset() + header.getOffset(),
				getRva() + header.getOffset(), reader);
			header.setStream(stringsStream);
			success &= stringsStream.parse();
		}

		// #Blob
		header = streamHeaderMap.get(CliStreamBlob.getName());
		if (header != null) {
			blobStream = new CliStreamBlob(header,
				getFileOffset() + header.getOffset(), getRva() + header.getOffset(), reader);
			header.setStream(blobStream);
			success &= blobStream.parse();
		}

		// #~ (must be done last)
		header = streamHeaderMap.get(CliStreamMetadata.getName());
		if (header != null) {
			metadataStream = new CliStreamMetadata(header, guidStream, userStringsStream,
				stringsStream, blobStream, getFileOffset() + header.getOffset(),
				getRva() + header.getOffset(), reader);
			header.setStream(metadataStream);
			success &= metadataStream.parse();
		}

		return success;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address start = program.getImageBase().add(getRva());
		try {
			program.getSymbolTable().createLabel(start, NAME, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			Msg.warn(this, "Invalid symbol name: \"" + NAME + "\"");
		}

		// Markup streams.  Must markup Metadata stream last.
		for (CliStreamHeader header : streamHeaderMap.values()) {
			if (header != metadataHeader) {
				header.markup(program, isBinary, monitor, log, ntHeader);
			}
		}
		if (metadataHeader != null) {
			metadataHeader.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(new CategoryPath(PATH));
		struct.add(DWORD, "Signature", "must be 0x424a5342");
		struct.add(WORD, "MajorVersion", null);
		struct.add(WORD, "MinorVersion", null);
		struct.add(DWORD, "Reserved", "should be 0");
		struct.add(DWORD, "VersionLength", null);
		struct.add(new ArrayDataType(CharDataType.dataType, this.versionLength, 1), "Version",
			null);
		struct.add(WORD, "Flags", "should be 0");
		struct.add(WORD, "StreamsCount", "number of stream headers to follow");
		for (CliStreamHeader hdr : streamHeaderMap.values()) {
			struct.add(hdr.toDataType(), hdr.getName(), null);
		}
		return struct;
	}

	/**
	 * Gets the file offset of this header.
	 * 
	 * @return The file offset of this header.
	 */
	public long getFileOffset() {
		return fileOffset;
	}
	
	/**
	 * Gets the relative virtual address of this header.
	 * 
	 * @return The relative virtual address of this header.
	 */
	public int getRva() {
		return rva;
	}

	/**
	 * Gets the signature.  
	 * <p>
	 * Should always be 0x424a5342.
	 * 
	 * @return The signature.
	 */
	public int getSignature() {
		return signature;
	}

	/**
	 * Gets the major version.
	 * 
	 * @return The major version.
	 */
	public short getMajorVersion() {
		return majorVersion;
	}

	/**
	 * Gets the minor version.
	 * 
	 * @return The minor version.
	 */
	public short getMinorVersion() {
		return minorVersion;
	}

	/**
	 * Gets the reserved field.  
	 * <p>
	 * Should always be 0.
	 * 
	 * @return The reserved field.
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * Gets the length of the version string that follows the length field.
	 * 
	 * @return The length of the version string that follows the length field.
	 */
	public int getVersionLength() {
		return versionLength;
	}

	/**
	 * Gets the version string.
	 * 
	 * @return The version string.  Could be null if the version length appeared
	 *   too long during parsing of the header.
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Gets the flags.
	 * <p>
	 * Should always be 0.
	 * 
	 * @return The flags.
	 */
	public short getFlags() {
		return flags;
	}

	/**
	 * Gets the number of streams present in the metadata.
	 * 
	 * @return The number of streams present in the metadata.
	 */
	public short getStreamsCount() {
		return streamsCount;
	}

	/**
	 * Gets the GUID stream.
	 * 
	 * @return The GUID stream.  Could be null if it did not parse correctly.
	 */
	public CliStreamGuid getGuidStream() {
		return guidStream;
	}

	/**
	 * Gets the user strings stream.
	 * 
	 * @return The user strings stream.  Could be null if it did not parse correctly.
	 */
	public CliStreamUserStrings getUserStringsStream() {
		return userStringsStream;
	}

	/**
	 * Gets the strings stream.
	 * 
	 * @return The strings stream.  Could be null if it did not parse correctly.
	 */
	public CliStreamStrings getStringsStream() {
		return stringsStream;
	}

	/**
	 * Gets the blob stream.
	 * 
	 * @return The blob stream.  Could be null if it did not parse correctly.
	 */
	public CliStreamBlob getBlobStream() {
		return blobStream;
	}

	/**
	 * Gets the Metadata stream.
	 * 
	 * @return The Metadata stream.  Could be null if it did not parse correctly.
	 */
	public CliStreamMetadata getMetadataStream() {
		return metadataStream;
	}

	/**
	 * Gets the stream headers.
	 * 
	 * @return A collection of stream headers.
	 */
	public Collection<CliStreamHeader> getStreamHeaders() {
		return streamHeaderMap.values();
	}
	
	/**
	 * Gets the stream header with the given name.
	 * 
	 * @param name The name of the stream header to get.
	 * @return The stream header that matches the given name, or null if it wasn't found.
	 */
	public CliStreamHeader getStreamHeader(String name) {
		return streamHeaderMap.get(name);
	}
	
	public int getBlobOffsetAtIndex(int index) {
		CliStreamHeader blobHdr = getStreamHeader("#Blob");
		if (blobHdr == null) return -1; // TODO: this isn't a nice way of doing this
		int offset = (int) this.fileOffset + blobHdr.getOffset() + index;
		return offset;
	}
}
