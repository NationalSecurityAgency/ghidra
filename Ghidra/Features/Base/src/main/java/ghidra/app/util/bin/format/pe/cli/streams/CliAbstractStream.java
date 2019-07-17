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
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A abstract CLI stream type for convenience.  Streams that we support should subclass 
 * this class and override the {@link #parse}, {@link #markup}, and {@link #toDataType} 
 * methods appropriately.  
 * <p>
 * When streams are laid down in memory they are referred to as heaps, but we'll just stick 
 * with calling them streams because using both terms can get confusing. 
 */
public abstract class CliAbstractStream implements StructConverter, PeMarkupable {

	public static final String PATH = "/PE/CLI/Streams";

	protected CliStreamHeader header;
	protected long offset;
	protected int rva;
	protected BinaryReader reader;

	/**
	 * Creates a new generic CLI stream type.  This is intended to be called by a subclass
	 * stream during its creation.
	 *  
	 * @param header The stream header associated with this stream.
	 * @param offset The reader offset where this stream starts. 
	 * @param rva The relative virtual address where this stream starts.
	 * @param reader A reader that is used to read the stream.
	 * @throws IOException if there is a problem reading the stream.
	 */
	public CliAbstractStream(CliStreamHeader header, long offset, int rva, BinaryReader reader)
			throws IOException {
		this.header = header;
		this.offset = offset;
		this.rva = rva;
		this.reader = reader;
	}

	/**
	 * Parses this stream.
	 * 
	 * @return True if parsing completed successfully; otherwise, false.
	 * @throws IOException If there was an IO problem while parsing.
	 */
	public abstract boolean parse() throws IOException;

	/**
	 * Does basic markup that all streams will want:
	 * <ul>
	 *   <li>Set monitor message</li>
	 *   <li>Validate addresses</li>
	 *   <li>Add bookmark</li>
	 *   <li>Add symbol</li>
	 *   <li>Create data type</li>
	 * </ul>
	 * Subclass should first call this and then provide any custom markup they need. 
	 */
	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, IOException {

		monitor.setMessage("[" + program.getName() + "]: CLI stream...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, rva);

		program.getBookmarkManager().setBookmark(addr, BookmarkType.INFO, "CLI Stream",
			header.getName());

		try {
			program.getSymbolTable().createLabel(addr, "CLI_Stream_" + header.getName(),
				SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error marking up CLI stream \"" + header.getName() + "\"", e);
			return;
		}

		if (!program.getMemory().contains(addr)) {
			return;
		}

		DataType dt = this.toDataType();
		dt.setCategoryPath(new CategoryPath(PATH));
		PeUtils.createData(program, addr, dt, log);
	}

	/**
	 * Gets this stream's header.
	 * 
	 * @return This stream's header.
	 */
	public CliStreamHeader getStreamHeader() {
		return header;
	}

	/**
	 * Gets the markup address of an offset in a given stream.
	 * 
	 * @param program 
	 * @param isBinary
	 * @param monitor
	 * @param log
	 * @param ntHeader
	 * @param stream The stream to offset into.
	 * @param streamIndex The index into the stream.
	 * @return The markup address of the given offset in the provided stream.
	 */
	public static Address getStreamMarkupAddress(Program program, boolean isBinary,
			TaskMonitor monitor, MessageLog log, NTHeader ntHeader, CliAbstractStream stream,
			int streamIndex) {
		CliStreamHeader streamHeader = stream.getStreamHeader();
		return PeUtils.getMarkupAddress(program, isBinary, ntHeader,
			streamHeader.getMetadataRoot().getRva() + streamHeader.getOffset() + streamIndex);
	}
}
