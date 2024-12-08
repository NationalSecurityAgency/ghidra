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
package ghidra.file.formats.ios;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * An extracted Mach-O that was once living inside of a Mach-O container file. The Mach-O layout
 * is manipulated so all of its segments are adjacent in the resulting binary.
 */
public class ExtractedMacho {

	protected ByteProvider provider;
	protected long providerOffset;
	protected byte[] footer;
	protected BinaryReader reader;
	protected MachHeader machoHeader;
	protected SegmentCommand textSegment;
	protected SegmentCommand linkEditSegment;
	protected Map<SegmentCommand, Integer> packedSegmentStarts = new HashMap<>();
	protected Map<SegmentCommand, Integer> packedSegmentAdjustments = new HashMap<>();
	protected Map<LoadCommand, Integer> packedLinkEditDataStarts = new HashMap<>();
	protected byte[] packed;
	protected TaskMonitor monitor;

	/**
	 * Creates a new {@link ExtractedMacho} object
	 * 
	 * @param provider The provider with the Mach-O header
	 * @param providerOffset The offset of the Mach-O in the given provider
	 * @param machoHeader The parsed {@link MachHeader}
	 * @param footer A footer that gets appended to the end of every extracted component so Ghidra 
	 *   can identify them and treat them special when imported
	 * @param monitor {@link TaskMonitor}
	 * @throws IOException If there was an IO-related error
	 * @throws CancelledException If the user cancelled the operation
	 */
	public ExtractedMacho(ByteProvider provider, long providerOffset, MachHeader machoHeader,
			byte[] footer, TaskMonitor monitor) throws IOException, CancelledException {
		this.provider = provider;
		this.providerOffset = providerOffset;
		this.footer = footer;
		this.machoHeader = machoHeader;
		this.textSegment = machoHeader.getSegment(SegmentNames.SEG_TEXT);
		this.linkEditSegment = machoHeader.getSegment(SegmentNames.SEG_LINKEDIT);
		this.reader = new BinaryReader(provider, machoHeader.isLittleEndian());
		this.monitor = monitor;
	}

	/**
	 * Performs the packing
	 * 
	 * @throws IOException If there was an IO-related error
	 * @throws CancelledException If the user cancelled the operation
	 */
	public void pack() throws IOException, CancelledException {

		// Keep track of each segment's file offset in the container.
		// Also keep a running total of each segment's size so we know how big to make our
		// packed array.
		int packedSize = 0;
		int packedLinkEditSize = 0;
		for (SegmentCommand segment : machoHeader.getAllSegments()) {
			monitor.checkCancelled();

			packedSegmentStarts.put(segment, packedSize);

			// The __LINKEDIT segment is shared across all Mach-O's, so it is very large.  We
			// Want to create a new packed __LINKEDIT segment with only the relevant info for
			// the Mach-O we are extracting, resulting in a significantly smaller file.
			if (segment == linkEditSegment) {
				for (LoadCommand cmd : machoHeader.getLoadCommands()) {
					if (cmd instanceof SymbolTableCommand symbolTable) {
						symbolTable.addSymbols(getExtraSymbols());
					}
					int offset = cmd.getLinkerDataOffset();
					int size = cmd.getLinkerDataSize();
					if (offset == 0 || size == 0) {
						continue;
					}
					packedLinkEditDataStarts.put(cmd, packedLinkEditSize);
					packedLinkEditSize += size;
				}
				packedSize += packedLinkEditSize;
				segment.setFileSize(packedLinkEditSize);
				segment.setVMsize(packedLinkEditSize);
			}
			else {
				packedSize += segment.getFileSize();
			}

			// Some older containers use a file offset of 0 for their __TEXT segment, despite 
			// being in the middle of the container and despite the other segments using 
			// absolute cache file offsets. Adjust these segments to be consistent with all the 
			// other segments, and store their adjustment values so we can later work with them
			// as absolute container file offsets.
			if (segment == textSegment && segment.getFileOffset() == 0) {
				segment.setFileOffset(providerOffset);
				packedSegmentAdjustments.put(segment, (int) providerOffset);
			}
		}

		// Account for the size of the footer
		packedSize += footer.length;

		packed = new byte[packedSize];

		// Copy each segment into the packed array (leaving no gaps)
		for (SegmentCommand segment : machoHeader.getAllSegments()) {
			monitor.checkCancelled();
			long segmentSize = segment.getFileSize();
			ByteProvider segmentProvider = getSegmentProvider(segment);
			if (segment.getFileOffset() + segmentSize > segmentProvider.length()) {
				segmentSize = segmentProvider.length() - segment.getFileOffset();
				Msg.warn(this, segment.getSegmentName() +
					" segment extends beyond end of file.  Truncating...");
			}
			byte[] bytes;
			if (segment == linkEditSegment) {
				bytes = createPackedLinkEditSegment(segmentProvider, packedLinkEditSize);
				adjustLinkEditAddress();
			}
			else {
				bytes = segmentProvider.readBytes(segment.getFileOffset(), segmentSize);
			}
			System.arraycopy(bytes, 0, packed, packedSegmentStarts.get(segment), bytes.length);
		}

		// Fixup various fields in the packed array
		fixupLoadCommands();

		// Add footer
		System.arraycopy(footer, 0, packed, packed.length - footer.length, footer.length);
	}

	/**
	 * Gets a {@link ByteProvider} for this {@link ExtractedMacho} object
	 * 
	 * @param fsrl FSRL identity of the file
	 * @return A {@link ByteProvider} for this {@link ExtractedMacho} object
	 */
	public ByteProvider getByteProvider(FSRL fsrl) {
		return new ByteArrayProvider(packed, fsrl);
	}

	/**
	 * Gets the {@link ByteProvider} that contains the given {@link SegmentCommand segment}
	 * 
	 * @param segment The {@link SegmentCommand segment}
	 * @return The {@link ByteProvider} that contains the given {@link SegmentCommand segment}
	 * @throws IOException If a {@link ByteProvider} could not be found
	 */
	protected ByteProvider getSegmentProvider(SegmentCommand segment) throws IOException {
		return provider;
	}

	/**
	 * Gets a {@link List} of extra {@link NList symbol}s for the component being extracted
	 * 
	 * @return A {@link List} of extra {@link NList symbol}s (could be empty)
	 */
	protected List<NList> getExtraSymbols() {
		return List.of();
	}

	/**
	 * Converts the given Mach-O file offset to an offset into the packed Mach-O
	 * 
	 * @param fileOffset The Mach-O file offset to convert
	 * @param segment The segment that contains the file offset; null if unknown
	 * @return An offset into the packed Mach-O
	 * @throws NotFoundException If there was no corresponding Mach-O offset
	 */
	protected long getPackedOffset(long fileOffset, SegmentCommand segment)
			throws NotFoundException {
		Integer segmentStart = packedSegmentStarts.get(segment);
		if (segmentStart != null) {
			return fileOffset - segment.getFileOffset() + segmentStart;
		}
		throw new NotFoundException(
			"Failed to convert Mach-O file offset to packed offset: 0x%x".formatted(fileOffset));
	}

	/**
	 * Creates a packed __LINKEDIT segment array
	 * 
	 * @param linkEditSegmentProvider The {@link ByteProvider} that contains the __LINKEDIT
	 *   segment
	 * @param packedLinkEditSize The size in bytes of the packed __LINKEDIT segment
	 * @return A packed __LINKEDIT segment array
	 * @throws IOException If there was an IO-related error
	 */
	private byte[] createPackedLinkEditSegment(ByteProvider linkEditSegmentProvider,
			int packedLinkEditSize) throws IOException {
		byte[] packedLinkEdit = new byte[packedLinkEditSize];

		for (LoadCommand cmd : packedLinkEditDataStarts.keySet()) {
			if (cmd instanceof SymbolTableCommand symbolTable &&
				symbolTable.getNumberOfSymbols() > 0) {
				List<NList> symbols = symbolTable.getSymbols();
				byte[] packedSymbolStringTable = new byte[NList.getSize(symbols)];
				int nlistIndex = 0;
				int stringIndex = symbols.get(0).getSize() * symbols.size();
				int stringIndexOrig = stringIndex;
				for (NList nlist : symbols) {
					byte[] nlistArray = nlistToArray(nlist, stringIndex - stringIndexOrig);
					byte[] stringArray = nlist.getString().getBytes(StandardCharsets.US_ASCII);
					System.arraycopy(nlistArray, 0, packedSymbolStringTable, nlistIndex,
						nlistArray.length);
					System.arraycopy(stringArray, 0, packedSymbolStringTable, stringIndex,
						stringArray.length);
					nlistIndex += nlistArray.length;
					stringIndex += stringArray.length + 1; // null terminate
				}
				System.arraycopy(packedSymbolStringTable, 0, packedLinkEdit,
					packedLinkEditDataStarts.get(cmd), packedSymbolStringTable.length);
			}
			else {
				byte[] bytes = linkEditSegmentProvider.readBytes(cmd.getLinkerDataOffset(),
					cmd.getLinkerDataSize());
				System.arraycopy(bytes, 0, packedLinkEdit, packedLinkEditDataStarts.get(cmd),
					bytes.length);
			}
		}

		return packedLinkEdit;
	}

	/**
	 * Converts the given {@link NList} to a byte array.  The given {@link NList}'s string
	 * index field will be replaced with the given string index parameter.
	 * 
	 * @param nlist The {@link NList} to convert
	 * @param stringIndex The new string index
	 * @return A new {@link NList} in byte array form
	 */
	private byte[] nlistToArray(NList nlist, int stringIndex) {
		byte[] ret = new byte[nlist.getSize()];
		DataConverter conv = DataConverter.getInstance(!machoHeader.isLittleEndian());
		conv.putInt(ret, 0, stringIndex);
		ret[4] = nlist.getType();
		ret[5] = nlist.getSection();
		conv.putShort(ret, 6, nlist.getDescription());
		if (nlist.is32bit()) {
			conv.putInt(ret, 8, (int) nlist.getValue());
		}
		else {
			conv.putLong(ret, 8, nlist.getValue());
		}
		return ret;
	}

	/**
	 * Fixes-up various fields in the new packed Mach-O's load commands
	 * 
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private void fixupLoadCommands() throws IOException {
		for (LoadCommand cmd : machoHeader.getLoadCommands()) {
			if (monitor.isCancelled()) {
				break;
			}
			switch (cmd.getCommandType()) {
				case LoadCommandTypes.LC_SEGMENT:
					fixupSegment((SegmentCommand) cmd, false);
					break;
				case LoadCommandTypes.LC_SEGMENT_64:
					fixupSegment((SegmentCommand) cmd, true);
					break;
				case LoadCommandTypes.LC_SYMTAB:
					fixupSymbolTable((SymbolTableCommand) cmd);
					break;
				case LoadCommandTypes.LC_DYSYMTAB:
					fixupDynamicSymbolTable((DynamicSymbolTableCommand) cmd);
					break;
				case LoadCommandTypes.LC_DYLD_INFO:
				case LoadCommandTypes.LC_DYLD_INFO_ONLY:
					fixupDyldInfo((DyldInfoCommand) cmd);
					break;
				case LoadCommandTypes.LC_CODE_SIGNATURE:
				case LoadCommandTypes.LC_SEGMENT_SPLIT_INFO:
				case LoadCommandTypes.LC_FUNCTION_STARTS:
				case LoadCommandTypes.LC_DATA_IN_CODE:
				case LoadCommandTypes.LC_DYLIB_CODE_SIGN_DRS:
				case LoadCommandTypes.LC_OPTIMIZATION_HINT:
				case LoadCommandTypes.LC_DYLD_EXPORTS_TRIE:
				case LoadCommandTypes.LC_DYLD_CHAINED_FIXUPS:
					fixupLinkEditData((LinkEditDataCommand) cmd);
					break;
			}
		}
	}

	/**
	 * Fixes-up the old Mach-O's file offsets and size in the given segment so they are correct
	 * for the newly packed Mach-O
	 * 
	 * @param segment The segment to fix-up
	 * @param is64bit True if the segment is 64-bit; false if 32-bit
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private void fixupSegment(SegmentCommand segment, boolean is64bit) throws IOException {
		long adjustment = packedSegmentAdjustments.getOrDefault(segment, 0);

		set(segment.getStartIndex() + (is64bit ? 0x18 : 0x18), segment.getVMaddress(),
			is64bit ? 8 : 4);
		set(segment.getStartIndex() + (is64bit ? 0x20 : 0x1c), segment.getVMsize(),
			is64bit ? 8 : 4);
		fixup(segment.getStartIndex() + (is64bit ? 0x28 : 0x20), adjustment, is64bit ? 8 : 4,
			segment);
		set(segment.getStartIndex() + (is64bit ? 0x30 : 0x24), segment.getFileSize(),
			is64bit ? 8 : 4);

		long sectionStartIndex = segment.getStartIndex() + (is64bit ? 0x48 : 0x38);
		for (Section section : segment.getSections()) {
			if (monitor.isCancelled()) {
				break;
			}

			// For some reason the section file offsets in the iOS 10 DYLD cache do not want
			// the adjustment despite the segment needed it.  We can expect to see warnings
			// in that particular version.
			if (section.getOffset() > 0 && section.getSize() > 0) {
				fixup(sectionStartIndex + (is64bit ? 0x30 : 0x28), adjustment, 4, segment);
			}
			if (section.getRelocationOffset() > 0) {
				fixup(sectionStartIndex + (is64bit ? 0x38 : 0x30), adjustment, 4, segment);
			}
			sectionStartIndex += is64bit ? 0x50 : 0x44;
		}
	}

	/**
	 * Fixes-up the old Mach-O's file offsets in the given symbol table so they are correct for 
	 * the newly packed Mach-O
	 * 
	 * @param cmd The symbol table to fix-up
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private void fixupSymbolTable(SymbolTableCommand cmd) throws IOException {
		if (cmd.getSymbolOffset() > 0) {
			long symbolOffset =
				fixup(cmd.getStartIndex() + 0x8, getLinkEditAdjustment(cmd), 4, linkEditSegment);
			set(cmd.getStartIndex() + 0xc, cmd.getNumberOfSymbols(), 4);
			if (cmd.getStringTableOffset() > 0) {
				if (cmd.getNumberOfSymbols() > 0) {
					set(cmd.getStartIndex() + 0x10,
						symbolOffset + cmd.getNumberOfSymbols() * cmd.getSymbolAt(0).getSize(), 4);
					set(cmd.getStartIndex() + 0x14, cmd.getStringTableSize(), 4);
				}
				else {
					set(cmd.getStartIndex() + 0x10, symbolOffset, 4);
					set(cmd.getStartIndex() + 0x14, 0, 4);
				}
			}
		}
	}

	/**
	 * Fixes-up the old Mach-O's file offsets in the given dynamic symbol table so they are 
	 * correct for the newly packed Mach-O.
	 * <p>
	 * NOTE: We are currently only extracting the Indirect Symbol Table, so zero-out the other
	 * fields that might point to data.
	 * 
	 * @param cmd The dynamic symbol table to fix-up
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private void fixupDynamicSymbolTable(DynamicSymbolTableCommand cmd) throws IOException {
		long adjustment = getLinkEditAdjustment(cmd);
		if (cmd.getTableOfContentsOffset() > 0) {
			set(cmd.getStartIndex() + 0x20, 0, 8);
		}
		if (cmd.getModuleTableOffset() > 0) {
			set(cmd.getStartIndex() + 0x28, 0, 8);
		}
		if (cmd.getReferencedSymbolTableOffset() > 0) {
			set(cmd.getStartIndex() + 0x30, 0, 8);
		}
		if (cmd.getIndirectSymbolTableOffset() > 0) {
			fixup(cmd.getStartIndex() + 0x38, adjustment, 4, linkEditSegment);
		}
		if (cmd.getExternalRelocationOffset() > 0) {
			set(cmd.getStartIndex() + 0x40, 0, 8);
		}
		if (cmd.getLocalRelocationOffset() > 0) {
			set(cmd.getStartIndex() + 0x48, 0, 8);
		}
	}

	/**
	 * Fixes-up the old Mach-O's file offsets in the given DYLD Info command so they are correct
	 * for the newly packed Mach-O.
	 * <p>
	 * NOTE: We are currently not extracting this load command, so zero-out all the fields.
	 * 
	 * @param cmd The DYLD Info command to fix-up
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private void fixupDyldInfo(DyldInfoCommand cmd) throws IOException {
		if (cmd.getRebaseOffset() > 0) {
			set(cmd.getStartIndex() + 0x8, 0, 8);
		}
		if (cmd.getBindOffset() > 0) {
			set(cmd.getStartIndex() + 0x10, 0, 8);
		}
		if (cmd.getWeakBindOffset() > 0) {
			set(cmd.getStartIndex() + 0x18, 0, 8);
		}
		if (cmd.getLazyBindOffset() > 0) {
			set(cmd.getStartIndex() + 0x20, 0, 8);
		}
		if (cmd.getExportOffset() > 0) {
			set(cmd.getStartIndex() + 0x28, 0, 8);
		}
	}

	/**
	 * Fixes-up the old Mach-O file offsets in the given link edit data command so they are 
	 * correct for the newly packed Mach-O
	 * 
	 * @param cmd The link edit data command to fix-up
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private void fixupLinkEditData(LinkEditDataCommand cmd) throws IOException {
		if (cmd.getLinkerDataOffset() > 0) {
			fixup(cmd.getStartIndex() + 0x8, getLinkEditAdjustment(cmd), 4, linkEditSegment);
		}
	}

	/**
	 * Gets a value that will need to be added to a container file offset into the __LINKEDIT 
	 * segment to account for our new __LINKEDIT segment being packed
	 *  
	 * @param cmd The target __LINKEDIT {@link LoadCommand}
	 * @return The adjustment value
	 */
	private long getLinkEditAdjustment(LoadCommand cmd) {
		return packedLinkEditDataStarts.getOrDefault(cmd, 0) -
			(cmd.getLinkerDataOffset() - linkEditSegment.getFileOffset());
	}

	/**
	 * Sets the bytes at the given container file offset to the given value.  The provided file 
	 * offset is assumed to map to a field in a load command.
	 *  
	 * @param fileOffset The Mach-O file offset to set
	 * @param value The new value
	 * @param size The number of bytes to set (must be 4 or 8)
	 * @throws IOException If there was an IO-related error
	 * @throws IllegalArgumentException if size is an unsupported value
	 */
	private void set(long fileOffset, long value, int size)
			throws IOException, IllegalArgumentException {
		if (size != 4 && size != 8) {
			throw new IllegalArgumentException("Size must be 4 or 8 (got " + size + ")");
		}

		try {
			byte[] newBytes = toBytes(value, size);
			System.arraycopy(newBytes, 0, packed, (int) getPackedOffset(fileOffset, textSegment),
				newBytes.length);
		}
		catch (NotFoundException e) {
			Msg.warn(this, e.getMessage());
		}
	}

	/**
	 * Fixes up the bytes at the given container file offset to map to the correct offset in the
	 * packed Mach-O.  The provided file offset is assumed to map to a field in a load command.
	 *  
	 * @param fileOffset The container file offset to fix-up
	 * @param adjustment A value to add to the bytes at the given container file offset prior to 
	 *   looking them up in the packed Mach-O
	 * @param size The number of bytes to fix-up (must be 4 or 8)
	 * @param segment The segment that the value at the file offset is associated with
	 * @return The newly fixed up value (or the original value if there was a graceful failure)
	 * @throws IOException If there was an IO-related error
	 * @throws IllegalArgumentException if size is an unsupported value
	 */
	private long fixup(long fileOffset, long adjustment, int size, SegmentCommand segment)
			throws IOException, IllegalArgumentException {
		if (size != 4 && size != 8) {
			throw new IllegalArgumentException("Size must be 4 or 8 (got " + size + ")");
		}
		long value = reader.readUnsignedValue(fileOffset, size);
		long ret = value;
		value += adjustment;

		try {
			ret = getPackedOffset(value, segment);
			byte[] newBytes = toBytes(ret, size);
			System.arraycopy(newBytes, 0, packed, (int) getPackedOffset(fileOffset, textSegment),
				newBytes.length);
		}
		catch (NotFoundException e) {
			Msg.warn(this, e.getMessage());
		}

		return ret;
	}

	/**
	 * We don't want our packed __LINKEDIT segment to overlap with other Mach-O's __LINKEDIT
	 * segments that might get extracted and added to the same program.  Rather than computing
	 * the optimal address it should go at (which will require looking at every other Mach-O
	 * in the container, which is slow), just make the address very far away from the other
	 * Mach-O's. This should be safe for 64-bit binaries. 
	 */
	private void adjustLinkEditAddress() {
		if (machoHeader.is32bit()) {
			return;
		}
		linkEditSegment.setVMaddress(textSegment.getVMaddress() << 4);
	}

	/**
	 * Converts the given value to a byte array
	 * 
	 * @param value The value to convert to a byte array
	 * @param size The number of bytes to convert (must be 4 or 8)
	 * @return The value as a byte array of the given size
	 * @throws IllegalArgumentException if size is an unsupported value
	 */
	public static byte[] toBytes(long value, int size) throws IllegalArgumentException {
		if (size != 4 && size != 8) {
			throw new IllegalArgumentException("Size must be 4 or 8 (got " + size + ")");
		}
		DataConverter converter = LittleEndianDataConverter.INSTANCE;
		return size == 8 ? converter.getBytes(value) : converter.getBytes((int) value);
	}
}
