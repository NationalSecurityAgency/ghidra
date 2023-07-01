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
package ghidra.file.formats.ios.dyldcache;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * A class for extracting DYLIB files from a {@link DyldCacheFileSystem}
 */
public class DyldCacheDylibExtractor {

	/**
	 * Gets an {@link ByteProvider} that reads a DYLIB from a {@link DyldCacheFileSystem}.  The
	 * DYLIB's header will be altered to account for its segment bytes being packed down.   
	 * 
	 * @param dylibOffset The offset of the DYLIB in the given provider
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @param index The DYLIB's {@link SplitDyldCache} index
	 * @param fsrl {@link FSRL} to assign to the resulting {@link ByteProvider}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} containing the bytes of the DYLIB
	 * @throws MachException If there was an error parsing the DYLIB headers
	 * @throws IOException If there was an IO-related issue with extracting the DYLIB
	 */
	public static ByteProvider extractDylib(long dylibOffset, SplitDyldCache splitDyldCache,
			int index, FSRL fsrl, TaskMonitor monitor) throws IOException, MachException {

		PackedSegments packedSegments =
			new PackedSegments(dylibOffset, splitDyldCache, index, monitor);

		return packedSegments.getByteProvider(fsrl);
	}

	/**
	 * A packed DYLIB that was once living inside of a DYLD shared cache.  The DYLIB is said to be 
	 * packed because its segment file bytes, which were not adjacent in its containing DYLD, are 
	 * now adjacent in its new array. 
	 */
	private static class PackedSegments {

		private BinaryReader reader;
		private MachHeader header;
		private SegmentCommand textSegment;
		private SegmentCommand linkEditSegment;
		private Map<SegmentCommand, Integer> packedSegmentStarts = new HashMap<>();
		private Map<SegmentCommand, Integer> packedSegmentAdjustments = new HashMap<>();
		private Map<LoadCommand, Integer> packedLinkEditDataStarts = new HashMap<>();
		private byte[] packed;
		private TaskMonitor monitor;

		/**
		 * Creates a new {@link PackedSegments} object
		 * 
		 * @param dylibOffset The offset of the DYLIB in the given provider
		 * @param splitDyldCache The {@link SplitDyldCache}
		 * @param index The DYLIB's {@link SplitDyldCache} index
		 * @param monitor {@link TaskMonitor}
		 * @throws MachException If there was an error parsing the DYLIB headers
		 * @throws IOException If there was an IO-related error
		 */
		public PackedSegments(long dylibOffset, SplitDyldCache splitDyldCache, int index,
				TaskMonitor monitor) throws MachException, IOException {
			ByteProvider provider = splitDyldCache.getProvider(index);
			this.header = new MachHeader(provider, dylibOffset, false).parse(splitDyldCache);
			this.textSegment = header.getSegment(SegmentNames.SEG_TEXT);
			this.linkEditSegment = header.getSegment(SegmentNames.SEG_LINKEDIT);
			this.reader = new BinaryReader(provider, header.isLittleEndian());
			this.monitor = monitor;

			// Keep track of each segment's file offset in the DYLD cache.
			// Also keep a running total of each segment's size so we know how big to make our
			// packed array.
			int packedSize = 0;
			int packedLinkEditSize = 0;
			for (SegmentCommand segment : header.getAllSegments()) {
				packedSegmentStarts.put(segment, packedSize);

				// The __LINKEDIT segment is shared across all DYLIB's, so it is very large.  We
				// Want to create a new packed __LINKEDIT segment with only the relevant info for
				// the DYLIB we are extracting, resulting in a significantly smaller file.
				if (segment == linkEditSegment) {
					for (LoadCommand cmd : header.getLoadCommands()) {
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

				// Some older DYLDs use a file offset of 0 for their __TEXT segment, despite being
				// in the middle of the cache and despite the other segments using absolute cache
				// file offsets. Adjust these segments to be consistent with all the other segments,
				// and store their adjustment values so we can later work with them as absolute
				// cache file offsets.
				if (segment == textSegment && segment.getFileOffset() == 0) {
					segment.setFileOffset(dylibOffset);
					packedSegmentAdjustments.put(segment, (int) dylibOffset);
				}
			}

			packed = new byte[packedSize];
			
			// Copy each segment into the packed array (leaving no gaps)
			for (SegmentCommand segment : header.getAllSegments()) {
				long segmentSize = segment.getFileSize();
				ByteProvider segmentProvider = getSegmentProvider(segment, splitDyldCache);
				if (segment.getFileOffset() + segmentSize > segmentProvider.length()) {
					segmentSize = segmentProvider.length() - segment.getFileOffset();
					Msg.warn(this, segment.getSegmentName() +
						" segment extends beyond end of file.  Truncating...");
				}
				byte[] bytes;
				if (segment == linkEditSegment) {
					bytes =
						createPackedLinkEditSegment(segmentProvider, packedLinkEditSize);
				}
				else {
					bytes = segmentProvider.readBytes(segment.getFileOffset(), segmentSize);
				}
				System.arraycopy(bytes, 0, packed, packedSegmentStarts.get(segment), bytes.length);
			}

			// Fixup various fields in the packed array
			fixupMachHeader();
			fixupLoadCommands();

			// TODO: Fixup pointer chains
		}

		/**
		 * Gets a {@link ByteProvider} for this {@link PackedSegments} object
		 * 
		 * @param fsrl FSRL identity of the file
		 * @return A {@link ByteProvider} for this {@link PackedSegments} object
		 */
		public ByteProvider getByteProvider(FSRL fsrl) {
			return new ByteArrayProvider(packed, fsrl);
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
					byte[] packedSymbolStringTable = new byte[cmd.getLinkerDataSize()];
					List<NList> symbols = symbolTable.getSymbols();
					int nlistIndex = 0;
					int stringIndex = symbols.get(0).getSize() * symbols.size();
					int stringIndexOrig = stringIndex;
					for (NList nlist : symbols) {
						byte[] nlistArray = nlistToArray(nlist, stringIndex);
						byte[] stringArray = nlist.getString().getBytes(StandardCharsets.US_ASCII);
						System.arraycopy(toBytes(stringIndex - stringIndexOrig, 4), 0, nlistArray,
							0, 4);
						System.arraycopy(nlistArray, 0, packedSymbolStringTable, nlistIndex,
							nlistArray.length);
						System.arraycopy(stringArray, 0, packedSymbolStringTable, stringIndex,
							stringArray.length);
						nlistIndex += nlistArray.length;
						stringIndex += stringArray.length + 1; // null terminate
					}
					System.arraycopy(packedSymbolStringTable, 0, packedLinkEdit,
						packedLinkEditDataStarts.get(cmd),
						packedSymbolStringTable.length);
				}
				else {
					byte[] bytes =
						linkEditSegmentProvider.readBytes(cmd.getLinkerDataOffset(), cmd.getLinkerDataSize());
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
			DataConverter conv = DataConverter.getInstance(!header.isLittleEndian());
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
		 * Fixes-up the {@link MachHeader} in the newly packed DYLIB
		 * 
		 * @throws IOException If there was an IO-related issue performing the fix-up
		 */
		private void fixupMachHeader() throws IOException {
			// Indicate that the new packed DYLIB is no longer in the cache
			set(header.getStartIndexInProvider() + 0x18,
				header.getFlags() & ~MachHeaderFlags.MH_DYLIB_IN_CACHE, 4);
		}

		/**
		 * Fixes-up various fields in the new packed DYLIB's load commands
		 * 
		 * @throws IOException If there was an IO-related issue performing the fix-up
		 */
		private void fixupLoadCommands() throws IOException {
			// Fixup indices, offsets, etc in the packed DYLIB's load commands
			for (LoadCommand cmd : header.getLoadCommands()) {
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
		 * Fixes-up the old DYLD file offsets and size in the given segment so they are correct for 
		 * the newly packed DYLIB
		 * 
		 * @param segment The segment to fix-up
		 * @param is64bit True if the segment is 64-bit; false if 32-bit
		 * @throws IOException If there was an IO-related issue performing the fix-up
		 */
		private void fixupSegment(SegmentCommand segment, boolean is64bit) throws IOException {
			long adjustment = packedSegmentAdjustments.getOrDefault(segment, 0);
			if (segment.getFileOffset() > 0) {
				fixup(segment.getStartIndex() + (is64bit ? 0x28 : 0x20), adjustment,
					is64bit ? 8 : 4, segment);
			}
			if (segment.getVMsize() > 0) {
				set(segment.getStartIndex() + (is64bit ? 0x20 : 0x1c), segment.getVMsize(),
					is64bit ? 8 : 4);
			}
			if (segment.getFileSize() > 0) {
				set(segment.getStartIndex() + (is64bit ? 0x30 : 0x24), segment.getFileSize(),
					is64bit ? 8 : 4);
			}
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
		 * Fixes-up the old DYLD file offsets in the given symbol table so they are correct for the 
		 * newly packed DYLIB
		 * 
		 * @param cmd The symbol table to fix-up
		 * @throws IOException If there was an IO-related issue performing the fix-up
		 */
		private void fixupSymbolTable(SymbolTableCommand cmd) throws IOException {
			if (cmd.getSymbolOffset() > 0) {
				long symbolOffset = fixup(cmd.getStartIndex() + 0x8, getLinkEditAdjustment(cmd), 4,
					linkEditSegment);
				if (cmd.getStringTableOffset() > 0) {
					if (cmd.getNumberOfSymbols() > 0) {
						set(cmd.getStartIndex() + 0x10,
							symbolOffset + cmd.getNumberOfSymbols() * cmd.getSymbolAt(0).getSize(),
							4);
					}
					else {
						set(cmd.getStartIndex() + 0x10, symbolOffset, 4);
						set(cmd.getStartIndex() + 0x14, 0, 4);
					}
				}
			}
		}

		/**
		 * Fixes-up the old DYLD file offsets in the given dynamic symbol table so they are correct 
		 * for the newly packed DYLIB.
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
		 * Fixes-up the old DYLD file offsets in the given DYLD Info command so they are correct for
		 * the newly packed DYLIB.
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
		 * Fixes-up the old DYLD file offsets in the given link edit data command so they are correct 
		 * for the newly packed DYLIB
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
		 * Gets a value that will need to be added to a DYLD file offset into the __LINKEDIT segment
		 * to account for our new __LINKEDIT segment being packed
		 *  
		 * @param cmd The target __LINKEDIT {@link LoadCommand}
		 * @return The adjustment value
		 */
		private long getLinkEditAdjustment(LoadCommand cmd) {
			return packedLinkEditDataStarts.getOrDefault(cmd, 0) -
				(cmd.getLinkerDataOffset() - linkEditSegment.getFileOffset());
		}

		/**
		 * Sets the bytes at the given DYLD file offset to the given value.  The provided file 
		 * offset is assumed to map to a field in a load command.
		 *  
		 * @param fileOffset The DYLD file offset to set
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
				System.arraycopy(newBytes, 0, packed,
					(int) getPackedOffset(fileOffset, textSegment), newBytes.length);
			}
			catch (NotFoundException e) {
				Msg.warn(this, e.getMessage());
			}
		}

		/**
		 * Fixes up the bytes at the given DYLD file offset to map to the correct offset in the
		 * packed DYLIB.  The provided file offset is assumed to map to a field in a load command.
		 *  
		 * @param fileOffset The DYLD file offset to fix-up
		 * @param adjustment A value to add to the bytes at the given DYLD file offset prior to 
		 *   looking them up in the packed DYLIB
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
				System.arraycopy(newBytes, 0, packed,
					(int) getPackedOffset(fileOffset, textSegment), newBytes.length);
			}
			catch (NotFoundException e) {
				Msg.warn(this, e.getMessage());
			}

			return ret;
		}

		/**
		 * Converts the given DYLD file offset to an offset into the packed DYLIB
		 * 
		 * @param fileOffset The DYLD file offset to convert
		 * @param segment The segment that contains the file offset; null if unknown
		 * @return An offset into the packed DYLIB
		 * @throws NotFoundException If there was no corresponding DYLIB offset
		 */
		private long getPackedOffset(long fileOffset, SegmentCommand segment)
				throws NotFoundException {
			Integer segmentStart = packedSegmentStarts.get(segment);
			if (segmentStart != null) {
				return fileOffset - segment.getFileOffset() + segmentStart;
			}
			throw new NotFoundException(
				"Failed to convert DYLD file offset to packed DYLIB offset: " +
					Long.toHexString(fileOffset));
		}

		/**
		 * Gets the {@link ByteProvider} that contains the given {@link SegmentCommand segment}
		 * 
		 * @param segment The {@link SegmentCommand segment}
		 * @param splitDyldCache The {@link SplitDyldCache}
		 * @return The {@link ByteProvider} that contains the given {@link SegmentCommand segment}
		 * @throws IOException If a {@link ByteProvider} could not be found
		 */
		private ByteProvider getSegmentProvider(SegmentCommand segment,
				SplitDyldCache splitDyldCache) throws IOException {
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader dyldCacheheader = splitDyldCache.getDyldCacheHeader(i);
				for (DyldCacheMappingInfo mappingInfo : dyldCacheheader.getMappingInfos()) {
					if (mappingInfo.contains(segment.getVMaddress())) {
						return splitDyldCache.getProvider(i);
					}
				}
			}
			throw new IOException(
				"Failed to find provider for segment: " + segment.getSegmentName());
		}

		/**
		 * Converts the given value to a byte array
		 * 
		 * @param value The value to convert to a byte array
		 * @param size The number of bytes to convert (must be 4 or 8)
		 * @return The value as a byte array of the given size
		 * @throws IllegalArgumentException if size is an unsupported value
		 */
		private byte[] toBytes(long value, int size) throws IllegalArgumentException {
			if (size != 4 && size != 8) {
				throw new IllegalArgumentException("Size must be 4 or 8 (got " + size + ")");
			}
			DataConverter converter = LittleEndianDataConverter.INSTANCE;
			return size == 8 ? converter.getBytes(value) : converter.getBytes((int) value);
		}
	}
}
