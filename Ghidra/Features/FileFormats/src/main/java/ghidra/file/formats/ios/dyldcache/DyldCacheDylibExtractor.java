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

import java.io.*;
import java.util.HashMap;
import java.util.Map;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * A class for extracting DYLIB files from a {@link DyldCacheFileSystem}
 */
public class DyldCacheDylibExtractor {

	/**
	 * Gets an {@link InputStream} that reads a DYLIB from a {@link DyldCacheFileSystem}.  The
	 * DYLIB's header will be altered to account for its segment bytes being packed down.   
	 * 
	 * @param dylibOffset The offset of the DYLIB in the given provider
	 * @param provider The DYLD
	 * @param monitor A cancellable {@link TaskMonitor}
	 * @return An {@link InputStream} that reads the specified DYLIB from the given DYLD 
	 *   {@link ByteProvider}
	 * @throws IOException If there was an IO-related issue with extracting the DYLIB
	 * @throws MachException If there was an error parsing the DYLIB headers
	 */
	public static InputStream extractDylib(long dylibOffset, ByteProvider provider,
			TaskMonitor monitor) throws IOException, MachException {

		// Make sure Mach-O header is valid
		MachHeader header = MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider,
			dylibOffset, false);
		header.parse();

		// Pack the DYLIB
		PackedDylib packedDylib = new PackedDylib(header, dylibOffset, provider);

		// Fixup indices, offsets, etc in the packed DYLIB's header
		for (LoadCommand cmd : header.getLoadCommands()) {
			if (monitor.isCancelled()) {
				break;
			}
			switch (cmd.getCommandType()) {
				case LoadCommandTypes.LC_SEGMENT:
					fixupSegment((SegmentCommand) cmd, packedDylib, false, monitor);
					break;
				case LoadCommandTypes.LC_SEGMENT_64:
					fixupSegment((SegmentCommand) cmd, packedDylib, true, monitor);
					break;
				case LoadCommandTypes.LC_SYMTAB:
					fixupSymbolTable((SymbolTableCommand) cmd, packedDylib);
					break;
				case LoadCommandTypes.LC_DYSYMTAB:
					fixupDynamicSymbolTable((DynamicSymbolTableCommand) cmd, packedDylib);
					break;
				case LoadCommandTypes.LC_DYLD_INFO:
				case LoadCommandTypes.LC_DYLD_INFO_ONLY:
					fixupDyldInfo((DyldInfoCommand) cmd, packedDylib);
					break;
			}
		}

		return packedDylib.getInputStream();
	}

	/**
	 * Fixes-up the old DYLD file offsets in the given segment so they are correct for the newly 
	 *   packed DYLIB
	 * 
	 * @param cmd The segment to fix-up
	 * @param packedDylib The packed DYLIB
	 * @param is64bit True if the segment is 64-bit; false if 32-bit
	 * @param monitor A cancellable {@link TaskMonitor}
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private static void fixupSegment(SegmentCommand cmd, PackedDylib packedDylib, boolean is64bit,
			TaskMonitor monitor) throws IOException {
		if (cmd.getFileOffset() > 0 && cmd.getFileSize() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + (is64bit ? 0x28 : 0x20), is64bit ? 8 : 4);
		}
		long sectionStartIndex = cmd.getStartIndex() + (is64bit ? 0x48 : 0x38);
		for (Section section : cmd.getSections()) {
			if (monitor.isCancelled()) {
				break;
			}
			if (section.getOffset() > 0 && section.getSize() > 0) {
				packedDylib.fixup(sectionStartIndex + (is64bit ? 0x30 : 0x28), 4);
			}
			if (section.getRelocationOffset() > 0) {
				packedDylib.fixup(sectionStartIndex + (is64bit ? 0x38 : 0x30), 4);
			}
			sectionStartIndex += is64bit ? 0x50 : 0x44;
		}
	}

	/**
	 * Fixes-up the old DYLD file offsets in the given symbol table so they are correct for the 
	 * newly packed DYLIB
	 * 
	 * @param cmd The symbol table to fix-up
	 * @param packedDylib The packed DYLIB
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private static void fixupSymbolTable(SymbolTableCommand cmd, PackedDylib packedDylib)
			throws IOException {
		if (cmd.getSymbolOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x8, 4);
		}
		if (cmd.getStringTableOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x10, 4);
		}
	}

	/**
	 * Fixes-up the old DYLD file offsets in the given dynamic symbol table so they are correct for 
	 * the newly packed DYLIB
	 * 
	 * @param cmd The dynamic symbol table to fix-up
	 * @param packedDylib The packed DYLIB
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private static void fixupDynamicSymbolTable(DynamicSymbolTableCommand cmd,
			PackedDylib packedDylib) throws IOException {
		if (cmd.getTableOfContentsOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x20, 4);
		}
		if (cmd.getModuleTableOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x28, 4);
		}
		if (cmd.getReferencedSymbolTableOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x30, 4);
		}
		if (cmd.getIndirectSymbolTableOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x38, 4);
		}
		if (cmd.getExternalRelocationOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x40, 4);
		}
		if (cmd.getLocalRelocationOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x48, 4);
		}
	}

	/**
	 * Fixes-up the old DYLD file offsets in the given DYLD Info command so they are correct for the 
	 * newly packed DYLIB
	 * 
	 * @param cmd The DYLD Info command to fix-up
	 * @param packedDylib The packed DYLIB
	 * @throws IOException If there was an IO-related issue performing the fix-up
	 */
	private static void fixupDyldInfo(DyldInfoCommand cmd, PackedDylib packedDylib)
			throws IOException {
		if (cmd.getRebaseOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x8, 4);
		}
		if (cmd.getBindOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x10, 4);
		}
		if (cmd.getWeakBindOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x18, 4);
		}
		if (cmd.getLazyBindOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x20, 4);
		}
		if (cmd.getExportOffset() > 0) {
			packedDylib.fixup(cmd.getStartIndex() + 0x28, 4);
		}
	}

	/**
	 * A packed DYLIB that was once living inside of a DYLD.  The DYLIB is said to be packed
	 * because its segment file bytes, which were not adjacent in its containing DYLD, are now
	 * adjacent in its new array. 
	 */
	private static class PackedDylib {

		private BinaryReader reader;
		private Map<SegmentCommand, Integer> packedStarts;
		private byte[] packed;

		/**
		 * Creates a new {@link PackedDylib} object
		 * 
		 * @param header The DYLD's DYLIB's Mach-O header
		 * @param dylibOffset The offset of the DYLIB in the given provider
		 * @param provider The DYLD's bytes
		 * @throws IOException If there was an IO-related error
		 */
		public PackedDylib(MachHeader header, long dylibOffset, ByteProvider provider)
				throws IOException {
			reader = new BinaryReader(provider, true);
			packedStarts = new HashMap<>();
			int size = 0;
			for (SegmentCommand segment : header.getAllSegments()) {
				packedStarts.put(segment, size);
				size += segment.getFileSize();

				// Some older DYLDs use relative file offsets for only their __TEXT segment.
				// Adjust these segments to be consistent with all the other segments.
				if (segment.getFileOffset() == 0) {
					segment.setFileOffset(dylibOffset);
				}
			}
			packed = new byte[size];
			for (SegmentCommand segment : header.getAllSegments()) {
				long segmentSize = segment.getFileSize();
				if (segment.getFileOffset() + segmentSize > provider.length()) {
					segmentSize = provider.length() - segment.getFileOffset();
					Msg.warn(this, segment.getSegmentName() +
						" segment extends beyond end of file.  Truncating...");
				}
				byte[] bytes = provider.readBytes(segment.getFileOffset(), segmentSize);
				System.arraycopy(bytes, 0, packed, packedStarts.get(segment), bytes.length);
			}
		}

		/**
		 * Gets an {@link InputStream} that reads the packed DYLIB
		 * 
		 * @return An {@link InputStream} that reads the packed DYLIB
		 */
		public InputStream getInputStream() {
			return new ByteArrayInputStream(packed);
		}

		/**
		 * Fixes up the bytes at the given DYLD file offset to map to the correct offset in the
		 * packed DYLIB
		 *  
		 * @param fileOffset The DYLD file offset to fix-up
		 * @param size The number of bytes to fix-up (must be 4 or 8)
		 * @throws IOException If there was an IO-related error
		 * @throws IllegalArgumentException if size is an unsupported value
		 */
		public void fixup(long fileOffset, int size) throws IOException {
			if (size != 4 && size != 8) {
				throw new IllegalArgumentException("Size must be 4 or 8 (got " + size + ")");
			}
			long orig = reader.readUnsignedValue(fileOffset, size);
			try {
				byte[] newBytes = toBytes(getPackedOffset(orig), size);
				System.arraycopy(newBytes, 0, packed, (int) getPackedOffset(fileOffset),
					newBytes.length);
			}
			catch (NotFoundException e) {
				Msg.warn(this, e.getMessage());
			}
		}

		/**
		 * Converts the given DYLD file offset to an offset into the packed DYLIB
		 * 
		 * @param fileOffset The DYLD file offset to convert
		 * @return An offset into the packed DYLIB
		 * @throws NotFoundException If there was no corresponding DYLIB offset
		 */
		private long getPackedOffset(long fileOffset) throws NotFoundException {
			for (SegmentCommand segment : packedStarts.keySet()) {
				if (fileOffset >= segment.getFileOffset() &&
					fileOffset < segment.getFileOffset() + segment.getFileSize()) {
					return fileOffset - segment.getFileOffset() + packedStarts.get(segment);
				}
			}
			throw new NotFoundException(
				"Failed to convert DYLD file offset to packed DYLIB offset: " +
					Long.toHexString(fileOffset));
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
