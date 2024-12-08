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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_slide_info structure.
 * <p>
 * Seen in iOS 8 and earlier. 
 */
public class DyldCacheSlideInfo1 extends DyldCacheSlideInfoCommon {

	private int tocOffset;
	private int tocCount;
	private int entriesOffset;
	private int entriesCount;
	private int entriesSize;

	private short[] toc;
	private byte[][] bits;

	/**
	 * Create a new {@link DyldCacheSlideInfo1}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 1
	 * @param mappingAddress The base address of where the slide fixups will take place
	 * @param mappingSize The size of the slide fixups block
	 * @param mappingFileOffset The base file offset of where the slide fixups will take place
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 1
	 */
	public DyldCacheSlideInfo1(BinaryReader reader, long mappingAddress, long mappingSize,
			long mappingFileOffset) throws IOException {
		super(reader, mappingAddress, mappingSize, mappingFileOffset);
		long startIndex = reader.getPointerIndex() - 4;  // version # already read

		tocOffset = reader.readNextInt();
		tocCount = reader.readNextInt();
		entriesOffset = reader.readNextInt();
		entriesCount = reader.readNextInt();
		entriesSize = reader.readNextInt();

		reader.setPointerIndex(startIndex + tocOffset);
		toc = reader.readNextShortArray(tocCount);

		reader.setPointerIndex(startIndex + entriesOffset);
		bits = new byte[entriesCount][];
		for (int i = 0; i < entriesCount; i++) {
			bits[i] = reader.readNextByteArray(entriesSize);
		}
	}

	/**
	 * {@return The TOC offset}
	 */
	public int getTocOffset() {
		return tocOffset;
	}

	/**
	 * {@return The TOC count}
	 */
	public int getTocCount() {
		return tocCount;
	}

	/**
	 * {@return The entries offset}
	 */
	public int getEntriesOffset() {
		return entriesOffset;
	}

	/**
	 * {@return The entries count}
	 */
	public int getEntriesCount() {
		return entriesCount;
	}

	/**
	 * {@return The entries size}
	 */
	public int getEntriesSize() {
		return entriesSize;
	}

	/**
	 * {@return The TOC}
	 */
	public short[] getToc() {
		return toc;
	}

	/**
	 * {@return The entries}
	 */
	public byte[][] getEntries() {
		return bits;
	}

	@Override
	public List<DyldFixup> getSlideFixups(BinaryReader reader, int pointerSize, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {

		List<DyldFixup> fixups = new ArrayList<>(1024);

		// V1 pointers currently don't need to be fixed, unless the cache is slid from its preferred
		// location.
		// Each bit represents whether or not its corresponding 4-byte address needs to get slid.
		monitor.initialize(tocCount, "Getting DYLD Cache V1 slide fixups...");
		for (int tocIndex = 0; tocIndex < tocCount; tocIndex++) {
			monitor.increment();

			int entryIndex = Short.toUnsignedInt(toc[tocIndex]);
			if (entryIndex >= entriesCount) {
				log.appendMsg("Entry too big! [" + tocIndex + "] " + entryIndex + " " +
					entriesCount + " " + bits.length);
				continue;
			}

			byte entry[] = bits[entryIndex];
			long segmentOffset = 4096L * tocIndex;
			for (int pageEntriesIndex = 0; pageEntriesIndex < 128; ++pageEntriesIndex) {
				monitor.checkCancelled();

				long prtEntryBitmap = Byte.toUnsignedLong(entry[pageEntriesIndex]);

				if (prtEntryBitmap != 0) {
					for (int bitMapIndex = 0; bitMapIndex < 8; ++bitMapIndex) {
						if ((prtEntryBitmap & (1L << bitMapIndex)) != 0) {
							long pageOffset = pageEntriesIndex * 8 * 4 + bitMapIndex * 4;
							long value = reader.readLong(segmentOffset + pageOffset) /* + slide */;
							fixups.add(
								new DyldFixup(segmentOffset + pageOffset, value, 8, null, null));
						}
					}
				}
			}
		}

		return fixups;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info", 0);
		struct.add(DWORD, "version", "");
		struct.add(DWORD, "toc_offset", "");
		struct.add(DWORD, "toc_count", "");
		struct.add(DWORD, "entries_offset", "");
		struct.add(DWORD, "entries_count", "");
		struct.add(DWORD, "entries_size", "");
		if (tocOffset > 0x18) {
			struct.add(new ArrayDataType(BYTE, tocOffset - 0x18, -1), "align", "");
		}
		struct.add(new ArrayDataType(WORD, tocCount, -1), "toc", "");
		if (entriesOffset > (tocOffset + (tocCount * 2))) {
			struct.add(new ArrayDataType(BYTE, entriesOffset - (tocOffset + (tocCount * 2)), -1),
				"align", "");
		}
		struct.add(new ArrayDataType(new ArrayDataType(BYTE, entriesSize, -1), entriesCount, -1),
			"entries", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
