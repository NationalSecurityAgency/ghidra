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
 * Represents a dyld_cache_slide_info2 structure.
 * <p>
 * Seen in iOS 10 and 11. 
 */
public class DyldCacheSlideInfo2 extends DyldCacheSlideInfoCommon {

	private static final int DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000;
	private static final int DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA = 0x8000;

	private int pageSize;
	private int pageStartsOffset;
	private int pageStartsCount;
	private int pageExtrasOffset;
	private int pageExtrasCount;
	private long deltaMask;
	private long valueAdd;
	private short[] pageStartsEntries;
	private short[] pageExtrasEntries;

	/**
	 * Create a new {@link DyldCacheSlideInfo2}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 2
	 * @param mappingAddress The base address of where the slide fixups will take place
	 * @param mappingSize The size of the slide fixups block
	 * @param mappingFileOffset The base file offset of where the slide fixups will take place
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 2
	 */
	public DyldCacheSlideInfo2(BinaryReader reader, long mappingAddress, long mappingSize,
			long mappingFileOffset) throws IOException {
		super(reader, mappingAddress, mappingSize, mappingFileOffset);
		pageSize = reader.readNextInt();
		pageStartsOffset = reader.readNextInt();
		pageStartsCount = reader.readNextInt();
		pageExtrasOffset = reader.readNextInt();
		pageExtrasCount = reader.readNextInt();
		deltaMask = reader.readNextLong();
		valueAdd = reader.readNextLong();
		pageStartsEntries = reader.readNextShortArray(pageStartsCount);
		pageExtrasEntries = reader.readNextShortArray(pageExtrasCount);
	}

	/**
	 * {@return The page size}
	 */
	public long getPageSize() {
		return Integer.toUnsignedLong(pageSize);
	}

	/**
	 * {@return The page starts offset}
	 */
	public long getPageStartsOffset() {
		return Integer.toUnsignedLong(pageStartsOffset);
	}

	/**
	 * {@return The page starts count}
	 */
	public long getPageStartsCount() {
		return Integer.toUnsignedLong(pageStartsCount);
	}

	/**
	 * {@return The page extras offset}
	 */
	public long getPageExtrasOffset() {
		return Integer.toUnsignedLong(pageExtrasOffset);
	}

	/**
	 * {@return The page extras count}
	 */
	public long getPageExtrasCount() {
		return Integer.toUnsignedLong(pageExtrasCount);
	}

	/**
	 * {@return The delta mask}
	 */
	public long getDeltaMask() {
		return deltaMask;
	}

	/**
	 * {@return The "value add"}
	 */
	public long getValueAdd() {
		return valueAdd;
	}

	/**
	 * {@return The page starts array}
	 */
	public short[] getPageStarts() {
		return pageStartsEntries;
	}

	/**
	 * {@return The page extras array}
	 */
	public short[] getPageExtras() {
		return pageExtrasEntries;
	}

	@Override
	public List<DyldFixup> getSlideFixups(BinaryReader reader, int pointerSize, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {

		List<DyldFixup> fixups = new ArrayList<>();

		monitor.initialize(pageStartsCount, "Getting DYLD Cache V2 slide fixups...");
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.increment();

			long segmentOffset = pageSize * index;
			int pageEntry = Short.toUnsignedInt(pageStartsEntries[index]);
			if (pageEntry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
				continue;
			}

			if ((pageEntry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) != 0) {
				// go into extras and process list of chain entries for the same page
				int extraIndex = (pageEntry & CHAIN_OFFSET_MASK);
				do {
					pageEntry = Short.toUnsignedInt(pageExtrasEntries[extraIndex]);
					long pageOffset = (pageEntry & CHAIN_OFFSET_MASK) * BYTES_PER_CHAIN_OFFSET;
					fixups.addAll(processPointerChain(segmentOffset, pageOffset, reader,
						pointerSize, monitor));
					extraIndex++;
				}
				while ((pageEntry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0);
			}
			else {
				long pageOffset = pageEntry * BYTES_PER_CHAIN_OFFSET;
				fixups.addAll(
					processPointerChain(segmentOffset, pageOffset, reader, pointerSize, monitor));
			}
		}

		return fixups;
	}

	/**
	 * Walks the pointer chain at the given reader offset to find necessary {@link DyldFixup}s
	 * 
	 * @param segmentOffset The segment offset
	 * @param pageOffset The page offset
	 * @param reader A reader positioned at the start of the segment to fix
	 * @param pointerSize The size of a pointer in bytes
	 * @param monitor A cancellable monitor
	 * @return A {@link List} of {@link DyldFixup}s
	 * @throws IOException If an IO-related error occurred
	 * @throws CancelledException If the user cancelled the operation
	 */
	private List<DyldFixup> processPointerChain(long segmentOffset, long pageOffset,
			BinaryReader reader, int pointerSize, TaskMonitor monitor)
			throws IOException, CancelledException {

		List<DyldFixup> fixups = new ArrayList<>(1024);
		long valueMask = ~deltaMask;
		long deltaShift = Long.numberOfTrailingZeros(deltaMask);

		for (long delta = -1; delta != 0; pageOffset += delta * 4) {
			monitor.checkCancelled();

			long dataOffset = segmentOffset + pageOffset;
			long chainValue =
				pointerSize == 8 ? reader.readLong(dataOffset) : reader.readUnsignedInt(dataOffset);

			delta = (chainValue & deltaMask) >> deltaShift;
			chainValue &= valueMask;
			if (chainValue != 0) {
				chainValue += valueAdd /* + slide */;
				fixups.add(new DyldFixup(dataOffset, chainValue, pointerSize, null, null));
			}
		}

		return fixups;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info2", 0);
		struct.add(DWORD, "version", "currently 2");
		struct.add(DWORD, "page_size", "currently 4096 (may also be 16384)");
		struct.add(DWORD, "page_starts_offset", "");
		struct.add(DWORD, "page_starts_count", "");
		struct.add(DWORD, "page_extras_offset", "");
		struct.add(DWORD, "page_extras_count", "");
		struct.add(QWORD, "delta_mask",
			"which (contiguous) set of bits contains the delta to the next rebase location");
		struct.add(QWORD, "value_add", "");
		if (pageStartsCount > 0) {
			if (pageStartsOffset > 0x28) {
				struct.add(new ArrayDataType(BYTE, pageStartsOffset - 0x28, -1), "align", "");
			}
			struct.add(new ArrayDataType(WORD, pageStartsCount, -1), "page_starts", "");
		}
		if (pageExtrasCount > 0) {
			if (pageExtrasOffset > (pageStartsOffset + (pageStartsCount * 2))) {
				struct.add(
					new ArrayDataType(BYTE,
						pageExtrasOffset - (pageStartsOffset + (pageStartsCount * 2)), -1),
					"align", "");
			}
			struct.add(new ArrayDataType(WORD, pageExtrasCount, -1), "page_extras", "");
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
