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
 * Represents a dyld_cache_slide_info4 structure. 
 * <p>
 * Not seen yet.
 */
public class DyldCacheSlideInfo4 extends DyldCacheSlideInfoCommon {

	private static final int DYLD_CACHE_SLIDE4_PAGE_NO_REBASE = 0xFFFF;
	private static final int DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA = 0x8000;

	private static final int HEADERSIZE4 = 40;
	private int pageSize;
	private int pageStartsOffset;
	private int pageStartsCount;
	private int pageExtrasOffset;
	private int pageExtrasCount;
	private long deltaMask;
	private long valueAdd;

	private short[] pageStarts;
	private short[] pageExtras;

	/**
	 * {@return The page size}
	 */
	public int getPageSize() {
		return pageSize;
	}

	/**
	 * {@return The page starts offset}
	 */
	public int getPageStartsOffset() {
		return pageStartsOffset;
	}

	/**
	 * {@return The page starts count}
	 */
	public int getPageStartsCount() {
		return pageStartsCount;
	}

	/**
	 * {@return The page extras offset}
	 */
	public int getPageExtrasOffset() {
		return pageExtrasOffset;
	}

	/**
	 * {@return The page extras count}
	 */
	public int getPageExtrasCount() {
		return pageExtrasCount;
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
		return pageStarts;
	}

	/**
	 * {@return The page extras array}
	 */
	public short[] getPageExtras() {
		return pageExtras;
	}

	/**
	 * Create a new {@link DyldCacheSlideInfo4}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 3
	 * @param mappingAddress The base address of where the slide fixups will take place
	 * @param mappingSize The size of the slide fixups block
	 * @param mappingFileOffset The base file offset of where the slide fixups will take place
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 3
	 */
	public DyldCacheSlideInfo4(BinaryReader reader, long mappingAddress, long mappingSize,
			long mappingFileOffset) throws IOException {
		super(reader, mappingAddress, mappingSize, mappingFileOffset);
		pageSize = reader.readNextInt();
		pageStartsOffset = reader.readNextInt();
		pageStartsCount = reader.readNextInt();
		pageExtrasOffset = reader.readNextInt();
		pageExtrasCount = reader.readNextInt();
		deltaMask = reader.readNextLong();
		valueAdd = reader.readNextLong();
		reader.setPointerIndex(pageStartsOffset);
		pageStarts = reader.readNextShortArray(pageStartsCount);
		reader.setPointerIndex(pageExtrasOffset);
		pageExtras = reader.readNextShortArray(pageExtrasCount);
	}

	@Override
	public List<DyldFixup> getSlideFixups(BinaryReader reader, int pointerSize,
			MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		List<DyldFixup> fixups = new ArrayList<>();

		monitor.initialize(pageStartsCount, "Getting DYLD Cache V4 slide fixups...");
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.increment();

			long segmentOffset = pageSize * index;

			int pageEntry = Short.toUnsignedInt(pageStarts[index]);
			if (pageEntry == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE) {
				continue;
			}

			if ((pageEntry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) != 0) {
				// go into extras and process list of chain entries for the same page
				int extraIndex = (pageEntry & CHAIN_OFFSET_MASK);
				do {
					pageEntry = Short.toUnsignedInt(pageExtras[extraIndex]);
					long pageOffset = (pageEntry & CHAIN_OFFSET_MASK) * BYTES_PER_CHAIN_OFFSET;
					fixups.addAll(processPointerChain(segmentOffset, pageOffset, reader, monitor));
					extraIndex++;
				}
				while ((pageEntry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) == 0);
			}
			else {
				long pageOffset = pageEntry * BYTES_PER_CHAIN_OFFSET;
				fixups.addAll(processPointerChain(segmentOffset, pageOffset, reader, monitor));

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
	 * @param monitor A cancellable monitor
	 * @return A {@link List} of {@link DyldFixup}s
	 * @throws IOException If an IO-related error occurred
	 * @throws CancelledException If the user cancelled the operation
	 */
	private List<DyldFixup> processPointerChain(long segmentOffset, long pageOffset,
			BinaryReader reader, TaskMonitor monitor) throws IOException, CancelledException {
		List<DyldFixup> fixups = new ArrayList<>(1024);
		long valueMask = ~deltaMask;
		long deltaShift = Long.numberOfTrailingZeros(deltaMask);

		for (long delta = -1; delta != 0; pageOffset += delta * 4) {
			monitor.checkCancelled();

			long dataOffset = segmentOffset + pageOffset;
			int chainValue = reader.readInt(dataOffset);

			delta = (chainValue & deltaMask) >> deltaShift;
			chainValue &= valueMask;
			if ((chainValue & 0xFFFF8000) == 0) {
				// small positive non-pointer, use as-is
			}
			else if ((chainValue & 0x3FFF8000) == 0x3FFF8000) {
				chainValue |= 0xC0000000;
			}
			else {
				chainValue += valueAdd /* + slide */;
			}

			fixups.add(new DyldFixup(dataOffset, chainValue, 4, null, null));
		}

		return fixups;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info4", 0);
		struct.add(DWORD, "version", "currently 4");
		struct.add(DWORD, "page_size", "currently 4096 (may also be 16384)");
		struct.add(DWORD, "page_starts_offset", "");
		struct.add(DWORD, "page_starts_count", "");
		struct.add(DWORD, "page_extras_offset", "");
		struct.add(DWORD, "page_extras_count", "");
		struct.add(QWORD, "delta_mask",
			"which (contiguous) set of bits contains the delta to the next rebase location (0xC0000000)");
		struct.add(QWORD, "value_add", "base address of cache");

		if (pageStartsOffset == HEADERSIZE4) {
			struct.add(new ArrayDataType(WORD, pageStartsCount, 1), "page_starts", "");
		}
		if (pageExtrasOffset == (HEADERSIZE4 + pageStartsCount * 2)) {
			struct.add(new ArrayDataType(WORD, pageExtrasCount, 1), "page_extras", "");
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
