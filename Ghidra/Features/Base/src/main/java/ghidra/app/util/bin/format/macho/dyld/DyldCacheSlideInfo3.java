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
 * Represents a dyld_cache_slide_info3 structure.
 * <p>
 * Seen in iOS 12 and later. 
 */
public class DyldCacheSlideInfo3 extends DyldCacheSlideInfoCommon {

	private static final int DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFFF;

	private int pageSize;
	private int pageStartsCount;
	private long authValueAdd;
	private short[] pageStarts;

	/**
	 * {@return The page size}
	 */
	public int getPageSize() {
		return pageSize;
	}

	/**
	 * {@return The page starts count}
	 */
	public int getPageStartsCount() {
		return pageStartsCount;
	}

	/**
	 * {@return The "auth value add"}
	 */
	public long getAuthValueAdd() {
		return authValueAdd;
	}

	/**
	 * {@return The page starts array}
	 */
	public short[] getPageStarts() {
		return pageStarts;
	}

	/**
	 * Create a new {@link DyldCacheSlideInfo3}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 3
	 * @param mappingAddress The base address of where the slide fixups will take place
	 * @param mappingSize The size of the slide fixups block
	 * @param mappingFileOffset The base file offset of where the slide fixups will take place
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 3
	 */
	public DyldCacheSlideInfo3(BinaryReader reader, long mappingAddress, long mappingSize,
			long mappingFileOffset) throws IOException {
		super(reader, mappingAddress, mappingSize, mappingFileOffset);
		pageSize = reader.readNextInt();
		pageStartsCount = reader.readNextInt();
		reader.readNextInt(); // padding
		authValueAdd = reader.readNextLong();
		pageStarts = reader.readNextShortArray(pageStartsCount);
	}

	@Override
	public List<DyldFixup> getSlideFixups(BinaryReader reader, int pointerSize, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		List<DyldFixup> fixups = new ArrayList<>();

		monitor.initialize(pageStartsCount, "Getting DYLD Cache V3 slide fixups...");
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.increment();

			long segmentOffset = pageSize * index;

			int pageEntry = Short.toUnsignedInt(pageStarts[index]);
			if (pageEntry == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
				continue;
			}

			long pageOffset = (pageEntry / 8) * 8; // first entry byte based;
			fixups.addAll(processPointerChain(segmentOffset, pageOffset, reader, monitor));
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

		for (long delta = -1; delta != 0; pageOffset += delta * 8) {
			monitor.checkCancelled();

			long dataOffset = segmentOffset + pageOffset;
			long chainValue = reader.readLong(dataOffset);

			// if authenticated pointer
			boolean isAuthenticated = chainValue >>> 63 != 0;
			delta = (chainValue & (0x7FFL << 51L)) >> 51L;

			if (isAuthenticated) {
				long offsetFromSharedCacheBase = chainValue & 0xFFFFFFFFL;
				//long diversityData = (chainValue >> 32L) & 0xFFFFL;
				//long hasAddressDiversity = (chainValue >> 48L) & 0x1L;
				//long key = (chainValue >> 49L) & 0x3L;
				chainValue = offsetFromSharedCacheBase + authValueAdd /* + slide */;
			}
			else {
				long top8Bits = chainValue & 0x0007F80000000000L;
				long bottom43Bits = chainValue & 0x000007FFFFFFFFFFL;
				chainValue = (top8Bits << 13) | bottom43Bits /* + slide */;
			}

			fixups.add(new DyldFixup(dataOffset, chainValue, 8, null, null));
		}

		return fixups;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info3", 0);
		struct.add(DWORD, "version", "currently 3");
		struct.add(DWORD, "page_size", "currently 4096 (may also be 16384)");
		struct.add(DWORD, "page_starts_count", "");
		struct.add(DWORD, "pad", "");
		struct.add(QWORD, "auth_value_add", "");
		struct.add(new ArrayDataType(WORD, pageStartsCount, 1), "page_starts", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
