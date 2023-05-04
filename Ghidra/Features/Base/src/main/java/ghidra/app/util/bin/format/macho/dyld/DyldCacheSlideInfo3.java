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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_slide_info3 structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/cache-builder/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
public class DyldCacheSlideInfo3 extends DyldCacheSlideInfoCommon {

	private static final int DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFFF;

	private int page_size;
	private int page_starts_count;
	private long auth_value_add;
	private short page_starts[];

	public int getPageSize() {
		return page_size;
	}

	public int getPageStartsCount() {
		return page_starts_count;
	}

	public long getAuthValueAdd() {
		return auth_value_add;
	}

	public short[] getPageStarts() {
		return page_starts;
	}

	/**
	 * Create a new {@link DyldCacheSlideInfo3}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 3
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 3
	 */
	public DyldCacheSlideInfo3(BinaryReader reader) throws IOException {
		super(reader);
		page_size = reader.readNextInt();
		page_starts_count = reader.readNextInt();
		int pad = reader.readNextInt();
		auth_value_add = reader.readNextLong();
		page_starts = reader.readNextShortArray(page_starts_count);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info3", 0);
		struct.add(DWORD, "version", "");
		struct.add(DWORD, "page_size", "");
		struct.add(DWORD, "page_starts_count", "");
		struct.add(DWORD, "pad", "");
		struct.add(QWORD, "auth_value_add", "");
		struct.add(new ArrayDataType(WORD, page_starts_count, 1), "page_starts", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public void fixPageChains(Program program, DyldCacheHeader dyldCacheHeader,
			boolean addRelocations, MessageLog log, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		long fixedAddressCount = 0;

		List<DyldCacheMappingAndSlideInfo> mappingInfos =
			dyldCacheHeader.getCacheMappingAndSlideInfos();
		
		if (mappingInfos.size() <= DATA_PAGE_MAP_ENTRY) {
			return;
		}
		
		DyldCacheMappingAndSlideInfo dyldCacheMappingInfo = mappingInfos.get(DATA_PAGE_MAP_ENTRY); // default
		for (DyldCacheMappingAndSlideInfo cacheSlideInfo : mappingInfos) {
			if (cacheSlideInfo.getSlideInfoFileOffset() == getSlideInfoOffset()) {
				dyldCacheMappingInfo = cacheSlideInfo;
				break;
			}
		}

		long dataPageStart = dyldCacheMappingInfo.getAddress();
		long pageSize = getPageSize();
		long pageStartsCount = getPageStartsCount();

		long authValueAdd = getAuthValueAdd();

		short[] pageStarts = getPageStarts();

		monitor.setMessage("Fixing V3 chained data page pointers...");

		monitor.setMaximum(pageStartsCount);
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.checkCancelled();

			long page = dataPageStart + (pageSize * index);

			monitor.setProgress(index);

			int pageEntry = pageStarts[index] & 0xffff;
			if (pageEntry == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
				continue;
			}

			long pageOffset = (pageEntry / 8) * 8; // first entry byte based

			List<Address> unchainedLocList;
			unchainedLocList = processPointerChain3(program, page, pageOffset, authValueAdd,
				addRelocations, monitor);

			fixedAddressCount += unchainedLocList.size();

			createChainPointers(program, unchainedLocList, monitor);
		}

		log.appendMsg("Fixed " + fixedAddressCount + " chained pointers.");

		monitor.setMessage("Created " + fixedAddressCount + " chained pointers");
	}

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param program the program 
	 * @param page within data pages that has pointers to be unchained
	 * @param nextOff offset within the page that is the chain start
	 * @param auth_value_add value to be added to each chain pointer
	 * 
	 * @return list of locations that were unchained
	 * 
	 * @throws MemoryAccessException IO problem reading file
	 * @throws CancelledException user cancels
	 */
	private List<Address> processPointerChain3(Program program, long page, long nextOff,
			long auth_value_add, boolean addRelocation, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		// TODO: should the image base be used to perform the ASLR slide on the pointers.
		//        currently image is kept at it's initial location with no ASLR.
		Address chainStart = program.getLanguage().getDefaultSpace().getAddress(page);
		Memory memory = program.getMemory();

		List<Address> unchainedLocList = new ArrayList<>(1024);

		long delta = -1;
		while (delta != 0) {
			monitor.checkCancelled();

			Address chainLoc = chainStart.add(nextOff);
			long chainValue = memory.getLong(chainLoc);

			// if authenticated pointer
			boolean isAuthenticated = chainValue >>> 63 != 0;
			delta = (chainValue & (0x7FFL << 51L)) >> 51L;

			if (isAuthenticated) {
				long offsetFromSharedCacheBase = chainValue & 0xFFFFFFFFL;
				//long diversityData = (chainValue >> 32L) & 0xFFFFL;
				//long hasAddressDiversity = (chainValue >> 48L) & 0x1L;
				//long key = (chainValue >> 49L) & 0x3L;
				chainValue = offsetFromSharedCacheBase + auth_value_add;
			}
			else {
				long top8Bits = chainValue & 0x0007F80000000000L;
				long bottom43Bits = chainValue & 0x000007FFFFFFFFFFL;
				chainValue = (top8Bits << 13) | bottom43Bits;
				// chainValue += slideAmount - if we were sliding
			}

			if (addRelocation) {
				addRelocationTableEntry(program, chainLoc, 3 * (isAuthenticated ? -1 : 1),
					chainValue, 8, null);
			}
			memory.setLong(chainLoc, chainValue);

			// delay creating data until after memory has been changed
			unchainedLocList.add(chainLoc);

			nextOff += delta * 8;
		}

		return unchainedLocList;
	}
}
