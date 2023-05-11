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
 * Represents a dyld_cache_slide_info structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/cache-builder/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
public class DyldCacheSlideInfo1 extends DyldCacheSlideInfoCommon {

	private int toc_offset;
	private int toc_count;
	private int entries_offset;
	private int entries_count;
	private int entries_size;

	private short toc[];
	private byte bits[][];

	public int getTocOffset() {
		return toc_offset;
	}

	public int getTocCount() {
		return toc_count;
	}

	public int getEntriesOffset() {
		return entries_offset;
	}

	public int getEntriesCount() {
		return entries_count;
	}

	public int getEntriesSize() {
		return entries_size;
	}

	public short[] getToc() {
		return toc;
	}

	public byte[][] getEntries() {
		return bits;
	}

	/**
	 * Create a new {@link DyldCacheSlideInfo1}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 1
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 1
	 */
	public DyldCacheSlideInfo1(BinaryReader reader) throws IOException {
		super(reader);
		long startIndex = reader.getPointerIndex() - 4;  // version # already read

		toc_offset = reader.readNextInt();
		toc_count = reader.readNextInt();
		entries_offset = reader.readNextInt();
		entries_count = reader.readNextInt();
		entries_size = reader.readNextInt();

		reader.setPointerIndex(startIndex + toc_offset);
		toc = reader.readNextShortArray(toc_count);

		reader.setPointerIndex(startIndex + entries_offset);
		bits = new byte[entries_count][];
		for (int i = 0; i < entries_count; i++) {
			bits[i] = reader.readNextByteArray(entries_size);
		}
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
		if (toc_offset > 0x18) {
			struct.add(new ArrayDataType(ByteDataType.dataType, toc_offset - 0x18, -1),
				"tocAlignment", "");
		}
		struct.add(new ArrayDataType(WordDataType.dataType, toc_count, -1), "toc", "");
		if (entries_offset > (toc_offset + (toc_count * 2))) {
			struct.add(new ArrayDataType(ByteDataType.dataType,
				entries_offset - (toc_offset + (toc_count * 2)), -1), "entriesAlignment", "");
		}
		struct.add(new ArrayDataType(new ArrayDataType(ByteDataType.dataType, entries_size, -1),
			entries_count, -1), "entries", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public void fixPageChains(Program program, DyldCacheHeader dyldCacheHeader,
			boolean addRelocations, MessageLog log, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {

		Memory memory = program.getMemory();

		List<DyldCacheMappingInfo> mappingInfos = dyldCacheHeader.getMappingInfos();
		DyldCacheMappingInfo dyldCacheMappingInfo = mappingInfos.get(DATA_PAGE_MAP_ENTRY);
		long dataPageStart = dyldCacheMappingInfo.getAddress();

		List<Address> unchainedLocList = new ArrayList<>(1024);

		monitor.setMessage("Fixing V1 chained data page pointers...");

		monitor.setMaximum(entries_count);

		// V1 pointers currently don't need to be fixed, unless the pointers the
		// dyld is slid from its preferred location.
		for (int tocIndex = 0; tocIndex < toc_count; tocIndex++) {
			monitor.checkCancelled();

			int entryIndex = (toc[tocIndex]) & 0xFFFF;
			if (entryIndex > entries_count || entryIndex > bits.length) {
				log.appendMsg("Entry too big! [" + tocIndex + "] " + entryIndex + " " +
					entries_count + " " + bits.length);
				continue;
			}

			byte entry[] = bits[entryIndex];

			long page = dataPageStart + (4096L * tocIndex);
			for (int pageEntriesIndex = 0; pageEntriesIndex < 128; ++pageEntriesIndex) {
				long prtEntryBitmap = entry[pageEntriesIndex] & 0xffL;

				if (prtEntryBitmap != 0) {
					for (int bitMapIndex = 0; bitMapIndex < 8; ++bitMapIndex) {
						if ((prtEntryBitmap & (1L << bitMapIndex)) != 0) {
							long loc = (page + pageEntriesIndex * 8 * 4 + bitMapIndex * 4);
							Address addr =
								memory.getProgram().getLanguage().getDefaultSpace().getAddress(loc);
							long origValue = memory.getLong(addr);

							long value = origValue /* + slide */ ;

							// not actually changing bytes, so not really a relocation, but a relocate-able place
							if (addRelocations) {
								addRelocationTableEntry(program, addr, 0x1000, value, 8, null);
							}
							//memory.setLong(addr, value);

							unchainedLocList.add(addr);
						}
					}
				}
			}

			monitor.setProgress(tocIndex);
		}

		createChainPointers(program, unchainedLocList, monitor);
	}

}
