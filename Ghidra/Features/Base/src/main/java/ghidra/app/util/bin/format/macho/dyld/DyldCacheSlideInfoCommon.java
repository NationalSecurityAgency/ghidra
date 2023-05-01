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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for representing the common components of the various dyld_cache_slide_info structures.
 * The intent is for the the full dyld_cache_slide_info structures to extend this and add their
 * specific parts.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/cache-builder/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
public abstract class DyldCacheSlideInfoCommon implements StructConverter {

	public static final int DATA_PAGE_MAP_ENTRY = 1;
	public static final int BYTES_PER_CHAIN_OFFSET = 4;
	public static final int CHAIN_OFFSET_MASK = 0x3fff;

	/**
	 * Parses the slide info
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info
	 * @param slideInfoOffset The offset of the slide info to parse
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return The slide info object
	 */
	public static DyldCacheSlideInfoCommon parseSlideInfo(BinaryReader reader, long slideInfoOffset,
			MessageLog log, TaskMonitor monitor) {
		if (slideInfoOffset == 0) {
			return null;
		}
		DyldCacheSlideInfoCommon returnedSlideInfo = null;

		monitor.setMessage("Parsing DYLD slide info...");
		monitor.initialize(1);
		try {
			reader.setPointerIndex(slideInfoOffset);
			int version = reader.readNextInt();
			reader.setPointerIndex(slideInfoOffset);
			switch (version) {
				case 1:
					returnedSlideInfo = new DyldCacheSlideInfo1(reader);
					break;
				case 2:
					returnedSlideInfo = new DyldCacheSlideInfo2(reader);
					break;
				case 3:
					returnedSlideInfo = new DyldCacheSlideInfo3(reader);
					break;
				case 4:
					returnedSlideInfo = new DyldCacheSlideInfo4(reader);
					break;
				default:
					throw new IOException();
			}
			monitor.incrementProgress(1);
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheHeader.class.getSimpleName(),
				"Failed to parse dyld_cache_slide_info.");
			return null;
		}
		returnedSlideInfo.slideInfoOffset = slideInfoOffset;
		return returnedSlideInfo;
	}

	protected int version;
	protected long slideInfoOffset;

	/**
	 * Create a new {@link DyldCacheSlideInfoCommon}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info
	 */
	public DyldCacheSlideInfoCommon(BinaryReader reader) throws IOException {
		version = reader.readNextInt();
	}

	/**
	 * Gets the version of the DYLD slide info.
	 * 
	 * @return The version of the DYLD slide info.
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Return the original slide info offset
	 * 
	 * @return the original slide info offset
	 */
	public long getSlideInfoOffset() {
		return slideInfoOffset;
	}

	public abstract void fixPageChains(Program program, DyldCacheHeader dyldCacheHeader,
			boolean addRelocations, MessageLog log, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException;

	protected void addRelocationTableEntry(Program program, Address chainLoc, int type,
			long chainValue, int appliedByteLength, String name) {
		// Add entry to relocation table for the pointer fixup
		program.getRelocationTable()
				.add(chainLoc, Status.APPLIED, type, new long[] { chainValue }, appliedByteLength,
					name);
	}

	/**
	 * Create pointers at each fixed chain location.
	 * 
	 * @param program The program
	 * @param unchainedLocList Address list of fixed pointer locations
	 * @param monitor A cancelable task monitor 
	 * 
	 * @throws CancelledException if the user cancels
	 */
	protected void createChainPointers(Program program, List<Address> unchainedLocList,
			TaskMonitor monitor) throws CancelledException {
		int numFixedLocations = unchainedLocList.size();

		monitor.setMessage("Fixed " + numFixedLocations + " chained pointers.  Creating Pointers");

		// Create pointers at any fixed-up addresses
		for (Address addr : unchainedLocList) {
			monitor.checkCancelled();
			try {
				program.getListing().createData(addr, Pointer64DataType.dataType);
			}
			catch (CodeUnitInsertionException e) {
				// No worries, something presumably more important was there already
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info", 0);
		struct.add(DWORD, "version", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
