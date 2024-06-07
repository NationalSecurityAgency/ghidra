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

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
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
	 * @param mappingAddress The base address of where the slide fixups will take place
	 * @param mappingSize The size of the slide fixups block
	 * @param mappingFileOffset The base file offset of where the slide fixups will take place
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @return The slide info object
	 */
	public static DyldCacheSlideInfoCommon parseSlideInfo(BinaryReader reader, long slideInfoOffset,
			long mappingAddress, long mappingSize, long mappingFileOffset, MessageLog log,
			TaskMonitor monitor) {
		if (slideInfoOffset == 0) {
			return null;
		}

		monitor.setMessage("Parsing DYLD slide info...");
		monitor.initialize(1);
		String errorMessage = "Failed to parse dyld_cache_slide_info";
		try {
			reader.setPointerIndex(slideInfoOffset);
			int version = reader.readInt(reader.getPointerIndex());
			errorMessage += version;
			DyldCacheSlideInfoCommon returnedSlideInfo = switch (version) {
				case 1 -> new DyldCacheSlideInfo1(reader, mappingAddress, mappingSize,
					mappingFileOffset);
				case 2 -> new DyldCacheSlideInfo2(reader, mappingAddress, mappingSize,
					mappingFileOffset);
				case 3 -> new DyldCacheSlideInfo3(reader, mappingAddress, mappingSize,
					mappingFileOffset);
				case 4 -> new DyldCacheSlideInfo4(reader, mappingAddress, mappingSize,
					mappingFileOffset);
				case 5 -> new DyldCacheSlideInfo5(reader, mappingAddress, mappingSize,
					mappingFileOffset);
				default -> throw new IOException(); // will be caught and version will be added to message
			};
			monitor.incrementProgress(1);
			returnedSlideInfo.slideInfoOffset = slideInfoOffset;
			return returnedSlideInfo;
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheSlideInfoCommon.class.getSimpleName(), errorMessage);
			return null;
		}
	}

	protected int version;
	protected long slideInfoOffset;
	protected long mappingAddress;
	protected long mappingSize;
	protected long mappingFileOffset;

	/**
	 * Create a new {@link DyldCacheSlideInfoCommon}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info
	 * @param mappingAddress The base address of where the slide fixups will take place
	 * @param mappingSize The size of the slide fixups block
	 * @param mappingFileOffset The base file offset of where the slide fixups will take place
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info
	 */
	public DyldCacheSlideInfoCommon(BinaryReader reader, long mappingAddress, long mappingSize,
			long mappingFileOffset) throws IOException {
		this.mappingAddress = mappingAddress;
		this.mappingSize = mappingSize;
		this.mappingFileOffset = mappingFileOffset;
		this.version = reader.readNextInt();
	}

	/**
	 * {@return The version of the DYLD slide info}
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * {@return The original slide info offset}
	 */
	public long getSlideInfoOffset() {
		return slideInfoOffset;
	}

	/**
	 * {@return The base address of where the slide fixups will take place}
	 */
	public long getMappingAddress() {
		return mappingAddress;
	}

	/**
	 * {@return The size of the slide fixups block}
	 */
	public long getMappingSize() {
		return mappingSize;
	}

	/**
	 * {@return The base file offset of where the slide fixups will take place}
	 */
	public long getMappingFileOffset() {
		return mappingFileOffset;
	}

	/**
	 * Walks the slide fixup information and collects a {@link List} of {@link DyldFixup}s that will
	 * need to be applied to the image
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the segment to fix up
	 * @param pointerSize The size of a pointer in bytes
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return A {@link List} of {@link DyldFixup}s
	 * @throws IOException If there was an IO-related issue
	 * @throws CancelledException If the user cancelled the operation
	 */
	public abstract List<DyldFixup> getSlideFixups(BinaryReader reader, int pointerSize,
			MessageLog log, TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Fixes up the program's slide pointers
	 * 
	 * @param program The {@link Program}
	 * @param markup True if the slide pointers should be marked up; otherwise, false
	 * @param addRelocations True if slide pointer locations should be added to the relocation
	 *   table; otherwise, false
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @throws MemoryAccessException If there was a problem accessing memory
	 * @throws CancelledException If the user cancelled the operation
	 */
	public void fixupSlidePointers(Program program, boolean markup, boolean addRelocations,
			MessageLog log, TaskMonitor monitor) throws MemoryAccessException, CancelledException {

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address dataPageAddr = space.getAddress(mappingAddress);

		try (ByteProvider provider = new MemoryByteProvider(memory, dataPageAddr)) {
			BinaryReader reader = new BinaryReader(provider, !memory.isBigEndian());
			
			List<DyldFixup> fixups =
				getSlideFixups(reader, program.getDefaultPointerSize(), log, monitor);

			monitor.initialize(fixups.size(), "Fixing DYLD Cache slide pointers...");
			for (DyldFixup fixup : fixups) {
				monitor.increment();
				Address addr = dataPageAddr.add(fixup.offset());
				if (fixup.size() == 8) {
					memory.setLong(addr, fixup.value());
				}
				else {
					memory.setInt(addr, (int) fixup.value());
				}
			}

			if (markup) {
				monitor.initialize(fixups.size(), "Marking up DYLD Cache slide pointers...");
				for (DyldFixup fixup : fixups) {
					monitor.increment();
					Address addr = dataPageAddr.add(fixup.offset());
					if (addRelocations) {
						program.getRelocationTable()
								.add(addr, Status.APPLIED, version, new long[] { fixup.value() },
									fixup.size(), null);
					}
					try {
						program.getListing().createData(addr, POINTER);
					}
					catch (CodeUnitInsertionException e) {
						// No worries, something presumably more important was there already
					}
				}
			}
		}
		catch (IOException e) {
			throw new MemoryAccessException(e.getMessage(), e);
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
