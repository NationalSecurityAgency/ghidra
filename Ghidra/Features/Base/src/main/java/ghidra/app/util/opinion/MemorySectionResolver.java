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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.program.database.register.AddressRangeObjectMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.datastruct.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class MemorySectionResolver {

	protected final Program program;

	private List<MemorySection> sections = new ArrayList<>(); // built-up prior to resolve
	private Map<String, Integer> sectionIndexMap = new HashMap<>();

	private Map<MemoryLoadable, List<AddressRange>> sectionMemoryMap; // created at time of resolve

	private int nextNonLoadedSectionInsertionIndex = 0;

	public MemorySectionResolver(Program program) {
		this.program = program;
	}

	/**
	 * Add initialized memory "section" based upon a specified data source fileOffset.
	 * The last "section" defined will take precedence when resolving conflicts. Sections identified 
	 * as loaded will take precedence over those that are non-loaded.
	 * placed into memory  
	 * @param key the loadable section key which corresponds to this memory "section"
	 * @param fileOffset data source file offset.  It is assumed that all initialized
	 * "sections" draw from a single data source.
	 * @param numberOfBytes number of bytes within "section" 
	 * @param startAddress desired physical start address of "section" (not overlay address)
	 * @param sectionName name of "section" 
	 * @param isReadable true if "section" has read privilege
	 * @param isWritable true if "section" has write privilege
	 * @param isExecutable true if "section" has execute privilege
	 * @param comment section comment (used as basis for block comment)
	 * @param isFragmentationOK if true this memory section may be fragmented due to 
	 * @param isLoadedSection if true this memory section will take precedence over non-loaded sections
	 * conflict/overlap with other memory sections of higher precedence.
	 * @throws AddressOverflowException
	 */
	public void addInitializedMemorySection(MemoryLoadable key, long fileOffset, long numberOfBytes,
			Address startAddress, String sectionName, boolean isReadable, boolean isWritable,
			boolean isExecutable, String comment, boolean isFragmentationOK,
			boolean isLoadedSection) throws AddressOverflowException {
		if (sectionMemoryMap != null) {
			throw new IllegalStateException("already resolved");
		}
		sectionName = getUniqueSectionName(sectionName);
		MemorySection memorySection = new MemorySection(key, true, fileOffset, numberOfBytes,
			makeRange(startAddress, numberOfBytes), sectionName, isReadable, isWritable,
			isExecutable, comment, isFragmentationOK);
		if (isLoadedSection) {
			sections.add(memorySection);
		}
		else {
			// ensure that non-loaded sections are processed after loaded sections
			// by inserting them before the loaded sections 
			sections.add(nextNonLoadedSectionInsertionIndex++, memorySection);
		}
	}

	/**
	 * Add uninitialized memory "section".
	 * The last "section" defined will take precedence when resolving conflicts.  
	 * @param key the loadable section key which corresponds to this memory "section"
	 * @param numberOfBytes number of bytes within "section" 
	 * @param startAddress desired physical start address of "section" (not overlay address)
	 * @param sectionName name of "section" 
	 * @param isReadable true if "section" has read privilege
	 * @param isWritable true if "section" has write privilege
	 * @param isExecutable true if "section" has execute privilege
	 * @param comment section comment (used as basis for block comment)
	 * @param isFragmentationOK if true this memory section may be fragmented due to 
	 * conflict/overlap with other memory sections of higher precedence.
	 * @throws AddressOverflowException
	 */
	public void addUninitializedMemorySection(MemoryLoadable key, long numberOfBytes,
			Address startAddress, String sectionName, boolean isReadable, boolean isWritable,
			boolean isExecutable, String comment, boolean isFragmentationOK)
			throws AddressOverflowException {
		if (sectionMemoryMap != null) {
			throw new IllegalStateException("already resolved");
		}
		sectionName = getUniqueSectionName(sectionName);
		sections.add(
			new MemorySection(key, false, -1, numberOfBytes, makeRange(startAddress, numberOfBytes),
				sectionName, isReadable, isWritable, isExecutable, comment, isFragmentationOK));
	}

	private String getUniqueSectionName(String baseName) {
		if (baseName != null) {
			baseName = baseName.trim();
			if (baseName.length() == 0) {
				baseName = "NO-NAME";
			}
		}
		else {
			baseName = "NO-NAME";
		}
		Memory mem = program.getMemory();
		String name = baseName;
		int index = 0;
		while (mem.getBlock(name) != null) {
			name = baseName + "-" + (++index);
		}
		return name;
	}

	private String getUniqueSectionChunkName(MemorySection section, Memory memory,
			int preferredIndex) {
		String sectionName = section.getSectionName();
		int index = preferredIndex;
		while (true) {
			String name = sectionName;
			if (index >= 0) {
				name += "." + index;
			}
			if (memory.getBlock(name) == null) {
				return name;
			}
			if (index <= 0) {
				index = 1;
			}
			else {
				index += 1;
			}
		}
	}

	private AddressRange makeRange(Address startAddress, long numberOfBytes)
			throws AddressOverflowException {
		Address endAddress = startAddress.addNoWrap(numberOfBytes - 1);
		return new AddressRangeImpl(startAddress, endAddress);
	}

	private class AllocatedFileSectionRange {

		final MemorySection section;
		final long rangeStartFileOffset;
		final long rangeSize; // size in file bytes
		final Address rangeStartAddress; // start of memory range (NOTE: may be overlay address)

		/**
		 * Construction file allocation range
		 * @param section memory section
		 * @param rangeStartFileOffset file byte offset for start of range 
		 * @param rangeSize length of range in bytes
		 * @param rangeStartAddress range memory address (NOTE: may be a memory overlay address)
		 */
		AllocatedFileSectionRange(MemorySection section, long rangeStartFileOffset, long rangeSize,
				Address rangeStartAddress) {
			this.section = section;
			this.rangeStartFileOffset = rangeStartFileOffset;
			this.rangeSize = rangeSize;
			this.rangeStartAddress = rangeStartAddress;
		}

		@Override
		public String toString() {
			return String.format("%s (%d, %d @ %s)", section.getSectionName(), rangeStartFileOffset,
				rangeSize, rangeStartAddress);
		}
	}

	/**
	 * Get the address set as a list of ranges which correspond to a 
	 * loaded section.  The key object corresponds to the key object 
	 * provided when the section was added.
	 * @param key section key object
	 * @return list of resolved address ranges or null if not found
	 */
	List<AddressRange> getResolvedLoadAddresses(MemoryLoadable key) {
		List<AddressRange> list = sectionMemoryMap.get(key);
		return list != null ? Collections.unmodifiableList(list) : null;
	}

	/**
	 * Indicates range supplied by another section (same file region mapping)
	 */
	private class ProxyAddressRange extends AddressRangeImpl {
		ProxyAddressRange(Address min, Address max) {
			super(min, max);
		}
	}

	/**
	 * Indicates range must be converted to a named overlay 
	 */
	private class OverlayAddressRange extends AddressRangeImpl {
		OverlayAddressRange(Address min, Address max) {
			super(min, max);
		}
	}

	private Map<AddressSpace, ObjectRangeMap<AllocatedFileSectionRange>> fileLoadMaps;

	private ObjectRangeMap<AllocatedFileSectionRange> getFileLoadRangeMap(AddressSpace space,
			boolean create) {
		if (fileLoadMaps == null) {
			if (!create) {
				return null;
			}
			fileLoadMaps = new HashMap<>();
		}
		ObjectRangeMap<AllocatedFileSectionRange> map = fileLoadMaps.get(space);
		if (map == null && create) {
			map = new ObjectRangeMap<>();
			fileLoadMaps.put(space, map);
		}
		return map;
	}

	/**
	 * Perform final resolve of all defined memory "sections" to establish final memory mappings.
	 * This method will resolve all conflicts and create memory blocks within the associated program.
	 * @param monitor
	 * @throws CancelledException
	 */
	public void resolve(TaskMonitor monitor) throws CancelledException {

		if (sectionMemoryMap != null) {
			throw new IllegalStateException("already resolved");
		}

		if (!program.getMemory().isEmpty()) {
			throw new IllegalStateException("program memory blocks already exist - unsupported");
		}

		// Maintain file allocation map for resolving file section overlap (i.e., shared bytes)
		// AddressRange -> section loaded from file
		AddressRangeObjectMap<AllocatedFileSectionRange> fileAllocationMap =
			new AddressRangeObjectMap<>();

		// build-up mapping of sections to a sequence of memory ranges
		sectionMemoryMap = new HashMap<>();

		// process sections in reverse order - last-in takes precedence
		int sectionCount = sections.size();
		for (int index = sectionCount - 1; index >= 0; --index) {
			monitor.checkCanceled();
			resolveSectionMemory(sections.get(index), fileAllocationMap, monitor);
		}
	}

	/**
	 * Resolve the specified section and create the corresponding memory block(s).
	 * An entry will be added to the sectionMemoryMap to facilitate subsequent 
	 * MemoryLoadable memory assignment lookups, see {@link #getResolvedLoadAddresses(MemoryLoadable)}. 
	 * @param section section to be resolved
	 * @param fileAllocationMap memory mapping of file for those sections already processed.
	 * Any new file regions claimed by the specified section will be added to this map.
	 * @param monitor task monitor
	 * @throws CancelledException
	 */
	private void resolveSectionMemory(MemorySection section,
			AddressRangeObjectMap<AllocatedFileSectionRange> fileAllocationMap, TaskMonitor monitor)
			throws CancelledException {

		List<AddressRange> memoryAllocationList =
			allocateSectionMemory(section, fileAllocationMap, monitor);

		try {
			List<AddressRange> sectionMemoryRanges =
				processSectionRanges(section, memoryAllocationList, monitor);
			MemoryLoadable key = section.getKey();
			if (key != null) {
				sectionMemoryMap.put(key, sectionMemoryRanges);
			}
		}
		catch (AddressOverflowException | IOException e) {
			Msg.error(this, "Error while creating section " + section.getSectionName() +
				section.getPhysicalAddressRange() + ": " + e.getMessage(), e);
		}
	}

	/**
	 * Complete creation of section memory block(s) based upon the provided
	 * memoryAllocationList.
	 * @param section section to be allocated and blocks created
	 * @param memoryAllocationList memory allocation list.
	 * Matching ranges allocated to other sections are identified using a ProxyAddressRange, 
	 * memory-mapped file range conflicts are identified using an OverlayAddressRange, while
	 * new file-mapped ranges are identified by an AddressRangeImpl.
	 * @param monitor
	 * @return memory address ranges corresponding to the specified section. Memory blocks
	 * will have been created for these ranges but may be shared by other sections.  
	 * @throws IOException
	 * @throws AddressOverflowException
	 * @throws CancelledException
	 */
	private List<AddressRange> processSectionRanges(MemorySection section,
			List<AddressRange> memoryAllocationList, TaskMonitor monitor)
			throws IOException, AddressOverflowException, CancelledException {

		long sectionByteOffset = 0;

		ObjectRangeMap<AllocatedFileSectionRange> fileLoadRangeMap = null;
		AddressSpace addressSpace = section.getPhysicalAddressSpace();
		if (addressSpace != AddressSpace.OTHER_SPACE) {
			fileLoadRangeMap = getFileLoadRangeMap(addressSpace, true);
		}

		List<AddressRange> modifiedRangeList = new ArrayList<>();

		Memory memory = program.getMemory();

		// NOTE: Allocated address ranges may refer to overlay memory address
		for (AddressRange allocatedAddrRange : memoryAllocationList) {

			monitor.checkCanceled();

			// Generate block name rangeIndex suffix if section sliced-up
			Integer rangeIndex = sectionIndexMap.get(section.sectionName);
			rangeIndex = (rangeIndex != null) ? (rangeIndex + 1) : 1;
			sectionIndexMap.put(section.sectionName, rangeIndex);
			if (rangeIndex == 1 && memoryAllocationList.size() == 1) {
				rangeIndex = -1; // prefer to omit index if only a single range
			}

			long rangeSize = allocatedAddrRange.getLength();

			if (allocatedAddrRange instanceof ProxyAddressRange) {
				modifiedRangeList.add(new AddressRangeImpl(allocatedAddrRange));
				sectionByteOffset += rangeSize;
				continue; // skip range
			}

			String blockName = getUniqueSectionChunkName(section, memory, rangeIndex);

			Address physicalStartAddr = section.getMinPhysicalAddress().add(sectionByteOffset);

			if (section.isInitialized) {
				MemoryBlock block;
				long fileOffset = section.fileOffset + sectionByteOffset;
				Address minAddr;
				Address maxAddr;
				if (allocatedAddrRange instanceof OverlayAddressRange) {
					String comment = section.getComment();
					if (section.isLoaded()) { // assume another section took priority
						MemoryBlock priorityBlock = memory.getBlock(physicalStartAddr);
						if (priorityBlock != null) {
							comment = comment + " - displaced by " + priorityBlock.getName();
						}
					}
					block = createInitializedBlock(section.key, true, blockName, physicalStartAddr,
						fileOffset, rangeSize, comment, section.isReadable(), section.isWritable(),
						section.isExecute(), monitor);
				}
				else {
					block = createInitializedBlock(section.key, false, blockName, physicalStartAddr,
						fileOffset, rangeSize, section.getComment(), section.isReadable(),
						section.isWritable(), section.isExecute(), monitor);
				}
				if (block != null) {
					minAddr = block.getStart();
					maxAddr = block.getEnd();
				}
				else {
					// block may be null due to unexpected conflict or pruning - allow to continue
					minAddr = physicalStartAddr;
					maxAddr = physicalStartAddr.addNoWrap(rangeSize - 1);
				}
				if (fileLoadRangeMap != null) {
					long chunkFileOffset = section.getFileOffset() + sectionByteOffset;
					AllocatedFileSectionRange allocatedFileRange =
						new AllocatedFileSectionRange(section, chunkFileOffset, rangeSize, minAddr);
					fileLoadRangeMap.setObject(chunkFileOffset, chunkFileOffset + rangeSize - 1,
						allocatedFileRange);
				}
				modifiedRangeList.add(new AddressRangeImpl(minAddr, maxAddr));
			}
			else {
				if (allocatedAddrRange instanceof OverlayAddressRange) {
					// skip
				}
				else {
					createUninitializedBlock(section.key, false, blockName, physicalStartAddr,
						rangeSize,
						section.getComment(), section.isReadable(), section.isWritable(),
						section.isExecute());
				}
				modifiedRangeList.add(new AddressRangeImpl(allocatedAddrRange));
			}
			sectionByteOffset += rangeSize;
		}
		return modifiedRangeList;
	}

	/**
	 * Determine loaded memory conflict set.  Use physical address of loaded overlay
	 * blocks to force reconciliation and avoid duplication.
	 * @param rangeMin minimum physical address of range
	 * @param rangeMax maximum physical address of range
	 * @return conflict memory set (physical address ranges only)
	 */
	private AddressSet getMemoryConflictSet(Address rangeMin, Address rangeMax) {

		// dedicated non-loaded overlay - don't bother with conflict check
		if (rangeMin.isNonLoadedMemoryAddress()) {
			return new AddressSet();
		}

		// Get base memory conflict set
		Memory memory = getMemory();
		AddressSet rangeSet = new AddressSet(rangeMin, rangeMax);
		AddressSet conflictSet = memory.intersect(rangeSet);

		// Add in loaded overlay conflicts (use their physical address)
		for (MemoryBlock block : memory.getBlocks()) {
			Address minAddr = block.getStart();
			Address maxAddr = block.getEnd();
			if (minAddr.isLoadedMemoryAddress() && minAddr.getAddressSpace().isOverlaySpace()) {
				AddressSet intersection = rangeSet.intersectRange(minAddr.getPhysicalAddress(),
					maxAddr.getPhysicalAddress());
				conflictSet.add(intersection);
			}
		}

		return conflictSet;
	}

	/**
	 * Allocate section to memory ranges based upon address-mapping of file offsets.
	 * The fileAllocationMap is used to map regions of the section to previously processed 
	 * sections or to identify new unclaimed address-mapped file regions.  Those ranges 
	 * which match memory-mapped file ranges are identified using a ProxyAddressRange, 
	 * memory-mapped file range conflicts are identified using an OverlayAddressRange, while
	 * new ranges will be identified by an AddressRangeImpl.
	 * @param section new section to be processed
	 * @param fileAllocationMap address to file region map
	 * @param monitor task monitor
	 * @return address range list section memory assignment
	 * @throws CancelledException
	 */
	private List<AddressRange> allocateSectionMemory(MemorySection section,
			AddressRangeObjectMap<AllocatedFileSectionRange> fileAllocationMap, TaskMonitor monitor)
			throws CancelledException {

		List<AddressRange> rangeList = new ArrayList<>();

		Address targetMinPhysicalAddr = section.getMinPhysicalAddress();
		Address targetMaxPhysicalAddr = section.getMaxPhysicalAddress();

		if (!section.isLoaded()) {
			// section should be assigned to named overlay in OTHER space
			if (section.getPhysicalAddressSpace() != AddressSpace.OTHER_SPACE) {
				throw new AssertException();
			}
			rangeList.add(new OverlayAddressRange(targetMinPhysicalAddr, targetMaxPhysicalAddr));
			return rangeList;
		}

		AddressSet physicalConflictAddrSet =
			getMemoryConflictSet(targetMinPhysicalAddr, targetMaxPhysicalAddr);
		boolean noConflict = physicalConflictAddrSet.isEmpty();
		if (noConflict || !section.isFragmentationOK) {
			if (noConflict) {
				// add normal non-conflicting section
				rangeList.add(section.getPhysicalAddressRange());
			}
			else {
				// if conflict and fragmentation not permitted bump section into overlay
				AddressRange physicalAddrRange = section.getPhysicalAddressRange();
				rangeList.add(
					new OverlayAddressRange(physicalAddrRange.getMinAddress(),
						physicalAddrRange.getMaxAddress()));
			}
			AllocatedFileSectionRange fileRange = new AllocatedFileSectionRange(section,
				section.getFileOffset(), section.length, targetMinPhysicalAddr);
			fileAllocationMap.setObject(targetMinPhysicalAddr, targetMaxPhysicalAddr, fileRange);
			return rangeList;
		}

		try {
			long fileOffset = section.getFileOffset(); // only used for initialized sections
			for (AddressRange physicalAddrRange : physicalConflictAddrSet.getAddressRanges()) {
				monitor.checkCanceled();

				Address physicalRangeMinAddr = physicalAddrRange.getMinAddress();
				Address physicalRangeMaxAddr = physicalAddrRange.getMaxAddress();

				// Handle chunk before range
				if (targetMinPhysicalAddr.compareTo(physicalRangeMinAddr) < 0) {
					// new range - no conflict
					fileOffset = addSectionRange(section, targetMinPhysicalAddr,
						physicalRangeMinAddr.subtract(1),
						fileOffset, rangeList);
					targetMinPhysicalAddr = physicalRangeMinAddr;
				}

				// Handle overlap/conflict region
				fileOffset = reconcileSectionRangeOverlap(section, physicalRangeMinAddr,
					physicalRangeMaxAddr, fileOffset,
					rangeList);
				targetMinPhysicalAddr = physicalRangeMaxAddr.addNoWrap(1); // could bump into end of space
			}

			// Handle residual chunk
			if (targetMinPhysicalAddr.compareTo(targetMaxPhysicalAddr) <= 0) {
				// new range - no conflict
				fileOffset = addSectionRange(section, targetMinPhysicalAddr, targetMaxPhysicalAddr,
					fileOffset, rangeList);
			}
		}
		catch (AddressOverflowException e) {
			// ignore - end of space
		}
		return rangeList;
	}

	/**
	 * Add a new non-conflicting section load memory range to the rangeList.
	 * @param section
	 * @param minAddr start of range
	 * @param maxAddr end of range
	 * @param fileOffset file offset at start of range
	 * @param rangeList rangeList accumulation list of sequentially allocated memory address ranges
	 * which makeup the specified loaded section.  This list will be added to for the new
	 * range.
	 * @return updated file offset if section is initialized.
	 */
	private long addSectionRange(MemorySection section, Address minAddr, Address maxAddr,
			long fileOffset, List<AddressRange> rangeList) {
		if (section.isInitialized) {
			fileOffset += maxAddr.subtract(minAddr) + 1;
		}
		rangeList.add(new AddressRangeImpl(minAddr, maxAddr));
		return fileOffset;
	}

	/**
	 * Reconcile section load range which has been determined to be in conflict with
	 * previously resolved section chunks.  Either OverlayAddressRange or 
	 * ProxyAddressRange objects will be added to rangeList to provide advice for
	 * subsequent memory block creation.
	 * @param section memory section to be loaded which resulted in conflict
	 * @param minPhysicalAddr start of conflict range physical address
	 * @param maxPhysicalAddr end of conflict range physical address
	 * @param fileOffset file offset at start of conflict range
	 * @param rangeList accumulation list of sequentially allocated memory address ranges
	 * which makeup the specified loaded section.  This list will be added to as the specified
	 * conflict range is reconciled.
	 * @return updated file offset if section is initialized.
	 */
	private long reconcileSectionRangeOverlap(MemorySection section, Address minPhysicalAddr,
			Address maxPhysicalAddr, long fileOffset, List<AddressRange> rangeList) {

		if (section.isInitialized) {

			ObjectRangeMap<AllocatedFileSectionRange> fileLoadRangeMap =
				getFileLoadRangeMap(minPhysicalAddr.getAddressSpace(), false);
			if (fileLoadRangeMap == null) {
				// unexpected unless memory already defined 
				rangeList.add(new OverlayAddressRange(minPhysicalAddr, maxPhysicalAddr));
				return fileOffset + maxPhysicalAddr.subtract(minPhysicalAddr) + 1;
			}

			long conflictRangeSize = maxPhysicalAddr.subtract(minPhysicalAddr) + 1;

			// conflict gap accumulator addresses
			Address conflictGapPhysicalAddrRangeStart = null;
			Address conflictGapPhysicalAddrRangeEnd = null;

			// NOTE: Range iterator does not fill-in the gaps, only those
			// ranges which match-up will be returned, range gaps correspond
			// to memory conflict. 
			IndexRangeIterator fileOffsetRangeIterator = fileLoadRangeMap.getIndexRangeIterator(
				fileOffset, fileOffset + conflictRangeSize - 1);

			long filePos = fileOffset;
			Address expectedPhysicalAddrRangeStart = minPhysicalAddr;

			while (fileOffsetRangeIterator.hasNext()) {

				if (expectedPhysicalAddrRangeStart == null) {
					throw new AssertException("expectedRangeStart is null");
				}

				// get file load range - which may have been loaded to a different memory area
				IndexRange fileOffsetRange = fileOffsetRangeIterator.next();
				long rangeSize = fileOffsetRange.getEnd() - fileOffsetRange.getStart() + 1;
				AllocatedFileSectionRange fileRange =
					fileLoadRangeMap.getObject(fileOffsetRange.getStart());

				if (fileOffsetRange.getStart() > filePos) {
					// File load gap in memory - conflict with uninitialized or pre-existing block.
					if (conflictGapPhysicalAddrRangeStart == null) {
						conflictGapPhysicalAddrRangeStart = expectedPhysicalAddrRangeStart;
					}
					expectedPhysicalAddrRangeStart =
						expectedPhysicalAddrRangeStart.add(fileOffsetRange.getStart() - filePos);
					conflictGapPhysicalAddrRangeEnd = expectedPhysicalAddrRangeStart.previous();
				}

				// Perform address computation in physical space
				Address physicalAddrRangeStart =
					fileRange.rangeStartAddress.getPhysicalAddress()
							.add(filePos - fileRange.rangeStartFileOffset);

				// Ignore use of overlay and compare physical address for match to avoid duplication
				if (!expectedPhysicalAddrRangeStart.equals(physicalAddrRangeStart)) {
					// File load memory range does not correspond to target memory range
					if (conflictGapPhysicalAddrRangeStart == null) {
						conflictGapPhysicalAddrRangeStart = expectedPhysicalAddrRangeStart;
					}
					conflictGapPhysicalAddrRangeEnd =
						expectedPhysicalAddrRangeStart.add(rangeSize - 1);
				}
				else {
					// File load range matches target
					if (conflictGapPhysicalAddrRangeStart != null) {
						// add accumulated conflict gap
						rangeList.add(new OverlayAddressRange(conflictGapPhysicalAddrRangeStart,
							conflictGapPhysicalAddrRangeEnd));
						conflictGapPhysicalAddrRangeStart = null;
						conflictGapPhysicalAddrRangeEnd = null;
					}
					rangeList.add(new ProxyAddressRange(expectedPhysicalAddrRangeStart,
						expectedPhysicalAddrRangeStart.add(rangeSize - 1)));
				}

				filePos = fileOffsetRange.getEnd() + 1;
				try {
					expectedPhysicalAddrRangeStart = minPhysicalAddr.add(filePos - fileOffset);
				}
				catch (AddressOutOfBoundsException e) {
					// catch case where we hit the end of the address space
					expectedPhysicalAddrRangeStart = null; // we should be done
				}
			}

			if ((filePos - fileOffset) != conflictRangeSize) {
				// Trailing file load gap in memory - conflict with uninitialized of pre-existing block
				if (conflictGapPhysicalAddrRangeStart == null) {
					conflictGapPhysicalAddrRangeStart = expectedPhysicalAddrRangeStart;
				}
				conflictGapPhysicalAddrRangeEnd = maxPhysicalAddr;
			}
			if (conflictGapPhysicalAddrRangeStart != null) {
				rangeList.add(new OverlayAddressRange(conflictGapPhysicalAddrRangeStart,
					conflictGapPhysicalAddrRangeEnd));
			}
			return fileOffset + conflictRangeSize;
		}

		// force proxy range condition for lower priority uninitialized section (unlikely condition)
		rangeList.add(new ProxyAddressRange(minPhysicalAddr, maxPhysicalAddr));
		return fileOffset;
	}

	/**
	 * Get program memory object
	 * @return program memory
	 */
	public Memory getMemory() {
		return program.getMemory();
	}

	/**
	 * Get program object
	 * @return program 
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Create a memory block (possible fragment if conflicts resolved) for the specified loadable "section". 
	 * If multiple blocks are created due to size restrictions only the first block will be returned.  The 
	 * returned block's length can be checked to determine if this has occurred.
	 * @param key the loadable section key which corresponds to this memory block or null for
	 * an adhoc block
	 * @param isOverlay true if an overlay should be created
	 * @param name unique name assignment based upon original "section" name
	 * @param start starting physical address of block
	 * @param fileOffset starting file offset for initialized data source
	 * @param length number of bytes in block
	 * @param comment block comment
	 * @param r true if "section" has read privilege
	 * @param w true if "section" has write privilege
	 * @param x true if "section" has execute privilege
	 * @return memory block 
	 * @throws IOException
	 * @throws AddressOverflowException
	 * @throws CancelledException
	 */
	protected abstract MemoryBlock createInitializedBlock(MemoryLoadable key, boolean isOverlay,
			String name, Address start, long fileOffset, long length, String comment, boolean r,
			boolean w, boolean x, TaskMonitor monitor)
			throws IOException, AddressOverflowException, CancelledException;

	/**
	 * Create a memory block (possible fragment if conflicts resolved) for the specified loadable "section". 
	 * If multiple blocks are created due to size restrictions only the first block will be returned.  The 
	 * returned block's length can be checked to determine if this has occurred.
	 * @param key the loadable section key which corresponds to this memory block or null for
	 * an adhoc block
	 * @param isOverlay true if an overlay should be created
	 * @param name unique name assignment based upon original "section" name
	 * @param start starting physical address of block
	 * @param length number of bytes in block
	 * @param comment block comment
	 * @param r true if "section" has read privilege
	 * @param w true if "section" has write privilege
	 * @param x true if "section" has execute privilege
	 * @return memory block 
	 * @throws IOException
	 * @throws AddressOverflowException
	 * @throws CancelledException
	 */
	protected abstract MemoryBlock createUninitializedBlock(MemoryLoadable key, boolean isOverlay,
			String name, Address start, long length, String comment, boolean r, boolean w,
			boolean x) throws IOException, AddressOverflowException, CancelledException;

}
