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

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.NList;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a DYLD Cache {@link Program} by parsing the DYLD Cache headers.
 */
public class DyldCacheProgramBuilder extends MachoProgramBuilder {

	private static final int DATA_PAGE_MAP_ENTRY = 1;
	private static final int BYTES_PER_CHAIN_OFFSET = 4;
	private static final int CHAIN_OFFSET_MASK = 0x3fff;
	private static final int DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000;
	private static final int DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA = 0x8000;

	protected DyldCacheHeader dyldCacheHeader;
	private boolean shouldProcessSymbols;
	private boolean shouldCreateDylibSections;
	private boolean shouldAddRelocationEntries;

	/**
	 * Creates a new {@link DyldCacheProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up
	 * @param provider The {@link ByteProvider} that contains the DYLD Cache bytes
	 * @param fileBytes Where the Mach-O's bytes came from
	 * @param shouldProcessSymbols True if symbols should be processed; otherwise, false
	 * @param shouldCreateDylibSections True if memory blocks should be created for DYLIB sections; 
	 *   otherwise, false
	 * @param shouldAddRelocationEntries True to create a relocation entry for each fixed up pointer in pointer chain
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 */
	protected DyldCacheProgramBuilder(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldProcessSymbols, boolean shouldCreateDylibSections,
			boolean shouldAddRelocationEntries, MessageLog log, TaskMonitor monitor) {
		super(program, provider, fileBytes, log, monitor);
		this.shouldProcessSymbols = shouldProcessSymbols;
		this.shouldCreateDylibSections = shouldCreateDylibSections;
		this.shouldAddRelocationEntries = shouldAddRelocationEntries;
	}

	/**
	 * Builds up a DYLD Cache {@link Program}.
	 * 
	 * @param program The {@link Program} to build up
	 * @param provider The {@link ByteProvider} that contains the DYLD Cache's bytes
	 * @param fileBytes Where the Mach-O's bytes came from
	 * @param shouldProcessSymbols True if symbols should be processed; otherwise, false
	 * @param shouldCreateDylibSections True if memory blocks should be created for DYLIB sections; 
	 *   otherwise, false
	 * @param addRelocationEntries True to create a relocation entry for each fixed up pointer in pointer chain
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @throws Exception if a problem occurs
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldProcessSymbols, boolean shouldCreateDylibSections,
			boolean addRelocationEntries, MessageLog log, TaskMonitor monitor) throws Exception {
		DyldCacheProgramBuilder dyldCacheProgramBuilder =
			new DyldCacheProgramBuilder(program, provider, fileBytes, shouldProcessSymbols,
				shouldCreateDylibSections, addRelocationEntries, log, monitor);
		dyldCacheProgramBuilder.build();
	}

	@Override
	protected void build() throws Exception {

		monitor.setMessage("Parsing DYLD Cache header ...");
		monitor.initialize(1);
		dyldCacheHeader = new DyldCacheHeader(new BinaryReader(provider, true));
		dyldCacheHeader.parseFromFile(shouldProcessSymbols, log, monitor);
		monitor.incrementProgress(1);

		setDyldCacheImageBase();
		processDyldCacheMemoryBlocks();
		fixPageChains();
		markupHeaders();
		markupBranchIslands();
		createSymbols();

		processDylibs();
	}

	/**
	 * Sets the program's image base.
	 * 
	 * @throws Exception if there was problem setting the program's image base
	 */
	private void setDyldCacheImageBase() throws Exception {
		monitor.setMessage("Setting image base...");
		monitor.initialize(1);
		program.setImageBase(space.getAddress(dyldCacheHeader.getBaseAddress()), true);
		monitor.incrementProgress(1);
	}

	/**
	 * Processes the DYLD Cache's memory mappings and creates memory blocks for them.
	 * 
	 * @throws Exception if there was a problem creating the memory blocks
	 */
	private void processDyldCacheMemoryBlocks() throws Exception {
		List<DyldCacheMappingInfo> mappingInfos = dyldCacheHeader.getMappingInfos();

		monitor.setMessage("Processing DYLD mapped memory blocks...");
		monitor.initialize(mappingInfos.size());
		long endOfMappedOffset = 0;
		for (DyldCacheMappingInfo mappingInfo : mappingInfos) {
			long offset = mappingInfo.getFileOffset();
			long size = mappingInfo.getSize();
			MemoryBlockUtils.createInitializedBlock(program, false, "DYLD",
				space.getAddress(mappingInfo.getAddress()), fileBytes, offset, size, "", "",
				mappingInfo.isRead(), mappingInfo.isWrite(), mappingInfo.isExecute(), log);
			if (offset + size > endOfMappedOffset) {
				endOfMappedOffset = offset + size;
			}
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}

		if (endOfMappedOffset < provider.length()) {
			monitor.setMessage("Processing DYLD unmapped memory block...");
			MemoryBlockUtils.createInitializedBlock(program, true, "FILE",
				AddressSpace.OTHER_SPACE.getAddress(endOfMappedOffset), fileBytes,
				endOfMappedOffset, provider.length() - endOfMappedOffset,
				"Useful bytes that don't get mapped into memory", "", false, false, false, log);
		}
	}

	/**
	 * Marks up the DYLD Cache headers.
	 * 
	 * @throws Exception if there was a problem marking up the headers
	 */
	private void markupHeaders() throws Exception {
		monitor.setMessage("Marking up DYLD headers...");
		monitor.initialize(1);
		dyldCacheHeader.parseFromMemory(program, space, log, monitor);
		dyldCacheHeader.markup(program, space, monitor, log);
		monitor.incrementProgress(1);
	}

	/**
	 * Marks up the DYLD Cache branch islands.
	 * 
	 * @throws Exception if there was a problem marking up the branch islands.
	 */
	private void markupBranchIslands() throws Exception {
		monitor.setMessage("Marking up DYLD branch islands...");
		monitor.initialize(dyldCacheHeader.getBranchPoolAddresses().size());
		for (Long addr : dyldCacheHeader.getBranchPoolAddresses()) {
			try {
				MachHeader header =
					MachHeader.createMachHeader(MessageLogContinuesFactory.create(log), provider,
						addr - dyldCacheHeader.getBaseAddress());
				header.parse();
				super.markupHeaders(header, space.getAddress(addr));
			}
			catch (MachException | IOException e) {
				// Not a show-stopper...carry on.
			}
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Creates the DYLD Cache symbols.
	 * 
	 * @throws Exception if there was a problem creating the symbols
	 */
	private void createSymbols() throws Exception {
		DyldCacheLocalSymbolsInfo localSymbolsInfo = dyldCacheHeader.getLocalSymbolsInfo();
		if (localSymbolsInfo != null) {
			monitor.setMessage("Processing DYLD symbols...");
			monitor.initialize(localSymbolsInfo.getNList().size());
			for (NList nlist : localSymbolsInfo.getNList()) {
				if (!nlist.getString().trim().isEmpty()) {
					try {
						program.getSymbolTable().createLabel(space.getAddress(nlist.getValue()),
							SymbolUtilities.replaceInvalidChars(nlist.getString(), true),
							program.getGlobalNamespace(), SourceType.IMPORTED);
					}
					catch (Exception e) {
						log.appendMsg(e.getMessage() + " " + nlist.getString());
					}
				}
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
	}

	/**
	 * Fixes any chained pointers within each of the data pages.
	 * 
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 * @throws CancelledException if user cancels
	 */
	private void fixPageChains() throws MemoryAccessException, CancelledException {
		long fixedAddressCount = 0;

		// locate slide Info
		DyldCacheSlideInfoCommon slideInfo = dyldCacheHeader.getSlideInfo();
		if (slideInfo == null || !(slideInfo instanceof DyldCacheSlideInfo2)) {
			log.appendMsg("No compatible slide info version");
			return;
		}
		DyldCacheSlideInfo2 slideInfo2 = (DyldCacheSlideInfo2) slideInfo;

		List<DyldCacheMappingInfo> mappingInfos = dyldCacheHeader.getMappingInfos();
		DyldCacheMappingInfo dyldCacheMappingInfo = mappingInfos.get(DATA_PAGE_MAP_ENTRY);
		long dataPageStart = dyldCacheMappingInfo.getAddress();
		long pageSize = slideInfo2.getPageSize();
		long pageStartsCount = slideInfo2.getPageStartsCount();

		long deltaMask = slideInfo2.getDeltaMask();
		long deltaShift = Long.numberOfTrailingZeros(deltaMask);
		long valueAdd = slideInfo2.getValueAdd();

		short[] pageEntries = slideInfo2.getPageStartsEntries();
		short[] extraEntries = slideInfo2.getPageExtrasEntries();

		monitor.setMessage("Fixing chained data page pointers...");

		monitor.setMaximum(pageStartsCount);
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.checkCanceled();

			long page = dataPageStart + (pageSize * index);

			monitor.setProgress(index);

			int pageEntry = pageEntries[index] & 0xffff;
			if (pageEntry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
				continue;
			}

			List<Address> unchainedLocList = new ArrayList<>(1024);

			if ((pageEntry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) != 0) {
				// go into extras and process list of chain entries for the same page
				int extraIndex = (pageEntry & CHAIN_OFFSET_MASK);
				do {
					pageEntry = extraEntries[extraIndex] & 0xffff;
					long pageOffset = (pageEntry & CHAIN_OFFSET_MASK) * BYTES_PER_CHAIN_OFFSET;

					processPointerChain(unchainedLocList, page, pageOffset, deltaMask, deltaShift,
						valueAdd);
					extraIndex++;
				}
				while ((pageEntry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0);
			}
			else {
				long pageOffset = pageEntry * BYTES_PER_CHAIN_OFFSET;

				processPointerChain(unchainedLocList, page, pageOffset, deltaMask, deltaShift,
					valueAdd);
			}

			fixedAddressCount += unchainedLocList.size();
			unchainedLocList.forEach(entry -> {
				// create a pointer at the fixed up chain pointer location
				try {
					// don't use data utilities. does too much extra checking work
					listing.createData(entry, Pointer64DataType.dataType);
				}
				catch (CodeUnitInsertionException e) {
					// No worries, something presumably more important was there already
				}
			});
		}

		log.appendMsg("Fixed " + fixedAddressCount + " chained pointers.  Creating Pointers");

		monitor.setMessage("Created " + fixedAddressCount + " chained pointers");
	}

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param unchainedLocList list of locations that were unchained
	 * @param page within data pages that has pointers to be unchained
	 * @param nextOff offset within the page that is the chain start
	 * @param deltaMask delta offset mask for each value
	 * @param deltaShift shift needed for the deltaMask to extract the next offset
	 * @param valueAdd value to be added to each chain pointer
	 * 
	 * @throws MemoryAccessException IO problem reading file
	 * @throws CancelledException user cancels
	 */
	private void processPointerChain(List<Address> unchainedLocList, long page, long nextOff,
			long deltaMask, long deltaShift, long valueAdd)
			throws MemoryAccessException, CancelledException {

		// TODO: should the image base be used to perform the ASLR slide on the pointers.
		//        currently image is kept at it's initial location with no ASLR.
		Address chainStart = memory.getProgram().getLanguage().getDefaultSpace().getAddress(page);

		byte origBytes[] = new byte[8];

		long valueMask = 0xffffffffffffffffL >>> (64 - deltaShift);

		long delta = -1;
		while (delta != 0) {
			monitor.checkCanceled();

			Address chainLoc = chainStart.add(nextOff);
			long chainValue = memory.getLong(chainLoc);

			delta = (chainValue & deltaMask) >> deltaShift;
			chainValue = chainValue & valueMask;
			if (chainValue != 0) {
				chainValue += valueAdd;
			}

			if (shouldAddRelocationEntries) {
				// Add entry to relocation table for the pointer fixup
				memory.getBytes(chainLoc, origBytes);
				program.getRelocationTable().add(chainLoc, 1, new long[] { chainValue }, origBytes,
					null);
			}

			memory.setLong(chainLoc, chainValue);

			// delay creating data until after memory has been changed
			unchainedLocList.add(chainLoc);

			nextOff += (delta * 4);
		}
	}

	/**
	 * Processes the DYLD Cache's DYLIB files.  This will mark up the DYLIB files, added them to the
	 * program tree, and make memory blocks for them.
	 * 
	 * @throws Exception if there was a problem processing the DYLIB files
	 */
	private void processDylibs() throws Exception {
		// Create an "info" object for each DyldCache DYLIB, which will make processing them 
		// easier
		monitor.setMessage("Parsing DYLIB's...");
		monitor.initialize(dyldCacheHeader.getImageInfos().size());
		TreeSet<DyldCacheMachoInfo> infoSet =
			new TreeSet<>((a, b) -> a.headerAddr.compareTo(b.headerAddr));
		for (DyldCacheImageInfo dyldCacheImageInfo : dyldCacheHeader.getImageInfos()) {
			infoSet.add(new DyldCacheMachoInfo(provider,
				dyldCacheImageInfo.getAddress() - dyldCacheHeader.getBaseAddress(),
				space.getAddress(dyldCacheImageInfo.getAddress()), dyldCacheImageInfo.getPath()));
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}

		// Markup DyldCache Mach-O headers 
		monitor.setMessage("Marking up DYLIB headers...");
		monitor.initialize(infoSet.size());
		for (DyldCacheMachoInfo info : infoSet) {
			info.markupHeaders();
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}

		// Add DyldCache Mach-O's to program tree
		monitor.setMessage("Adding DYLIB's to program tree...");
		monitor.initialize(infoSet.size());
		Iterator<DyldCacheMachoInfo> iter = infoSet.iterator();
		if (iter.hasNext()) {
			DyldCacheMachoInfo curr = iter.next();
			do {
				DyldCacheMachoInfo next = iter.hasNext() ? iter.next() : null;
				curr.addToProgramTree(next);
				curr = next;
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
			while (iter.hasNext());
		}

		// Process DyldCache DYLIB memory blocks.
		monitor.setMessage("Processing DYLIB memory blocks...");
		monitor.initialize(infoSet.size());
		for (DyldCacheMachoInfo info : infoSet) {
			info.processMemoryBlocks();
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Convenience class to store information we need about an individual Mach-O.
	 */
	private class DyldCacheMachoInfo {

		private Address headerAddr;
		private MachHeader header;
		private String path;
		private String name;

		/**
		 * Creates a new {@link DyldCacheMachoInfo} object with the given parameters.
		 * 
		 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes
		 * @param offset The offset in the provider to the start of the Mach-O
		 * @param headerAddr The Mach-O's header address
		 * @param path The path of the Mach-O
		 * @throws Exception If there was a problem handling the Mach-O info
		 */
		public DyldCacheMachoInfo(ByteProvider provider, long offset, Address headerAddr,
				String path) throws Exception {
			this.headerAddr = headerAddr;
			this.header = MachHeader.createMachHeader(MessageLogContinuesFactory.create(log),
				provider, offset, false);
			this.header.parse();
			this.path = path;
			this.name = new File(path).getName();
		}

		/**
		 * Processes memory blocks for this Mach-O.
		 * 
		 * @throws Exception If there was a problem processing memory blocks for this Mach-O
		 * @see DyldCacheProgramBuilder#processMemoryBlocks(MachHeader, String, boolean, boolean)
		 */
		public void processMemoryBlocks() throws Exception {
			DyldCacheProgramBuilder.this.processMemoryBlocks(header, name,
				shouldCreateDylibSections, false);
		}

		/**
		 * Marks up the Mach-O headers.
		 * 
		 * @throws Exception If there was a problem marking up the Mach-O's headers
		 * @see DyldCacheProgramBuilder#markupHeaders(MachHeader, Address)
		 */
		public void markupHeaders() throws Exception {
			DyldCacheProgramBuilder.this.markupHeaders(header, headerAddr);

			if (!name.isEmpty()) {
				listing.setComment(headerAddr, CodeUnit.PLATE_COMMENT, path);
			}
		}

		/**
		 * Adds an entry to the program tree for this Mach-O
		 * 
		 * @param next The Mach-O that comes directly after this one.  Could be null if this
		 *   is the last one.
		 * @throws Exception If there was a problem adding this Mach-O to the program tree
		 */
		public void addToProgramTree(DyldCacheMachoInfo next) throws Exception {
			ProgramFragment fragment = listing.getDefaultRootModule().createFragment(path);
			if (next != null) {
				fragment.move(headerAddr, next.headerAddr.subtract(1));
			}
			else {
				// This is the last Mach-O, so we'll assume it ends where the mapping that contains 
				// it ends.
				for (DyldCacheMappingInfo mappingInfo : dyldCacheHeader.getMappingInfos()) {
					Address mappingAddr = space.getAddress(mappingInfo.getAddress());
					if (headerAddr.compareTo(mappingAddr) >= 0 &&
						headerAddr.compareTo(mappingAddr.add(mappingInfo.getSize() - 1)) <= 0) {
						fragment.move(headerAddr, mappingAddr.add(mappingInfo.getSize() - 1));
					}
				}
			}
		}
	}
}
