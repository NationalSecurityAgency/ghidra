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
import java.util.List;
import java.util.TreeSet;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a DYLD Cache {@link Program} by parsing the DYLD Cache headers.
 */
public class DyldCacheProgramBuilder extends MachoProgramBuilder {

	private boolean shouldProcessSymbols;

	/**
	 * Creates a new {@link DyldCacheProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up
	 * @param provider The {@link ByteProvider} that contains the DYLD Cache bytes
	 * @param fileBytes Where the DYLD Cache's bytes came from
	 * @param shouldProcessSymbols True if symbols should be processed; otherwise, false
	 * @param shouldAddChainedFixupsRelocations True if relocations should be added for chained 
	 *   fixups; otherwise, false
	 *   imported and combined into 1 program; otherwise, false
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 */
	protected DyldCacheProgramBuilder(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldProcessSymbols, boolean shouldAddChainedFixupsRelocations, MessageLog log,
			TaskMonitor monitor) {
		super(program, provider, fileBytes, shouldAddChainedFixupsRelocations, log, monitor);
		this.shouldProcessSymbols = shouldProcessSymbols;
	}

	/**
	 * Builds up a DYLD Cache {@link Program}.
	 * 
	 * @param program The {@link Program} to build up
	 * @param provider The {@link ByteProvider} that contains the DYLD Cache's bytes
	 * @param fileBytes Where the Mach-O's bytes came from
	 * @param shouldProcessSymbols True if symbols should be processed; otherwise, false
	 * @param shouldAddChainedFixupsRelocations True if relocations should be added for chained 
	 *   fixups; otherwise, false
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @throws Exception if a problem occurs
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldProcessSymbols, boolean shouldAddChainedFixupsRelocations, MessageLog log,
			TaskMonitor monitor) throws Exception {
		DyldCacheProgramBuilder dyldCacheProgramBuilder = new DyldCacheProgramBuilder(program,
			provider, fileBytes, shouldProcessSymbols, shouldAddChainedFixupsRelocations, log,
			monitor);
		dyldCacheProgramBuilder.build();
	}

	@Override
	protected void build() throws Exception {

		try (SplitDyldCache splitDyldCache =
			new SplitDyldCache(provider, shouldProcessSymbols, log, monitor)) {

			// Set image base
			setDyldCacheImageBase(splitDyldCache.getDyldCacheHeader(0));

			// Setup memory
			// Check if local symbols are present
			boolean localSymbolsPresent = false;
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
				ByteProvider bp = splitDyldCache.getProvider(i);
				String name = splitDyldCache.getName(i);

				processDyldCacheMemoryBlocks(header, name, bp);
				
				if (header.getLocalSymbolsInfo() != null) {
					localSymbolsPresent = true;
				}
			}

			// Perform additional DYLD processing
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
				ByteProvider bp = splitDyldCache.getProvider(i);

				fixPageChains(header);
				markupHeaders(header);
				markupBranchIslands(header, bp);
				createLocalSymbols(header);
				processDylibs(splitDyldCache, header, bp, localSymbolsPresent);
			}
		}
	}

	/**
	 * Sets the program's image base.
	 * 
	 * @param dyldCacheHeader The "base" DYLD Cache header
	 * @throws Exception if there was problem setting the program's image base
	 */
	private void setDyldCacheImageBase(DyldCacheHeader dyldCacheHeader) throws Exception {
		monitor.setMessage("Setting image base...");
		monitor.initialize(1);
		program.setImageBase(space.getAddress(dyldCacheHeader.getBaseAddress()), true);
		monitor.incrementProgress(1);
	}

	/**
	 * Processes the DYLD Cache's memory mappings and creates memory blocks for them.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @param name The name of the DYLD Cache
	 * @param bp The corresponding {@link ByteProvider}
	 * @throws Exception if there was a problem creating the memory blocks
	 */
	private void processDyldCacheMemoryBlocks(DyldCacheHeader dyldCacheHeader, String name,
			ByteProvider bp) throws Exception {
		List<DyldCacheMappingInfo> mappingInfos = dyldCacheHeader.getMappingInfos();
		monitor.setMessage("Processing DYLD mapped memory blocks...");
		monitor.initialize(mappingInfos.size());
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, bp, monitor);
		long endOfMappedOffset = 0;
		boolean bookmarkSet = false;
		for (DyldCacheMappingInfo mappingInfo : mappingInfos) {
			long offset = mappingInfo.getFileOffset();
			long size = mappingInfo.getSize();
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, "DYLD",
				space.getAddress(mappingInfo.getAddress()), fb, offset, size, "", "",
				mappingInfo.isRead(), mappingInfo.isWrite(), mappingInfo.isExecute(), log);

			if (offset + size > endOfMappedOffset) {
				endOfMappedOffset = offset + size;
			}

			if (!bookmarkSet) {
				program.getBookmarkManager()
						.setBookmark(block.getStart(), BookmarkType.INFO, "Dyld Cache Header",
							name + " - " + dyldCacheHeader.getUUID());
				bookmarkSet = true;
			}

			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}

		if (endOfMappedOffset < bp.length()) {
			monitor.setMessage("Processing DYLD unmapped memory block...");
			MemoryBlock fileBlock = MemoryBlockUtils.createInitializedBlock(program, true, "FILE",
				AddressSpace.OTHER_SPACE.getAddress(endOfMappedOffset), fb, endOfMappedOffset,
				bp.length() - endOfMappedOffset, "Useful bytes that don't get mapped into memory",
				"", false, false, false, log);
			dyldCacheHeader.setFileBlock(fileBlock);
		}
	}

	/**
	 * Marks up the DYLD Cache headers.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @throws Exception if there was a problem marking up the headers
	 */
	private void markupHeaders(DyldCacheHeader dyldCacheHeader) throws Exception {
		monitor.setMessage("Marking up DYLD headers...");
		monitor.initialize(1);
		dyldCacheHeader.parseFromMemory(program, space, log, monitor);
		dyldCacheHeader.markup(program, space, monitor, log);
		monitor.incrementProgress(1);
	}

	/**
	 * Marks up the DYLD Cache branch islands.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @param bp The corresponding {@link ByteProvider}
	 * @throws Exception if there was a problem marking up the branch islands.
	 */
	private void markupBranchIslands(DyldCacheHeader dyldCacheHeader, ByteProvider bp)
			throws Exception {
		monitor.setMessage("Marking up DYLD branch islands...");
		monitor.initialize(dyldCacheHeader.getBranchPoolAddresses().size());
		for (Long addr : dyldCacheHeader.getBranchPoolAddresses()) {
			try {
				MachHeader header = new MachHeader(bp, addr - dyldCacheHeader.getBaseAddress());
				header.parse();
				super.markupHeaders(header, space.getAddress(addr));
			}
			catch (MachException | IOException e) {
				// Not a show-stopper...carry on.
			}
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Create the DYLD Cache local symbols.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @throws Exception if there was a problem creating the local symbols
	 */
	private void createLocalSymbols(DyldCacheHeader dyldCacheHeader) throws Exception {
		if (!shouldProcessSymbols) {
			return;
		}
		DyldCacheLocalSymbolsInfo localSymbolsInfo = dyldCacheHeader.getLocalSymbolsInfo();
		if (localSymbolsInfo == null) {
			return;
		}
		monitor.setMessage("Creating DYLD local symbols...");
		monitor.initialize(localSymbolsInfo.getNList().size());
		for (NList nlist : localSymbolsInfo.getNList()) {
			if (nlist.getString().isBlank()) {
				continue;
			}
			try {
				program.getSymbolTable()
						.createLabel(space.getAddress(nlist.getValue()),
							SymbolUtilities.replaceInvalidChars(nlist.getString(), true),
							program.getGlobalNamespace(), SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendMsg(e.getMessage() + " " + nlist.getString());
			}
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Fixes any chained pointers within each of the data pages.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 * @throws CancelledException if user cancels
	 */
	private void fixPageChains(DyldCacheHeader dyldCacheHeader)
			throws MemoryAccessException, CancelledException {
		// locate slide Info
		List<DyldCacheSlideInfoCommon> slideInfos = dyldCacheHeader.getSlideInfos();
		for (DyldCacheSlideInfoCommon info : slideInfos) {
			int version = info.getVersion();

			log.appendMsg("Fixing page chains version: " + version);
			info.fixPageChains(program, dyldCacheHeader, shouldAddChainedFixupsRelocations, log,
				monitor);
		}
	}

	/**
	 * Processes the DYLD Cache's DYLIB files.  This will mark up the DYLIB files, added them to the
	 * program tree, and make memory blocks for them.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @param bp The corresponding {@link ByteProvider}
	 * @param localSymbolsPresent True if DYLD local symbols are present; otherwise, false
	 * @throws Exception if there was a problem processing the DYLIB files
	 */
	private void processDylibs(SplitDyldCache splitDyldCache, DyldCacheHeader dyldCacheHeader,
			ByteProvider bp, boolean localSymbolsPresent) throws Exception {
		// Create an "info" object for each DyldCache DYLIB, which will make processing them 
		// easier.  Save off the "libobjc" DYLIB for additional processing later.
		monitor.setMessage("Parsing DYLIB's...");
		DyldCacheMachoInfo libobjcInfo = null;
		TreeSet<DyldCacheMachoInfo> infoSet =
			new TreeSet<>((a, b) -> a.headerAddr.compareTo(b.headerAddr));
		List<DyldCacheImage> mappedImages = dyldCacheHeader.getMappedImages();
		monitor.initialize(mappedImages.size());
		for (DyldCacheImage mappedImage : mappedImages) {
			DyldCacheMachoInfo info = new DyldCacheMachoInfo(splitDyldCache, bp,
				mappedImage.getAddress() - dyldCacheHeader.getBaseAddress(),
				space.getAddress(mappedImage.getAddress()), mappedImage.getPath());
			infoSet.add(info);
			if (libobjcInfo == null && info.name.contains("libobjc.")) {
				libobjcInfo = info;
			}
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}
		
		// Create Exports
		monitor.setMessage("Creating DYLIB exports...");
		monitor.initialize(infoSet.size());
		boolean exportsCreated = false;
		for (DyldCacheMachoInfo info : infoSet) {
			info.createExports();
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}

		// Create DyldCache Mach-O symbols if local symbols are not present
		if (shouldProcessSymbols && !localSymbolsPresent) {
			monitor.setMessage("Creating DYLIB symbols...");
			monitor.initialize(infoSet.size());
			for (DyldCacheMachoInfo info : infoSet) {
				info.createSymbols(exportsCreated);
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}

		// Markup DyldCache Mach-O headers 
		monitor.setMessage("Marking up DYLIB headers...");
		monitor.initialize(infoSet.size());
		for (DyldCacheMachoInfo info : infoSet) {
			info.markupHeaders();
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}

		// Add DyldCache Mach-O's to program tree
		monitor.setMessage("Adding DYLIB's to program tree...");
		monitor.initialize(infoSet.size());
		for (DyldCacheMachoInfo info : infoSet) {
			info.addToProgramTree();
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}

		// Process DyldCache DYLIB memory blocks
		monitor.setMessage("Processing DYLIB memory blocks...");
		monitor.initialize(infoSet.size());
		for (DyldCacheMachoInfo info : infoSet) {
			info.processMemoryBlocks();
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}

		// Process and markup the libobjc DYLIB
		monitor.setMessage("Processing libobjc...");
		DyldCacheMachoInfo libObjcInfo =
			infoSet.stream().filter(e -> e.name.contains("libobjc.")).findAny().orElse(null);
		if (libObjcInfo != null) {
			LibObjcDylib libObjcDylib =
				new LibObjcDylib(libObjcInfo.header, program, space, log, monitor);
			libObjcDylib.markup();
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
		 * @param splitDyldCache The {@link SplitDyldCache}
		 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes
		 * @param offset The offset in the provider to the start of the Mach-O
		 * @param headerAddr The Mach-O's header address
		 * @param path The path of the Mach-O
		 * @throws Exception If there was a problem handling the Mach-O info
		 */
		public DyldCacheMachoInfo(SplitDyldCache splitDyldCache, ByteProvider provider, long offset, Address headerAddr, String path) throws Exception {
			this.headerAddr = headerAddr;
			this.header = new MachHeader(provider, offset, false);
			this.header.parse(splitDyldCache);
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
			DyldCacheProgramBuilder.this.processMemoryBlocks(header, name, true, false);
		}
		
		/**
		 * Creates exports for this Mach-O.
		 * 
		 * @return True if exports were created; otherwise, false
		 * @throws Exception If there was a problem creating exports for this Mach-O
		 */
		public boolean createExports() throws Exception {
			return DyldCacheProgramBuilder.this.processExports(header);
		}
		
		/**
		 * Creates symbols for this Mach-O (does not include exports).
		 * 
		 * @param processExports True if symbol table exports should be processed; otherwise, false
		 * @throws Exception If there was a problem creating symbols for this Mach-O
		 * @see DyldCacheProgramBuilder#processSymbolTables(MachHeader, boolean)
		 */
		public void createSymbols(boolean processExports) throws Exception {
			DyldCacheProgramBuilder.this.processSymbolTables(header, processExports);
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
		 * Adds an entry to the program tree for this Mach-O.  An entry consists of a 
		 * {@link ProgramModule module} named the path of this Mach-O in the DYLD Cache, and
		 * {@link ProgramFragment fragments} for each of this Mach-O's segments and sections.
		 * 
		 * @throws Exception If there was a problem adding this Mach-O to the program tree
		 */
		public void addToProgramTree() throws Exception {
			ProgramModule module;
			try {
				module = listing.getDefaultRootModule().createModule(path);
			}
			catch (DuplicateNameException e) {
				log.appendMsg("Failed to add duplicate module to program tree: " + path);
				return;
			}

			// Add the segments, because things like the header are not included in any section
			for (SegmentCommand segment : header.getAllSegments()) {
				if (segment.getVMsize() == 0) {
					continue;
				}
				if (segment.getSegmentName().equals(SegmentNames.SEG_LINKEDIT)) {
					continue; // __LINKEDIT segment is shared across all modules
				}
				Address segmentStart = space.getAddress(segment.getVMaddress());
				Address segmentEnd = segmentStart.add(segment.getVMsize() - 1);
				if (!memory.contains(segmentEnd)) {
					segmentEnd = memory.getBlock(segmentStart).getEnd();
				}
				ProgramFragment segmentFragment =
					module.createFragment(String.format("%s - %s", segment.getSegmentName(), path));
				segmentFragment.move(segmentStart, segmentEnd);

				// Add the sections, which will remove overlapped ranges from the segment fragment
				for (Section section : segment.getSections()) {
					if (section.getSize() == 0) {
						continue;
					}
					Address sectionStart = space.getAddress(section.getAddress());
					Address sectionEnd = sectionStart.add(section.getSize() - 1);
					if (!memory.contains(sectionEnd)) {
						sectionEnd = memory.getBlock(sectionStart).getEnd();
					}
					ProgramFragment sectionFragment =
						module.createFragment(String.format("%s %s - %s", section.getSegmentName(),
							section.getSectionName(), path));
					sectionFragment.move(sectionStart, sectionEnd);
				}

				// If the sections fully filled the segment, we can remove the now-empty segment
				if (segmentFragment.isEmpty()) {
					module.removeChild(segmentFragment.getName());
				}
			}
		}
	}
}
