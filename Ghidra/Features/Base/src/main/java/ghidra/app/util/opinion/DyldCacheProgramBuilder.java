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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.NList;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
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
	private boolean shouldCreateDylibSections;
	private boolean shouldAddRelocationEntries;
	private boolean shouldCombineSplitFiles;

	/**
	 * Creates a new {@link DyldCacheProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up
	 * @param provider The {@link ByteProvider} that contains the DYLD Cache bytes
	 * @param fileBytes Where the DYLD Cache's bytes came from
	 * @param shouldProcessSymbols True if symbols should be processed; otherwise, false
	 * @param shouldCreateDylibSections True if memory blocks should be created for DYLIB sections; 
	 *   otherwise, false
	 * @param shouldAddRelocationEntries True to create a relocation entry for each fixed up pointer
	 *   in pointer chain
	 * @param shouldCombineSplitFiles True if split DYLD Cache files should be automatically 
	 *   imported and combined into 1 program; otherwise, false
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 */
	protected DyldCacheProgramBuilder(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldProcessSymbols, boolean shouldCreateDylibSections,
			boolean shouldAddRelocationEntries, boolean shouldCombineSplitFiles, MessageLog log,
			TaskMonitor monitor) {
		super(program, provider, fileBytes, log, monitor);
		this.shouldProcessSymbols = shouldProcessSymbols;
		this.shouldCreateDylibSections = shouldCreateDylibSections;
		this.shouldAddRelocationEntries = shouldAddRelocationEntries;
		this.shouldCombineSplitFiles = shouldCombineSplitFiles;
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
	 * @param addRelocationEntries True to create a relocation entry for each fixed up pointer in 
	 *   pointer chain; otherwise, false
	 * @param shouldCombineSplitFiles True if split DYLD Cache files should be automatically 
	 *   imported and combined into 1 program; otherwise, false
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @throws Exception if a problem occurs
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldProcessSymbols, boolean shouldCreateDylibSections,
			boolean addRelocationEntries, boolean shouldCombineSplitFiles, MessageLog log,
			TaskMonitor monitor) throws Exception {
		DyldCacheProgramBuilder dyldCacheProgramBuilder = new DyldCacheProgramBuilder(program,
			provider, fileBytes, shouldProcessSymbols, shouldCreateDylibSections,
			addRelocationEntries, shouldCombineSplitFiles, log, monitor);
		dyldCacheProgramBuilder.build();
	}

	@Override
	protected void build() throws Exception {

		try (SplitDyldCache splitDyldCache = new SplitDyldCache(provider, shouldProcessSymbols,
			shouldCombineSplitFiles, log, monitor)) {

			// Set image base
			setDyldCacheImageBase(splitDyldCache.getDyldCacheHeader(0));

			// Setup memory
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
				ByteProvider bp = splitDyldCache.getProvider(i);

				processDyldCacheMemoryBlocks(header, bp);
			}

			// Perform additional DYLD processing
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader header = splitDyldCache.getDyldCacheHeader(i);
				ByteProvider bp = splitDyldCache.getProvider(i);

				fixPageChains(header);
				markupHeaders(header);
				markupBranchIslands(header, bp);
				createSymbols(header);
				processDylibs(header, bp);
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
	 * @param bp The corresponding {@link ByteProvider}
	 * @throws Exception if there was a problem creating the memory blocks
	 */
	private void processDyldCacheMemoryBlocks(DyldCacheHeader dyldCacheHeader, ByteProvider bp)
			throws Exception {
		List<DyldCacheMappingInfo> mappingInfos = dyldCacheHeader.getMappingInfos();
		monitor.setMessage("Processing DYLD mapped memory blocks...");
		monitor.initialize(mappingInfos.size());
		FileBytes fb = MemoryBlockUtils.createFileBytes(program, bp, monitor);
		long endOfMappedOffset = 0;
		for (DyldCacheMappingInfo mappingInfo : mappingInfos) {
			long offset = mappingInfo.getFileOffset();
			long size = mappingInfo.getSize();
			MemoryBlockUtils.createInitializedBlock(program, false, "DYLD",
				space.getAddress(mappingInfo.getAddress()), fb, offset, size, "", "",
				mappingInfo.isRead(), mappingInfo.isWrite(), mappingInfo.isExecute(), log);

			if (offset + size > endOfMappedOffset) {
				endOfMappedOffset = offset + size;
			}
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}

		if (endOfMappedOffset < bp.length()) {
			monitor.setMessage("Processing DYLD unmapped memory block...");
			MemoryBlockUtils.createInitializedBlock(program, true, "FILE",
				AddressSpace.OTHER_SPACE.getAddress(endOfMappedOffset), fb, endOfMappedOffset,
				bp.length() - endOfMappedOffset, "Useful bytes that don't get mapped into memory",
				"", false, false, false, log);
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
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Creates the DYLD Cache symbols.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @throws Exception if there was a problem creating the symbols
	 */
	private void createSymbols(DyldCacheHeader dyldCacheHeader) throws Exception {
		DyldCacheLocalSymbolsInfo localSymbolsInfo = dyldCacheHeader.getLocalSymbolsInfo();
		if (localSymbolsInfo != null) {
			monitor.setMessage("Processing DYLD symbols...");
			monitor.initialize(localSymbolsInfo.getNList().size());
			for (NList nlist : localSymbolsInfo.getNList()) {
				if (!nlist.getString().trim().isEmpty()) {
					try {
						program.getSymbolTable()
								.createLabel(space.getAddress(nlist.getValue()),
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
			info.fixPageChains(program, dyldCacheHeader, shouldAddRelocationEntries, log, monitor);
		}
	}

	/**
	 * Processes the DYLD Cache's DYLIB files.  This will mark up the DYLIB files, added them to the
	 * program tree, and make memory blocks for them.
	 * 
	 * @param dyldCacheHeader The {@link DyldCacheHeader}
	 * @param bp The corresponding {@link ByteProvider}
	 * @throws Exception if there was a problem processing the DYLIB files
	 */
	private void processDylibs(DyldCacheHeader dyldCacheHeader, ByteProvider bp) throws Exception {
		// Create an "info" object for each DyldCache DYLIB, which will make processing them 
		// easier
		monitor.setMessage("Parsing DYLIB's...");
		TreeSet<DyldCacheMachoInfo> infoSet =
			new TreeSet<>((a, b) -> a.headerAddr.compareTo(b.headerAddr));
		List<DyldCacheImage> mappedImages = dyldCacheHeader.getMappedImages();
		monitor.initialize(mappedImages.size());
		for (DyldCacheImage mappedImage : mappedImages) {
			infoSet.add(new DyldCacheMachoInfo(bp,
				mappedImage.getAddress() - dyldCacheHeader.getBaseAddress(),
				space.getAddress(mappedImage.getAddress()), mappedImage.getPath()));
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
				try {
					curr.addToProgramTree(dyldCacheHeader, next);
				}
				catch (DuplicateNameException exc) {
					log.appendException(exc);
				}
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
			this.header = new MachHeader(provider, offset, false);
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
		 * @param dyldCacheHeader The DYLD Cache header
		 * @param next The Mach-O that comes directly after this one.  Could be null if this
		 *   is the last one.
		 * @throws Exception If there was a problem adding this Mach-O to the program tree
		 */
		public void addToProgramTree(DyldCacheHeader dyldCacheHeader, DyldCacheMachoInfo next)
				throws Exception {
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
