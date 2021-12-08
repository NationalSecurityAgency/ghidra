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

import static ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.*;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.apache.commons.collections4.BidiMap;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
import ghidra.app.util.bin.format.macho.prelink.PrelinkMap;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a PRELINK Mach-O {@link Program} by parsing the Mach-O headers.
 */
public class MachoPrelinkProgramBuilder extends MachoProgramBuilder {

	private List<PrelinkMap> prelinkList;

	private boolean shouldAddRelocationEntries;

	/**
	 * Creates a new {@link MachoPrelinkProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param prelinkList Parsed {@link PrelinkMap PRELINK} information.
	 * @param shouldAddRelocationEntries true if relocation records should be created
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 */
	protected MachoPrelinkProgramBuilder(Program program, ByteProvider provider,
			FileBytes fileBytes, List<PrelinkMap> prelinkList, boolean shouldAddRelocationEntries,
			MessageLog log, TaskMonitor monitor) {
		super(program, provider, fileBytes, log, monitor);
		this.prelinkList = prelinkList;
		this.shouldAddRelocationEntries = shouldAddRelocationEntries;
	}

	/**
	 * Builds up a PRELINK Mach-O {@link Program}.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param prelinkList Parsed {@link PrelinkMap PRELINK} information.
	 * @param addRelocationEntries  true if relocation records should be added
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			List<PrelinkMap> prelinkList, boolean addRelocationEntries, MessageLog log,
			TaskMonitor monitor) throws Exception {
		MachoPrelinkProgramBuilder machoPrelinkProgramBuilder = new MachoPrelinkProgramBuilder(
			program, provider, fileBytes, prelinkList, addRelocationEntries, log, monitor);
		machoPrelinkProgramBuilder.build();
	}

	@Override
	protected void build() throws Exception {

		// We want to handle the start of the Mach-O normally.  It represents the System.kext.
		super.build();

		// fixup any slide or headers before markup or regular relocation
		fixPreLinkAddresses();

		doRelocations();
	}

	@Override
	protected void doRelocations() throws Exception {
		processDyldInfo(false);
		markupHeaders(machoHeader, setupHeaderAddr(machoHeader.getAllSegments()));
		markupSections();
		processProgramVars();
		loadSectionRelocations();
		loadExternalRelocations();
		loadLocalRelocations();
	}

	protected void fixPreLinkAddresses() throws MemoryAccessException, CancelledException,
			Exception, IOException, MachException {
		// Fixup any chained pointers
		List<Address> fixedAddresses = fixupChainedPointers();

		processPreLinkMachoInfo();

		// Create pointers at any fixed-up addresses, that don't have header data created at them
		for (Address addr : fixedAddresses) {
			monitor.checkCanceled();
			try {
				program.getListing().createData(addr, Pointer64DataType.dataType);
			}
			catch (CodeUnitInsertionException e) {
				// No worries, something presumably more important was there already
			}
		}
	}

	protected void processPreLinkMachoInfo() throws Exception, IOException, MachException {
		List<PrelinkMachoInfo> prelinkMachoInfoList = new ArrayList<>();

		// if has fileSetEntryCommands, that tells where the prelinked headers are
		List<FileSetEntryCommand> fileSetEntries =
			machoHeader.getLoadCommands(FileSetEntryCommand.class);
		if (fileSetEntries != null && fileSetEntries.size() > 0) {
			for (FileSetEntryCommand fileSetEntryCommand : fileSetEntries) {
				prelinkMachoInfoList
						.add(new PrelinkMachoInfo(provider, fileSetEntryCommand.getFileOffset(),
							space.getAddress(fileSetEntryCommand.getVMaddress()),
							fileSetEntryCommand.getFileSetEntryName()));
			}
		}
		else {

			// The rest of the Mach-O's live in the memory segments that the System.kext already 
			// defined. Therefore, we really just want to go through and do additional markup on them 
			// since they are already loaded in.
			List<Long> machoHeaderOffsets =
				MachoPrelinkUtils.findPrelinkMachoHeaderOffsets(provider, monitor);
			if (machoHeaderOffsets.isEmpty()) {
				return;
			}

			// Match PRELINK information to the Mach-O's we've found
			BidiMap<PrelinkMap, Long> map = MachoPrelinkUtils.matchPrelinkToMachoHeaderOffsets(
				provider, prelinkList, machoHeaderOffsets, monitor);

			// Determine the starting address of the PRELINK Mach-O's
			long prelinkStart = MachoPrelinkUtils.getPrelinkStartAddr(machoHeader);
			Address prelinkStartAddr = null;
			if (prelinkStart == 0) {
				// Probably iOS 12, which doesn't define a proper __PRELINK_TEXT segment.
				// Assume the file offset is the same as the offset from image base.
				prelinkStartAddr = program.getImageBase().add(machoHeaderOffsets.get(0));
			}
			else {
				prelinkStartAddr = space.getAddress(prelinkStart);
			}

			// Create an "info" object for each PRELINK Mach-O, which will make processing them easier

			for (Long machoHeaderOffset : machoHeaderOffsets) {
				prelinkMachoInfoList.add(new PrelinkMachoInfo(provider, machoHeaderOffset,
					prelinkStartAddr.add(machoHeaderOffset - machoHeaderOffsets.get(0)),
					map.getKey(machoHeaderOffset)));
			}
		}

		// Process each PRELINK Mach-O
		monitor.initialize(prelinkMachoInfoList.size());
		for (int i = 0; i < prelinkMachoInfoList.size(); i++) {
			PrelinkMachoInfo info = prelinkMachoInfoList.get(i);
			PrelinkMachoInfo next = null;
			if (i < prelinkMachoInfoList.size() - 1) {
				next = prelinkMachoInfoList.get(i + 1);
			}

			info.processMemoryBlocks();
			info.markupHeaders();
			info.addToProgramTree(next);

			monitor.incrementProgress(1);
		}
	}

	@Override
	protected void renameObjMsgSendRtpSymbol()
			throws DuplicateNameException, InvalidInputException {
		// Do nothing.  This is not applicable for a PRELINK Mach-O.
	}

	/**
	 * Fixes up any chained pointers.  Relies on the __thread_starts section being present.
	 * 
	 * @return A list of addresses where pointer fixes were performed.
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 */
	private List<Address> fixupChainedPointers() throws MemoryAccessException, CancelledException {

		List<Address> fixedAddresses = new ArrayList<>();

		// if has Chained Fixups load command, use it
		List<DyldChainedFixupsCommand> loadCommands =
			machoHeader.getLoadCommands(DyldChainedFixupsCommand.class);
		for (LoadCommand loadCommand : loadCommands) {
			DyldChainedFixupsCommand linkCmd = (DyldChainedFixupsCommand) loadCommand;

			DyldChainedFixupHeader chainHeader = linkCmd.getChainHeader();

			DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();

			DyldChainedStartsInSegment[] chainedStarts = chainedStartsInImage.getChainedStarts();
			for (DyldChainedStartsInSegment chainStart : chainedStarts) {
				fixedAddresses.addAll(processSegmentPointerChain(chainHeader, chainStart));
			}
			log.appendMsg("Fixed up " + fixedAddresses.size() + " chained pointers.");
		}

		// if pointer chains fixed by DyldChainedFixupsCommands, then all finished
		if (loadCommands.size() > 0) {
			return fixedAddresses;
		}

		// if has thread_starts use to fixup chained pointers
		Section threadStarts = machoHeader.getSection(SegmentNames.SEG_TEXT, "__thread_starts");
		if (threadStarts == null) {
			return Collections.emptyList();
		}

		Address threadSectionStart = null;
		Address threadSectionEnd = null;
		threadSectionStart = space.getAddress(threadStarts.getAddress());
		threadSectionEnd = threadSectionStart.add(threadStarts.getSize() - 1);

		monitor.setMessage("Fixing up chained pointers...");

		long nextOffSize = (memory.getInt(threadSectionStart) & 1) * 4 + 4;
		Address chainHead = threadSectionStart.add(4);

		while (chainHead.compareTo(threadSectionEnd) < 0 && !monitor.isCancelled()) {
			int headStartOffset = memory.getInt(chainHead);
			if (headStartOffset == 0xFFFFFFFF || headStartOffset == 0) {
				break;
			}

			Address chainStart = program.getImageBase().add(headStartOffset & 0xffffffffL);
			fixedAddresses.addAll(processPointerChain(chainStart, nextOffSize));
			chainHead = chainHead.add(4);
		}

		log.appendMsg("Fixed up " + fixedAddresses.size() + " chained pointers.");
		return fixedAddresses;
	}

	private List<Address> processSegmentPointerChain(DyldChainedFixupHeader chainHeader,
			DyldChainedStartsInSegment chainStart)
			throws MemoryAccessException, CancelledException {

		List<Address> fixedAddresses = new ArrayList<Address>();
		long fixedAddressCount = 0;

		if (chainStart.getPointerFormat() == 0) {
			return fixedAddresses;
		}

		long dataPageStart = chainStart.getSegmentOffset();
		dataPageStart = dataPageStart + program.getImageBase().getOffset();
		long pageSize = chainStart.getPageSize();
		long pageStartsCount = chainStart.getPageCount();

		long authValueAdd = 0;

		short[] pageStarts = chainStart.getPage_starts();

		short ptrFormatValue = chainStart.getPointerFormat();
		DyldChainType ptrFormat = DyldChainType.lookupChainPtr(ptrFormatValue);

		monitor.setMessage("Fixing " + ptrFormat.getName() + " chained pointers...");

		monitor.setMaximum(pageStartsCount);
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.checkCanceled();

			long page = dataPageStart + (pageSize * index);

			monitor.setProgress(index);

			int pageEntry = pageStarts[index] & 0xffff;
			if (pageEntry == DYLD_CHAINED_PTR_START_NONE) {
				continue;
			}

			List<Address> unchainedLocList = new ArrayList<>(1024);

			long pageOffset = pageEntry; // first entry is byte based

			switch (ptrFormat) {
				case DYLD_CHAINED_PTR_ARM64E:
				case DYLD_CHAINED_PTR_ARM64E_KERNEL:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
					processPointerChain(chainHeader, unchainedLocList, ptrFormat, page, pageOffset,
						authValueAdd);
					break;

				// These might work, but have not been fully tested!
				case DYLD_CHAINED_PTR_64:
				case DYLD_CHAINED_PTR_64_OFFSET:
				case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				case DYLD_CHAINED_PTR_32:
				case DYLD_CHAINED_PTR_32_CACHE:
				case DYLD_CHAINED_PTR_32_FIRMWARE:
				case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
					processPointerChain(chainHeader, unchainedLocList, ptrFormat, page, pageOffset,
						authValueAdd);
					break;

				case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
				default:
					log.appendMsg(
						"WARNING: Pointer Chain format " + ptrFormat + " not processed yet!");
					break;
			}

			fixedAddressCount += unchainedLocList.size();

			fixedAddresses.addAll(unchainedLocList);
		}

		log.appendMsg(
			"Fixed " + fixedAddressCount + " " + ptrFormat.getName() + " chained pointers.");

		return fixedAddresses;
	}

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param chainHeader fixup header chains
	 * @param unchainedLocList list of locations that were unchained
	 * @param pointerFormat format of pointers within this chain
	 * @param page within data pages that has pointers to be unchained
	 * @param nextOff offset within the page that is the chain start
	 * @param auth_value_add value to be added to each chain pointer
	 * 
	 * @throws MemoryAccessException IO problem reading file
	 * @throws CancelledException user cancels
	 */
	private void processPointerChain(DyldChainedFixupHeader chainHeader,
			List<Address> unchainedLocList, DyldChainType pointerFormat, long page, long nextOff,
			long auth_value_add) throws MemoryAccessException, CancelledException {

		long imageBaseOffset = program.getImageBase().getOffset();
		Address chainStart = memory.getProgram().getLanguage().getDefaultSpace().getAddress(page);

		byte[] origBytes = new byte[8];

		long next = -1;
		boolean start = true;
		while (next != 0) {
			monitor.checkCanceled();

			Address chainLoc = chainStart.add(nextOff);
			final long chainValue = DyldChainedPtr.getChainValue(memory, chainLoc, pointerFormat);
			long newChainValue = chainValue;

			boolean isAuthenticated = DyldChainedPtr.isAuthenticated(pointerFormat, chainValue);
			boolean isBound = DyldChainedPtr.isBound(pointerFormat, chainValue);

			String symName = null;

			if (isAuthenticated && !isBound) {
				long offsetFromSharedCacheBase =
					DyldChainedPtr.getTarget(pointerFormat, chainValue);
				//long diversityData = DyldChainedPtr.getDiversity(pointerFormat, chainValue);
				//boolean hasAddressDiversity =
				//	DyldChainedPtr.hasAddrDiversity(pointerFormat, chainValue);
				//long key = DyldChainedPtr.getKey(pointerFormat, chainValue);
				newChainValue = imageBaseOffset + offsetFromSharedCacheBase + auth_value_add;
			}
			else if (!isAuthenticated && isBound) {
				int chainOrdinal = (int) DyldChainedPtr.getOrdinal(pointerFormat, chainValue);
				long addend = DyldChainedPtr.getAddend(pointerFormat, chainValue);
				DyldChainedImports chainedImports = chainHeader.getChainedImports();
				DyldChainedImport chainedImport = chainedImports.getChainedImport(chainOrdinal);
				//int libOrdinal = chainedImport.getLibOrdinal();
				symName = chainedImport.getName();
				// lookup the symbol, and then add addend
				List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(symName);
				if (globalSymbols.size() == 1) {
					newChainValue = globalSymbols.get(0).getAddress().getOffset();
				}
				newChainValue += addend;
			}
			else if (isAuthenticated && isBound) {
				int chainOrdinal = (int) DyldChainedPtr.getOrdinal(pointerFormat, chainValue);
				//long addend = DyldChainedPtr.getAddend(pointerFormat, chainValue);
				//long diversityData = DyldChainedPtr.getDiversity(pointerFormat, chainValue);
				//boolean hasAddressDiversity =
				//	DyldChainedPtr.hasAddrDiversity(pointerFormat, chainValue);
				//long key = DyldChainedPtr.getKey(pointerFormat, chainValue);

				DyldChainedImports chainedImports = chainHeader.getChainedImports();
				DyldChainedImport chainedImport = chainedImports.getChainedImport(chainOrdinal);
				symName = chainedImport.getName();

				// lookup the symbol, and then add addend
				List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(symName);
				if (globalSymbols.size() == 1) {
					newChainValue = globalSymbols.get(0).getAddress().getOffset();
				}
				newChainValue = newChainValue + auth_value_add;
			}
			else {
				newChainValue = DyldChainedPtr.getTarget(pointerFormat, chainValue);
				newChainValue += imageBaseOffset;
			}

			if (!start || program.getRelocationTable().getRelocation(chainLoc) == null) {
				addRelocationTableEntry(chainLoc,
					(start ? 0x8000 : 0x4000) | (isAuthenticated ? 4 : 0) | (isBound ? 2 : 0) | 1,
					newChainValue, origBytes, symName);
				DyldChainedPtr.setChainValue(memory, chainLoc, pointerFormat, newChainValue);
			}
			// delay creating data until after memory has been changed
			unchainedLocList.add(chainLoc);

			start = false;
			next = DyldChainedPtr.getNext(pointerFormat, chainValue);
			nextOff += next * DyldChainedPtr.getStride(pointerFormat);
		}
	}

	private void addRelocationTableEntry(Address chainLoc, int type, long chainValue,
			byte[] origBytes, String name) throws MemoryAccessException {
		if (shouldAddRelocationEntries) {
			// Add entry to relocation table for the pointer fixup
			memory.getBytes(chainLoc, origBytes);
			program.getRelocationTable()
					.add(chainLoc, type, new long[] { chainValue }, origBytes, name);
		}
	}

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param chainStart The starting of address of the pointer chain to fix.
	 * @param nextOffSize The size of the next offset.
	 * @return A list of addresses where pointer fixes were performed.
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 */
	private List<Address> processPointerChain(Address chainStart, long nextOffSize)
			throws MemoryAccessException {
		List<Address> fixedAddresses = new ArrayList<>();

		while (!monitor.isCancelled()) {
			long chainValue = memory.getLong(chainStart);

			fixupPointer(chainStart, chainValue);
			fixedAddresses.add(chainStart);

			long nextValueOff = ((chainValue >> 51L) & 0x7ffL) * nextOffSize;
			if (nextValueOff == 0) {
				break;
			}
			chainStart = chainStart.add(nextValueOff);
		}

		return fixedAddresses;
	}

	/**
	 * Fixes up the pointer at the given address.
	 * 
	 * @param pointerAddr The address of the pointer to fix.
	 * @param pointerValue The value at the address of the pointer to fix.
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 */
	private void fixupPointer(Address pointerAddr, long pointerValue) throws MemoryAccessException {

		final long BIT63 = (0x1L << 63);
		final long BIT62 = (0x1L << 62);

		// Bad chain value
		if ((pointerValue & BIT62) != 0) {
			// this is a pointer, but is good now
		}

		long fixedPointerValue = 0;
		long fixedPointerType = 0;

		// Pointer checked value
		if ((pointerValue & BIT63) != 0) {
			//long tagType = (pointerValue >> 49L) & 0x3L;
			long pacMod = ((pointerValue >> 32) & 0xffff);
			fixedPointerType = pacMod;
			fixedPointerValue = program.getImageBase().getOffset() + (pointerValue & 0xffffffffL);
		}
		else {
			fixedPointerValue =
				((pointerValue << 13) & 0xff00000000000000L) | (pointerValue & 0x7ffffffffffL);
			if ((pointerValue & 0x40000000000L) != 0) {
				fixedPointerValue |= 0xfffc0000000000L;
			}
		}

		// Add entry to relocation table for the pointer fixup
		byte[] origBytes = new byte[8];
		memory.getBytes(pointerAddr, origBytes);
		program.getRelocationTable()
				.add(pointerAddr, (int) fixedPointerType, new long[] { fixedPointerValue },
					origBytes, null);

		// Fixup the pointer
		memory.setLong(pointerAddr, fixedPointerValue);
	}

	/**
	 * Convenience class to store information we need about an individual PRELINK Mach-O.
	 */
	private class PrelinkMachoInfo {

		private Address headerAddr;
		private MachHeader header;
		private String name;

		/**
		 * Creates a new {@link PrelinkMachoInfo} object with the given parameters.
		 * 
		 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
		 * @param offset The offset in the provider to the start of the Mach-O.
		 * @param headerAddr The Mach-O's header address.
		 * @param prelink The {@link PrelinkMap PRELINK} information associated with the Mach-O.
		 * @throws Exception If there was a problem handling the Mach-O or PRELINK info.
		 */
		public PrelinkMachoInfo(ByteProvider provider, long offset, Address headerAddr,
				PrelinkMap prelink) throws Exception {
			this(provider, offset, headerAddr, "");

			if (prelink != null) {
				String path = prelink.getPrelinkBundlePath();
				if (path != null) {
					this.name = new File(path).getName();
				}
			}
		}

		public PrelinkMachoInfo(ByteProvider provider, long fileOffset, Address headerAddr,
				String kextName) throws Exception {
			this.headerAddr = headerAddr;
			this.header = MachHeader.createMachHeader(MessageLogContinuesFactory.create(log),
				provider, fileOffset, false);
			this.header.parse();
			this.headerAddr = headerAddr;
			this.name = kextName;
		}

		/**
		 * Processes memory blocks for this PRELINK Mach-O.
		 * 
		 * @throws Exception If there was a problem processing memory blocks for this PRELINK 
		 *   Mach-O.
		 * @see MachoPrelinkProgramBuilder#processMemoryBlocks(MachHeader, String, boolean, boolean)
		 */
		public void processMemoryBlocks() throws Exception {
			MachoPrelinkProgramBuilder.this.processMemoryBlocks(header, name, true, false);
		}

		/**
		 * Marks up the PRELINK Mach-O headers.
		 * 
		 * @throws Exception If there was a problem marking up the PRELINK Mach-O's headers.
		 * @see MachoPrelinkProgramBuilder#markupHeaders(MachHeader, Address)
		 */
		public void markupHeaders() throws Exception {
			MachoPrelinkProgramBuilder.this.markupHeaders(header, headerAddr);

			if (!name.isEmpty()) {
				listing.setComment(headerAddr, CodeUnit.PLATE_COMMENT, name);
			}
		}

		/**
		 * Adds an entry to the program tree for this PRELINK Mach-O.
		 * 
		 * @param next The PRELINK Mach-O that comes directly after this one.  Could be null if this
		 *   is the last one.
		 * @throws Exception If there was a problem adding this PRELINK Mach-O to the program tree.
		 */
		public void addToProgramTree(PrelinkMachoInfo next) throws Exception {
			if (!name.isEmpty()) {
				ProgramFragment fragment = listing.getDefaultRootModule().createFragment(name);
				if (next != null) {
					fragment.move(headerAddr, next.headerAddr.subtract(1));
				}
				else {
					// This is the last PRELINK Mach-O, so we'll assume it ends where the section
					// that contains it ends.
					for (Section section : machoHeader.getAllSections()) {
						Address sectionAddr = space.getAddress(section.getAddress());
						if (headerAddr.compareTo(sectionAddr) >= 0 &&
							headerAddr.compareTo(sectionAddr.add(section.getSize() - 1)) <= 0) {
							fragment.move(headerAddr, sectionAddr.add(section.getSize() - 1));
						}
					}
				}
			}
		}
	}
}
