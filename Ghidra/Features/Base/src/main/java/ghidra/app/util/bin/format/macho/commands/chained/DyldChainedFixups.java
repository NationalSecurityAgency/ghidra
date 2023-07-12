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
package ghidra.app.util.bin.format.macho.commands.chained;

import static ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.*;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.DyldChainedFixupsCommand;
import ghidra.app.util.bin.format.macho.commands.SegmentNames;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DyldChainedFixups {

	private MachHeader machoHeader;
	private Program program;
	private MessageLog log;
	private TaskMonitor monitor;
	private Memory memory;
	private AddressSpace space;

	/**
	 * Creates a new {@link DyldChainedFixups}
	 * 
	 * @param program The {@link Program}
	 * @param header The Mach-O header
	 * @param log The log
	 * @param monitor A cancelable task monitor.
	 */
	public DyldChainedFixups(Program program, MachHeader header, MessageLog log,
			TaskMonitor monitor) {
		this.program = program;
		this.machoHeader = header;
		this.log = log;
		this.monitor = monitor;
		this.memory = program.getMemory();
		this.space = program.getAddressFactory().getDefaultAddressSpace();
	}

	/**
	 * Fixes up any chained fixups.  Relies on the __thread_starts section being present.
	 * 
	 * @return A list of addresses where chained fixups were performed.
	 * @throws Exception if there was a problem reading/writing memory.
	 */
	public List<Address> processChainedFixups() throws Exception {
		monitor.setMessage("Fixing up chained pointers...");

		List<Address> fixedAddresses = new ArrayList<>();

		// First look for a DyldChainedFixupsCommand
		List<DyldChainedFixupsCommand> loadCommands =
			machoHeader.getLoadCommands(DyldChainedFixupsCommand.class);
		for (DyldChainedFixupsCommand loadCommand : loadCommands) {
			DyldChainedFixupHeader chainHeader = loadCommand.getChainHeader();
			DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();
			List<DyldChainedStartsInSegment> chainedStarts =
				chainedStartsInImage.getChainedStarts();
			for (DyldChainedStartsInSegment chainStart : chainedStarts) {
				fixedAddresses.addAll(processSegmentPointerChain(chainHeader, chainStart));
			}
			log.appendMsg("Fixed up " + fixedAddresses.size() + " chained pointers.");
		}
		if (!loadCommands.isEmpty()) {
			return fixedAddresses;
		}

		// Didn't find a DyldChainedFixupsCommand, so look for the sections with fixup info
		Section chainStartsSection =
			machoHeader.getSection(SegmentNames.SEG_TEXT, SectionNames.CHAIN_STARTS);
		Section threadStartsSection =
			machoHeader.getSection(SegmentNames.SEG_TEXT, SectionNames.THREAD_STARTS);

		if (chainStartsSection != null) {
			Address sectionStart = space.getAddress(chainStartsSection.getAddress());
			ByteProvider provider = new MemoryByteProvider(memory, sectionStart);
			BinaryReader reader = new BinaryReader(provider, machoHeader.isLittleEndian());
			DyldChainedStartsOffsets chainedStartsOffsets = new DyldChainedStartsOffsets(reader);
			for (int offset : chainedStartsOffsets.getChainStartOffsets()) {
				processPointerChain(null, fixedAddresses, chainedStartsOffsets.getPointerFormat(),
					program.getImageBase().add(offset).getOffset(), 0, 0);
			}
			log.appendMsg("Fixed up " + fixedAddresses.size() + " chained pointers.");
		}
		else if (threadStartsSection != null) {
			Address threadSectionStart = space.getAddress(threadStartsSection.getAddress());
			Address threadSectionEnd = threadSectionStart.add(threadStartsSection.getSize() - 1);
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
		}

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

		short[] pageStarts = chainStart.getPageStarts();

		short ptrFormatValue = chainStart.getPointerFormat();
		DyldChainType ptrFormat = DyldChainType.lookupChainPtr(ptrFormatValue);

		monitor.setMessage("Fixing " + ptrFormat.getName() + " chained pointers...");

		monitor.setMaximum(pageStartsCount);
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.checkCancelled();

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
	 * @param chainHeader fixup header chains (could be null)
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
		Address chainStart = space.getAddress(page);

		long next = -1;
		boolean start = true;
		while (next != 0) {
			monitor.checkCancelled();

			Address chainLoc = chainStart.add(nextOff);
			final long chainValue = DyldChainedPtr.getChainValue(memory, chainLoc, pointerFormat);
			long newChainValue = chainValue;

			boolean isAuthenticated = DyldChainedPtr.isAuthenticated(pointerFormat, chainValue);
			boolean isBound = DyldChainedPtr.isBound(pointerFormat, chainValue);

			if (isBound && chainHeader == null) {
				log.appendMsg(
					"Error: dyld_chained_fixups_header required to process bound chain fixup at " +
						chainLoc);
				return;
			}

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
				if (DyldChainedPtr.isRelative(pointerFormat)) {
					newChainValue += imageBaseOffset;
				}
			}

			if (!start || !program.getRelocationTable().hasRelocation(chainLoc)) {
				int byteLength = 0;
				Status status = Status.FAILURE;
				try {
					RelocationResult result =
						DyldChainedPtr.setChainValue(memory, chainLoc, pointerFormat,
							newChainValue);
					status = result.status();
					byteLength = result.byteLength();
				}
				finally {
					program.getRelocationTable()
							.add(chainLoc, status,
								(start ? 0x8000 : 0x4000) | (isAuthenticated ? 4 : 0) |
									(isBound ? 2 : 0) | 1,
								new long[] { newChainValue }, byteLength, symName);
				}
			}
			// delay creating data until after memory has been changed
			unchainedLocList.add(chainLoc);

			start = false;
			next = DyldChainedPtr.getNext(pointerFormat, chainValue);
			nextOff += next * DyldChainedPtr.getStride(pointerFormat);
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
		byte origBytes[] = new byte[8];
		memory.getBytes(pointerAddr, origBytes);

		boolean success = false;
		try {
			// Fixup the pointer
			memory.setLong(pointerAddr, fixedPointerValue);
			success = true;
		}
		finally {
			Status status = success ? Status.APPLIED : Status.FAILURE;
			program.getRelocationTable()
					.add(pointerAddr, status, (int) fixedPointerType,
						new long[] { fixedPointerValue },
						origBytes, null);
		}
	}
}
