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
import java.util.*;

import org.apache.commons.collections4.BidiMap;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.SegmentNames;
import ghidra.app.util.bin.format.macho.prelink.PrelinkMap;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a PRELINK Mach-O {@link Program} by parsing the Mach-O headers.
 */
public class MachoPrelinkProgramBuilder extends MachoProgramBuilder {

	private List<PrelinkMap> prelinkList;

	/**
	 * Creates a new {@link MachoPrelinkProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param prelinkList Parsed {@link PrelinkMap PRELINK} information.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 */
	protected MachoPrelinkProgramBuilder(Program program, ByteProvider provider,
			FileBytes fileBytes, List<PrelinkMap> prelinkList, MessageLog log,
			TaskMonitor monitor) {
		super(program, provider, fileBytes, log, monitor);
		this.prelinkList = prelinkList;
	}

	/**
	 * Builds up a PRELINK Mach-O {@link Program}.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param prelinkList Parsed {@link PrelinkMap PRELINK} information.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			List<PrelinkMap> prelinkList, MessageLog log, TaskMonitor monitor) throws Exception {
		MachoPrelinkProgramBuilder machoPrelinkProgramBuilder = new MachoPrelinkProgramBuilder(
			program, provider, fileBytes, prelinkList, log, monitor);
		machoPrelinkProgramBuilder.build();
	}

	@Override
	protected void build() throws Exception {

		// We want to handle the start of the Mach-O normally.  It represents the System.kext.
		super.build();
		
		// Fixup any chained pointers
		List<Address> fixedAddresses = fixupChainedPointers();

		// The rest of the Mach-O's live in the memory segments that the System.kext already 
		// defined. Therefore, we really just want to go through and do additional markup on them 
		// since they are already loaded in.
		List<Long> machoHeaderOffsets =
			MachoPrelinkUtils.findPrelinkMachoHeaderOffsets(provider, monitor);
		if (machoHeaderOffsets.isEmpty()) {
			return;
		}

		// Match PRELINK information to the Mach-O's we've found
		BidiMap<PrelinkMap, Long> map = MachoPrelinkUtils.matchPrelinkToMachoHeaderOffsets(provider,
			prelinkList, machoHeaderOffsets, monitor);

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
		List<PrelinkMachoInfo> prelinkMachoInfoList = new ArrayList<>();
		for (Long machoHeaderOffset : machoHeaderOffsets) {
			prelinkMachoInfoList.add(new PrelinkMachoInfo(provider, machoHeaderOffset,
				prelinkStartAddr.add(machoHeaderOffset - machoHeaderOffsets.get(0)),
				map.getKey(machoHeaderOffset)));
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

		// Create pointers at any fixed-up addresses
		fixedAddresses.forEach(addr -> {
			try {
				DataUtilities.createData(program, addr, Pointer64DataType.dataType, -1, false,
					DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				// No worries, something presumably more important was there already
			}
		});
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
	private List<Address> fixupChainedPointers() throws MemoryAccessException {

		Section threadStarts = machoHeader.getSection(SegmentNames.SEG_TEXT, "__thread_starts");
		if (threadStarts == null) {
			return Collections.emptyList();
		}

		monitor.setMessage("Fixing up chained pointers...");

		List<Address> fixedAddresses = new ArrayList<>();
		Address threadSectionStart = space.getAddress(threadStarts.getAddress());
		Address threadSectionEnd = threadSectionStart.add(threadStarts.getSize() - 1);

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
		program.getRelocationTable().add(pointerAddr, (int) fixedPointerType,
			new long[] { fixedPointerValue }, origBytes, null);

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
			this.headerAddr = headerAddr;
			this.header = MachHeader.createMachHeader(MessageLogContinuesFactory.create(log),
				provider, offset);
			this.header.parse();
			this.headerAddr = headerAddr;
			this.name = "";

			if (prelink != null) {
				String path = prelink.getPrelinkBundlePath();
				if (path != null) {
					this.name = new File(path).getName();
				}
			}
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
