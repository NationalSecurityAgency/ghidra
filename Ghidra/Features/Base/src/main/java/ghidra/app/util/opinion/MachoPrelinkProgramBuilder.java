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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.BidiMap;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.prelink.MachoPrelinkMap;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a PRELINK Mach-O {@link Program} by parsing the Mach-O headers.
 */
public class MachoPrelinkProgramBuilder extends MachoProgramBuilder {

	private List<Address> chainedFixups = new ArrayList<>();

	/**
	 * Creates a new {@link MachoPrelinkProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param shouldAddChainedFixupsRelocations True if relocations should be added for chained 
	 *   fixups; otherwise, false.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	protected MachoPrelinkProgramBuilder(Program program, ByteProvider provider,
			FileBytes fileBytes, boolean shouldAddChainedFixupsRelocations, MessageLog log,
			TaskMonitor monitor) throws Exception {
		super(program, provider, fileBytes, shouldAddChainedFixupsRelocations, log, monitor);
	}

	/**
	 * Builds up a PRELINK Mach-O {@link Program}.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param addChainedFixupsRelocations True if relocations should be added for chained fixups;
	 *   otherwise, false.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean addChainedFixupsRelocations, MessageLog log, TaskMonitor monitor)
			throws Exception {
		MachoPrelinkProgramBuilder machoPrelinkProgramBuilder = new MachoPrelinkProgramBuilder(
			program, provider, fileBytes, addChainedFixupsRelocations, log, monitor);
		machoPrelinkProgramBuilder.build();
	}

	@Override
	protected void build() throws Exception {

		// We want to handle the start of the Mach-O normally.  It represents the System.kext.
		super.build();

		// Now process the inner Mach-O's.  Newer formats use LC_FILESET_ENTRY.  Older formats
		// require scanning and XML parsing.
		List<MachoInfo> machoInfoList = processPrelinkFileSet();
		if (machoInfoList.isEmpty()) {
			machoInfoList = processPrelinkXml();
		}
		monitor.initialize(machoInfoList.size());
		for (MachoInfo info : machoInfoList) {
			info.processMemoryBlocks();
			info.markupHeaders();
			info.addToProgramTree();
			monitor.incrementProgress(1);
		}

		// Remove empty entries from Program Tree
		ProgramModule rootModule = listing.getDefaultRootModule();
		for (Group group : rootModule.getChildren()) {
			if (group instanceof ProgramFragment) {
				ProgramFragment fragment = (ProgramFragment) group;
				if (fragment.isEmpty()) {
					rootModule.removeChild(fragment.getName());
				}
			}
		}

		// Do things that needed to wait until after the inner Mach-O's are processed
		super.markupChainedFixups(chainedFixups);
	}

	/**
	 * Processes the LC_FILESET_ENTRY commands to generate a {@link List} of discovered Mach-O's
	 * 
	 * @return A {@link List} of discovered Mach-O's
	 * @throws Exception if a problem occurs
	 */
	private List<MachoInfo> processPrelinkFileSet() throws Exception {
		List<MachoInfo> machoInfoList = new ArrayList<>();
		for (FileSetEntryCommand cmd : machoHeader.getLoadCommands(FileSetEntryCommand.class)) {
			MachoInfo info = new MachoInfo(provider, cmd.getFileOffset(),
				space.getAddress(cmd.getVMaddress()), cmd.getFileSetEntryId().getString());
			machoInfoList.add(info);
		}
		return machoInfoList;
	}

	/**
	 * Processes the PRELINK XML to generate a {@link List} of discovered Mach-O's
	 * 
	 * @return A {@link List} of discovered Mach-O's
	 * @throws Exception if a problem occurs
	 */
	private List<MachoInfo> processPrelinkXml() throws Exception {
		List<MachoInfo> machoInfoList = new ArrayList<>();
		List<Long> machoHeaderOffsets =
			MachoPrelinkUtils.findPrelinkMachoHeaderOffsets(provider, monitor);
		if (machoHeaderOffsets.isEmpty()) {
			return machoInfoList;
		}

		List<MachoPrelinkMap> prelinkList = MachoPrelinkUtils.parsePrelinkXml(provider, monitor);

		// Match PRELINK information to the Mach-O's we've found
		BidiMap<MachoPrelinkMap, Long> map = MachoPrelinkUtils.matchPrelinkToMachoHeaderOffsets(
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
			String name = "";
			MachoPrelinkMap prelink = map.getKey(machoHeaderOffset);
			if (prelink != null) {
				String path = prelink.getPrelinkBundlePath();
				if (path != null) {
					name = new File(path).getName();
				}
			}
			machoInfoList.add(new MachoInfo(provider, machoHeaderOffset,
				prelinkStartAddr.add(machoHeaderOffset - machoHeaderOffsets.get(0)), name));
		}

		return machoInfoList;
	}

	@Override
	protected void renameObjMsgSendRtpSymbol()
			throws DuplicateNameException, InvalidInputException {
		// Do nothing.  This is not applicable for a PRELINK Mach-O.
	}

	@Override
	protected void markupChainedFixups(List<Address> fixups) throws CancelledException {
		// Just save the list.  
		// We need to delay doing the markup until after we process all the inner Mach-O's.
		this.chainedFixups = fixups;
	}

	/**
	 * Convenience class to store information we need about an individual inner Mach-O
	 */
	private class MachoInfo {

		private Address headerAddr;
		private MachHeader header;
		private String name;

		/**
		 * Creates a new {@link MachoInfo} object with the given parameters.
		 * 
		 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
		 * @param offset The offset in the provider to the start of the Mach-O.
		 * @param headerAddr The Mach-O's header address.
		 * @param name The Mach-O's name.
		 * @throws Exception If there was a problem handling the Mach-O or PRELINK info.
		 */
		public MachoInfo(ByteProvider provider, long offset, Address headerAddr,
				String name) throws Exception {
			this.headerAddr = headerAddr;
			this.header = new MachHeader(provider, offset, false);
			this.header.parse();
			this.headerAddr = headerAddr;
			this.name = name;
		}

		/**
		 * Processes memory blocks for this Mach-O.
		 * 
		 * @throws Exception If there was a problem processing memory blocks for this Mach-O.
		 * @see MachoPrelinkProgramBuilder#processMemoryBlocks(MachHeader, String, boolean, boolean)
		 */
		public void processMemoryBlocks() throws Exception {
			MachoPrelinkProgramBuilder.this.processMemoryBlocks(header, name, true, false);
		}

		/**
		 * Marks up the Mach-O headers.
		 * 
		 * @throws Exception If there was a problem marking up the Mach-O's headers.
		 * @see MachoPrelinkProgramBuilder#markupHeaders(MachHeader, Address)
		 */
		public void markupHeaders() throws Exception {
			MachoPrelinkProgramBuilder.this.markupHeaders(header, headerAddr);

			if (!name.isEmpty()) {
				listing.setComment(headerAddr, CodeUnit.PLATE_COMMENT, name);
			}
		}

		/**
		 * Adds an entry to the program tree for this Mach-O.
		 * 
		 * @throws Exception If there was a problem adding this Mach-O to the program tree.
		 */
		public void addToProgramTree() throws Exception {
			if (name.isEmpty()) {
				return;
			}
			ProgramModule module;
			try {
				module = listing.getDefaultRootModule().createModule(name);
			}
			catch (DuplicateNameException e) {
				log.appendMsg("Failed to add duplicate module to program tree: " + name);
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
					module.createFragment(String.format("%s - %s", segment.getSegmentName(), name));
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
							section.getSectionName(), name));
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
