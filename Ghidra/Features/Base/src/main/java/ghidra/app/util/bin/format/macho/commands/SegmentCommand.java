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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a segment_command and segment_command_64 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class SegmentCommand extends LoadCommand {

	private String segname;
	private long vmaddr;
	private long vmsize;
	private long fileoff;
	private long filesize;
	private int maxprot;
	private int initprot;
	private int nsects;
	private int flags;

	private boolean is32bit;
	private List<Section> sections = new ArrayList<Section>();

	public static SegmentCommand createSegmentCommand(FactoryBundledWithBinaryReader reader,
			boolean is32bit) throws IOException {
		SegmentCommand segmentCommand =
			(SegmentCommand) reader.getFactory().create(SegmentCommand.class);
		segmentCommand.initSegmentCommand(reader, is32bit);
		return segmentCommand;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public SegmentCommand() {
	}

	private void initSegmentCommand(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		initLoadCommand(reader);
		this.is32bit = is32bit;

		segname = reader.readNextAsciiString(MachConstants.NAME_LENGTH);
		if (is32bit) {
			vmaddr = reader.readNextInt() & 0xffffffffL;
			vmsize = reader.readNextInt() & 0xffffffffL;
			fileoff = reader.readNextInt() & 0xffffffffL;
			filesize = reader.readNextInt() & 0xffffffffL;
		}
		else {
			vmaddr = reader.readNextLong();
			vmsize = reader.readNextLong();
			fileoff = reader.readNextLong();
			filesize = reader.readNextLong();
		}
		maxprot = reader.readNextInt();
		initprot = reader.readNextInt();
		nsects = reader.readNextInt();
		flags = reader.readNextInt();

		for (int i = 0; i < nsects; ++i) {
			sections.add(Section.createSection(reader, is32bit));
		}
	}

	public List<Section> getSections() {
		return sections;
	}

	public Section getSectionContaining(Address address) {
		long offset = address.getOffset();
		for (Section section : sections) {
			long start = section.getAddress();
			long end = start + section.getSize();
			if (offset >= start && offset <= end) {
				return section;
			}
		}
		return null;
	}

	public Section getSectionByName(String sectionName) {
		for (Section section : sections) {
			if (section.getSectionName().equals(sectionName)) {
				return section;
			}
		}
		return null;
	}

	public String getSegmentName() {
		return segname;
	}

	public long getVMaddress() {
		return vmaddr;
	}

	public long getVMsize() {
		return vmsize;
	}

	public long getFileOffset() {
		return fileoff;
	}
	
	public void setFileOffset(long fileOffset) {
		fileoff = fileOffset;
	}

	public long getFileSize() {
		return filesize;
	}

	/**
	 * Returns a octal model value reflecting the
	 * segment's maximum protection value allowed.
	 * For example:{@code
	 * 7 -> 0x111 -> rwx
	 * 5 -> 0x101 -> rx}
	 * @return the maximum protections of a segment
	 */
	public int getMaxProtection() {
		return maxprot;
	}

	/**
	 * Returns a octal model value reflecting the
	 * segment's initial protection value.
	 * For example:{@code
	 * 7 -> 0x111 -> rwx
	 * 5 -> 0x101 -> rx}
	 * @return the initial protections of a segment
	 */
	public int getInitProtection() {
		return initprot;
	}

	/**
	 * Returns true if the initial protections include READ.
	 * @return true if the initial protections include READ
	 */
	public boolean isRead() {
		return (initprot & SegmentConstants.PROTECTION_R) != 0;
	}

	/**
	 * Returns true if the initial protections include WRITE.
	 * @return true if the initial protections include WRITE
	 */
	public boolean isWrite() {
		return (initprot & SegmentConstants.PROTECTION_W) != 0;
	}

	/**
	 * Returns true if the initial protections include EXECUTE.
	 * @return true if the initial protections include EXECUTE
	 */
	public boolean isExecute() {
		return (initprot & SegmentConstants.PROTECTION_X) != 0;
	}

	public int getNumberOfSections() {
		return nsects;
	}

	public int getFlags() {
		return flags;
	}

	public boolean isAppleProtected() {
		return (flags & SegmentConstants.FLAG_APPLE_PROTECTED) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(new StringDataType(), MachConstants.NAME_LENGTH, "segname", null);
		if (is32bit) {
			struct.add(DWORD, "vmaddr", null);
			struct.add(DWORD, "vmsize", null);
			struct.add(DWORD, "fileoff", null);
			struct.add(DWORD, "filesize", null);
		}
		else {
			struct.add(QWORD, "vmaddr", null);
			struct.add(QWORD, "vmsize", null);
			struct.add(QWORD, "fileoff", null);
			struct.add(QWORD, "filesize", null);
		}
		struct.add(DWORD, "maxprot", null);
		struct.add(DWORD, "initprot", null);
		struct.add(DWORD, "nsects", null);
		struct.add(DWORD, "flags", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "segment_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address addr = baseAddress.getNewAddress(getStartIndex());
				DataType segmentDT = toDataType();
				api.createData(addr, segmentDT);
				api.setPlateComment(addr, getSegmentName());

				Address sectionAddress = addr.add(segmentDT.getLength());
				for (Section section : sections) {
					if (monitor.isCancelled()) {
						return;
					}
					DataType sectionDT = section.toDataType();
					api.createData(sectionAddress, sectionDT);
					api.setPlateComment(sectionAddress, section.toString());
					sectionAddress = sectionAddress.add(sectionDT.getLength());

					if (section.getType() == SectionTypes.S_ZEROFILL) {
						continue;
					}
					if (header.getFileType() == MachHeaderFileTypes.MH_DYLIB_STUB) {
						continue;
					}

					Address sectionByteAddr = baseAddress.add(section.getOffset());
					if (section.getSize() > 0) {
						api.createLabel(sectionByteAddr, section.getSectionName(), true,
							SourceType.IMPORTED);
						api.createFragment(parentModule, "SECTION_BYTES", sectionByteAddr,
							section.getSize());
					}

					if (section.getRelocationOffset() > 0) {
						Address relocStartAddr = baseAddress.add(section.getRelocationOffset());
						long offset = 0;
						List<RelocationInfo> relocations = section.getRelocations();
						for (RelocationInfo reloc : relocations) {
							if (monitor.isCancelled()) {
								return;
							}
							DataType relocDT = reloc.toDataType();
							Address relocAddr = relocStartAddr.add(offset);
							api.createData(relocAddr, relocDT);
							api.setPlateComment(relocAddr, reloc.toString());
							offset += relocDT.getLength();
						}
						api.createFragment(parentModule, section.getSectionName() + "_Relocations",
							relocStartAddr, offset);
					}
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}

	@Override
	public String toString() {
		return getSegmentName();
	}
}
