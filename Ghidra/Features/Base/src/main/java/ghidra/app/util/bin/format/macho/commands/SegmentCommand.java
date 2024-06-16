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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a segment_command and segment_command_64 structure 
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

	public SegmentCommand(BinaryReader reader, boolean is32bit) throws IOException {
		super(reader);
		this.is32bit = is32bit;

		segname = reader.readNextAsciiString(MachConstants.NAME_LENGTH);
		if (is32bit) {
			vmaddr = reader.readNextUnsignedInt();
			vmsize = reader.readNextUnsignedInt();
			fileoff = reader.readNextUnsignedInt();
			filesize = reader.readNextUnsignedInt();
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
			sections.add(new Section(reader, is32bit));
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

	public void setSegmentName(String name) {
		this.segname = name;
	}

	public long getVMaddress() {
		// Mask off possible chained fixup found in kernelcache segment addresses
		if ((vmaddr & 0xfff000000000L) == 0xfff000000000L) {
			return vmaddr | 0xffff000000000000L;
		}
		return vmaddr;
	}

	public void setVMaddress(long vmaddr) {
		this.vmaddr = vmaddr;
	}

	public long getVMsize() {
		return vmsize;
	}

	public void setVMsize(long vmSize) {
		vmsize = vmSize;
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

	public void setFileSize(long fileSize) {
		filesize = fileSize;
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

	/**
	 * Returns true if the segment contains the given address
	 * 
	 * @param addr The address to check
	 * @return True if the segment contains the given address; otherwise, false
	 */
	public boolean contains(long addr) {
		return Long.compareUnsigned(addr, vmaddr) >= 0 &&
			Long.compareUnsigned(addr, vmaddr + vmsize) < 0;
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
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);
			Address addr = baseAddress.getNewAddress(getStartIndex());

			Address sectionAddress = addr.add(toDataType().getLength());
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
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}

	@Override
	public String toString() {
		return getSegmentName();
	}

	/**
	 * Creates a new segment command byte array
	 * 
	 * @param magic The magic
	 * @param name The name of the segment (must be less than or equal to 16 bytes)
	 * @param vmAddr The address of the start of the segment
	 * @param vmSize The size of the segment in memory
	 * @param fileOffset The file offset of the start of the segment
	 * @param fileSize The size of the segment on disk
	 * @param maxProt The maximum protections of the segment
	 * @param initProt The initial protection of the segment
	 * @param numSections The number of sections in the segment
	 * @param flags The segment flags
	 * @return The new segment in byte array form
	 * @throws MachException if an invalid magic value was passed in (see {@link MachConstants}), or
	 *   if the desired segment name exceeds 16 bytes
	 */
	public static byte[] create(int magic, String name, long vmAddr, long vmSize, long fileOffset,
			long fileSize, int maxProt, int initProt, int numSections, int flags)
			throws MachException {

		if (name.length() > 16) {
			throw new MachException("Segment name cannot exceed 16 bytes: " + name);
		}

		DataConverter conv = DataConverter.getInstance(magic == MachConstants.MH_MAGIC);
		boolean is64bit = magic == MachConstants.MH_CIGAM_64 || magic == MachConstants.MH_MAGIC_64;

		// Segment Command
		byte[] bytes = new byte[size(magic)];
		conv.putInt(bytes, 0x00,
			is64bit ? LoadCommandTypes.LC_SEGMENT_64 : LoadCommandTypes.LC_SEGMENT);
		conv.putInt(bytes, 0x04, bytes.length);
		byte[] nameBytes = name.getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(nameBytes, 0, bytes, 0x8, nameBytes.length);
		if (is64bit) {
			conv.putLong(bytes, 0x18, vmAddr);
			conv.putLong(bytes, 0x20, vmSize);
			conv.putLong(bytes, 0x28, fileOffset);
			conv.putLong(bytes, 0x30, fileSize);
			conv.putInt(bytes, 0x38, maxProt);
			conv.putInt(bytes, 0x3c, initProt);
			conv.putInt(bytes, 0x40, numSections);
			conv.putInt(bytes, 0x44, flags);
		}
		else {
			conv.putInt(bytes, 0x18, (int) vmAddr);
			conv.putInt(bytes, 0x1c, (int) vmSize);
			conv.putInt(bytes, 0x20, (int) fileOffset);
			conv.putInt(bytes, 0x24, (int) fileSize);
			conv.putInt(bytes, 0x28, maxProt);
			conv.putInt(bytes, 0x2c, initProt);
			conv.putInt(bytes, 0x30, numSections);
			conv.putInt(bytes, 0x34, flags);
		}

		return bytes;
	}

	/**
	 * Gets the size a segment command would be for the given magic
	 * 
	 * @param magic The magic
	 * @return The size in bytes a segment command would be for the given magic
	 * @throws MachException if an invalid magic value was passed in (see {@link MachConstants})
	 */
	public static int size(int magic) throws MachException {
		if (!MachConstants.isMagic(magic)) {
			throw new MachException("Invalid magic: 0x%x".formatted(magic));
		}
		boolean is64bit = magic == MachConstants.MH_CIGAM_64 || magic == MachConstants.MH_MAGIC_64;
		return is64bit ? 0x48 : 0x38;
	}
}
