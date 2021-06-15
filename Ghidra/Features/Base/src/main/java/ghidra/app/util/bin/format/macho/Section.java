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
package ghidra.app.util.bin.format.macho;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.commands.SegmentNames;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a section and section_64 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class Section implements StructConverter {

	private String sectname;
	private String segname;
	private long addr;
	private long size;
	private int offset;
	private int align;
	private int reloff;
	private int nrelocs;
	private int flags;
	private int reserved1;
	private int reserved2;
	private int reserved3;//only used for 64 bit

	private FactoryBundledWithBinaryReader reader;
	private boolean is32bit;
	private List<RelocationInfo> relocations = new ArrayList<>();

	public static Section createSection(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		Section section = (Section) reader.getFactory().create(Section.class);
		section.initSection(reader, is32bit);
		return section;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public Section() {
	}

	private void initSection(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		this.reader = reader;
		this.is32bit = is32bit;

		sectname = reader.readNextAsciiString(MachConstants.NAME_LENGTH);
		segname = reader.readNextAsciiString(MachConstants.NAME_LENGTH);
		if (is32bit) {
			addr = reader.readNextUnsignedInt();
			size = reader.readNextUnsignedInt();
		}
		else {
			addr = reader.readNextLong();
			size = reader.readNextLong();
		}
		offset = reader.readNextInt();
		align = reader.readNextInt();
		reloff = reader.readNextInt();
		nrelocs = reader.readNextInt();
		flags = reader.readNextInt();
		reserved1 = reader.readNextInt();
		reserved2 = reader.readNextInt();

		if (!is32bit) {
			reserved3 = reader.readNextInt();
		}

		long index = reader.getPointerIndex();
		reader.setPointerIndex(reloff);
		for (int i = 0; i < nrelocs; ++i) {
			relocations.add(RelocationInfo.createRelocationInfo(reader));
		}
		reader.setPointerIndex(index);
	}

	public List<RelocationInfo> getRelocations() {
		return relocations;
	}

	/**
	 * Returns true if this section has READ permission.
	 * <p>
	 * NOTE: On a real system, sections don't have their own permissions, only the segments they 
	 * live in do.  However, Ghidra needs finer-grained control for analysis to work correctly, so 
	 * we take control over section permissions to fit our needs.
	 * 
	 * @return true if this section has READ permission
	 */
	public boolean isRead() {
		return true; // All sections appear to be readable
	}

	/**
	 * Returns true if this section has WRITE permission.
	 * <p>
	 * NOTE: On a real system, sections don't have their own permissions, only the segments they 
	 * live in do.  However, Ghidra needs finer-grained control for analysis to work correctly, so 
	 * we take control over section permissions to fit our needs.
	 * 
	 * @return true if this section has WRITE permission
	 */
	public boolean isWrite() {

		if (sectname.startsWith(SectionNames.SECT_GOT)) {
			// Assume the GOT section is read_only.  This is not true, but it helps with analysis
			// This should be relocation setup.
			return true;
		}

		return !SegmentNames.SEG_TEXT.equals(segname) &&
			!SegmentNames.SEG_TEXT_EXEC.equals(segname) &&
			!SegmentNames.SEG_PRELINK_TEXT.equals(segname) &&
			!SectionNames.DATA_CONST.equals(sectname);
	}

	/**
	 * Returns true if this section has EXECUTE permission.
	 * <p>
	 * NOTE: On a real system, sections don't have their own permissions, only the segments they 
	 * live in do.  However, Ghidra needs finer-grained control for analysis to work correctly, so 
	 * we take control over section permissions to fit our needs.
	 * 
	 * @return true if this section has EXECUTE permission
	 */
	public boolean isExecute() {

		if (SectionNames.TEXT.equals(sectname) || SegmentNames.SEG_TEXT_EXEC.equals(segname)) {
			return true;
		}

		boolean pureInstr = (getAttributes() & SectionAttributes.S_ATTR_PURE_INSTRUCTIONS) != 0;
		boolean someInstr = (getAttributes() & SectionAttributes.S_ATTR_SOME_INSTRUCTIONS) != 0;
		return pureInstr || someInstr;
	}

	/**
	 * Returns an input stream to underlying bytes of this section.
	 * @return an input stream to underlying bytes of this section
	 * @throws IOException if an i/o error occurs.
	 */
	public InputStream getDataStream(MachHeader header) throws IOException {
		if (getType() == SectionTypes.S_ZEROFILL) {
			return new SectionInputStream(getSize(), (byte) 0);
		}
		if (getSectionName().equals(SectionNames.IMPORT_JUMP_TABLE) &&
			header.getFileType() == MachHeaderFileTypes.MH_EXECUTE) {
			return new SectionInputStream(getSize(), (byte) 0xf4);
		}
		return reader.getByteProvider().getInputStream(header.getStartIndex() + offset);
	}

	public String getSectionName() {
		return sectname;
	}

	public String getSegmentName() {
		return segname;
	}

	public long getAddress() {
		return addr;
	}

	public long getSize() {
		return size;
	}

	public int getOffset() {
		return offset;
	}

	public int getAlign() {
		return align;
	}

	public int getRelocationOffset() {
		return reloff;
	}

	public int getNumberOfRelocations() {
		return nrelocs;
	}

	public int getFlags() {
		return flags;
	}

	public int getType() {
		return flags & SectionTypes.SECTION_TYPE_MASK;
	}

	public int getAttributes() {
		return flags & SectionAttributes.SECTION_ATTRIBUTES_MASK;
	}

	public int getReserved1() {
		return reserved1;
	}

	public int getReserved2() {
		return reserved2;
	}

	public int getReserved3() {
		return reserved3;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("section", 0);
		struct.add(new StringDataType(), MachConstants.NAME_LENGTH, "sectname", null);
		struct.add(new StringDataType(), MachConstants.NAME_LENGTH, "segname", null);
		if (is32bit) {
			struct.add(DWORD, "addr", null);
			struct.add(DWORD, "size", null);
		}
		else {
			struct.add(QWORD, "addr", null);
			struct.add(QWORD, "size", null);
		}
		struct.add(DWORD, "offset", null);
		struct.add(DWORD, "align", null);
		struct.add(DWORD, "reloff", null);
		struct.add(DWORD, "nrelocs", null);
		struct.add(DWORD, "flags", null);
		struct.add(DWORD, "reserved1", null);
		struct.add(DWORD, "reserved2", null);
		if (!is32bit) {
			struct.add(DWORD, "reserved3", null);
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("      Name: " + sectname + '\n');
		buffer.append("   Address: 0x" + Long.toHexString(addr) + '\n');
		buffer.append("    Length: 0x" + Long.toHexString(size) + '\n');
		buffer.append("      Type: 0x" + Integer.toHexString(getType()) + " (" +
			SectionTypes.getTypeName(getType()) + ")" + '\n');
		buffer.append("    Offset: 0x" + Long.toHexString(offset) + '\n');
		List<String> attrs = SectionAttributes.getAttributeNames(getAttributes());
		buffer.append("Attributes: " + Integer.toHexString(getAttributes()) + '\n');
		for (String attr : attrs) {
			buffer.append("            " + attr + '\n');
		}
		return buffer.toString();
	}

	private class SectionInputStream extends InputStream {
		long streamSize;
		byte value;
		long nRead;

		SectionInputStream(long streamSize, byte value) {
			this.streamSize = streamSize;
			this.value = value;
		}

		@Override
		public int read() throws IOException {
			if (++nRead > streamSize) {
				return -1;
			}
			return (value & 0xff);
		}
	}
}
