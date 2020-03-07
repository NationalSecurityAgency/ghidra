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
package ghidra.app.util.bin.format.ne;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Conv;

/**
 * <p>
 * A class to represent the Information Block
 * defined in the Windows new-style executable.
 * </p>
 * <p>
 * ...as defined in WINNT.H
 * </p>
 * <pre>
 * typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
 *     WORD   ne_magic;                    // Magic number
 *     CHAR   ne_ver;                      // Version number
 *     CHAR   ne_rev;                      // Revision number
 *     WORD   ne_enttab;                   // Offset of Entry Table
 *     WORD   ne_cbenttab;                 // Number of bytes in Entry Table
 *     LONG   ne_crc;                      // Checksum of whole file
 *     WORD   ne_flags;                    // Flag word
 *     WORD   ne_autodata;                 // Automatic data segment number
 *     WORD   ne_heap;                     // Initial heap allocation
 *     WORD   ne_stack;                    // Initial stack allocation
 *     LONG   ne_csip;                     // Initial CS:IP setting
 *     LONG   ne_sssp;                     // Initial SS:SP setting
 *     WORD   ne_cseg;                     // Count of file segments
 *     WORD   ne_cmod;                     // Entries in Module Reference Table
 *     WORD   ne_cbnrestab;                // Size of non-resident name table
 *     WORD   ne_segtab;                   // Offset of Segment Table
 *     WORD   ne_rsrctab;                  // Offset of Resource Table
 *     WORD   ne_restab;                   // Offset of resident name table
 *     WORD   ne_modtab;                   // Offset of Module Reference Table
 *     WORD   ne_imptab;                   // Offset of Imported Names Table
 *     LONG   ne_nrestab;                  // Offset of Non-resident Names Table
 *     WORD   ne_cmovent;                  // Count of movable entries
 *     WORD   ne_align;                    // Segment alignment shift count
 *     WORD   ne_cres;                     // Count of resource segments
 *     BYTE   ne_exetyp;                   // Target Operating system
 *     BYTE   ne_flagsothers;              // Other .EXE flags
 *     WORD   ne_pretthunks;               // offset to return thunks
 *     WORD   ne_psegrefbytes;             // offset to segment ref. bytes
 *     WORD   ne_swaparea;                 // Minimum code swap area size
 *     WORD   ne_expver;                   // Expected Windows version number
 * } IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;
 * </pre>
 * 
 * @see <a href="https://www.fileformat.info/format/exe/corion-ne.htm">The NE EXE File Format</a>
 * @see <a href="https://www.pcjs.org/pubs/pc/reference/microsoft/mspl13/msdos/encyclopedia/appendix-k/">Segmented (New) .EXE File Header Format</a>
 */
public class InformationBlock {
	private static final String TAB = "        ";

	/**
	 * Program flags: no auto data segments
	 */
	public final static byte FLAGS_PROG_NO_AUTO_DATA = (byte) 0x00;
	/**
	 * Program flags: single data segment
	 */
	public final static byte FLAGS_PROG_SINGLE_DATA = (byte) 0x01;
	/**
	 * Program flags: multiple data segments
	 */
	public final static byte FLAGS_PROG_MULTIPLE_DATA = (byte) 0x02;

	public final static byte FLAGS_PROG_GLOBAL_INIT = (byte) 0x04;
	public final static byte FLAGS_PROG_PROTECTED_MODE = (byte) 0x08;
	public final static byte FLAGS_PROG_8086 = (byte) 0x10;
	public final static byte FLAGS_PROG_80286 = (byte) 0x20;
	public final static byte FLAGS_PROG_80386 = (byte) 0x40;
	public final static byte FLAGS_PROG_80x87 = (byte) 0x80;

	/**
	 * Is application full screen?
	 */
	public final static byte FLAGS_APP_FULL_SCREEN = (byte) 0x01;
	/**
	 * Is application compatible with Windows Program Manager?
	 */
	public final static byte FLAGS_APP_WIN_PM_COMPATIBLE = (byte) 0x02;
	/**
	 * Does application use Windows Program Manager?
	 */
	public final static byte FLAGS_APP_WINDOWS_PM = (byte) 0x03;
	/**
	 * Does the first segment contain code that loads the application?
	 */
	public final static byte FLAGS_APP_LOAD_CODE = (byte) 0x08;
	public final static byte FLAGS_APP_LINK_ERRS = (byte) 0x20;
	public final static byte FLAGS_APP_NONCONFORMING_PROG = (byte) 0x40;
	public final static byte FLAGS_APP_LIBRARY_MODULE = (byte) 0x80;

	/**
	 * Unknown executable type
	 */
	public final static byte EXETYPE_UNKNOWN = (byte) 0x00;
	/**
	 * OS/2 executable
	 */
	public final static byte EXETYPE_OS2 = (byte) 0x01;
	/**
	 * Windows executable
	 */
	public final static byte EXETYPE_WINDOWS = (byte) 0x02;
	/**
	 * European DOS 4.x executable
	 */
	public final static byte EXETYPE_EUROPEAN_DOS_4 = (byte) 0x04;
	/**
	 * Reserved executable Type
	 */
	public final static byte EXETYPE_RESERVED4 = (byte) 0x08;
	/**
	 * Windows 386 executable
	 */
	public final static byte EXETYPE_WINDOWS_386 = (byte) 0x04;
	/**
	 * Borland Operating System Services executable
	 */
	public final static byte EXETYPE_BOSS = (byte) 0x05;
	/**
	 * Pharlap 286 OS/2 executable
	 */
	public final static byte EXETYPE_PHARLAP_286_OS2 = (byte) 0x81;
	/**
	 * Pharlap 386 Windows executable
	 */
	public final static byte EXETYPE_PHARLAP_286_WIN = (byte) 0x82;

	/**
	 * Supports long names
	 */
	public final static byte OTHER_FLAGS_SUPPORTS_LONG_NAMES = (byte) 0x00;
	/**
	 * Protected mode
	 */
	public final static byte OTHER_FLAGS_PROTECTED_MODE = (byte) 0x01;
	/**
	 * Proportional font
	 */
	public final static byte OTHER_FLAGS_PROPORTIONAL_FONT = (byte) 0x02;
	/**
	 * Gangload area
	 */
	public final static byte OTHER_FLAGS_GANGLOAD_AREA = (byte) 0x04;

	private short ne_magic;        // Magic number
	private byte ne_ver;           // Version number
	private byte ne_rev;           // Revision number
	private short ne_enttab;       // Offset of entry table
	private short ne_cbenttab;     // Number of bytes in entry table
	private int ne_crc;            // Checksum of whole file
	private byte ne_flags_prog;    // Flag word - program
	private byte ne_flags_app;     // Flag word - application
	private short ne_autodata;     // Automatic data segment number
	private short ne_heap;         // Initial heap allocation
	private short ne_stack;        // Initial stack allocation
	private int ne_csip;           // Initial CS:IP setting
	private int ne_sssp;           // Initial SS:SP setting
	private short ne_cseg;         // Count of file segments
	private short ne_cmod;         // Entries in module reference table
	private short ne_cbnrestab;    // Size of non-resident name table
	private short ne_segtab;       // Offset of segment table
	private short ne_rsrctab;      // Offset of resource table
	private short ne_restab;       // Offset of resident name table
	private short ne_modtab;       // Offset of module reference table
	private short ne_imptab;       // Offset of imported names table
	private int ne_nrestab;        // Offset of non-resident names table
	private short ne_cmovent;      // Count of movable entries
	private short ne_align;        // Segment alignment shift count
	private short ne_cres;         // Count of resource segments
	private byte ne_exetyp;        // Target operating system
	private byte ne_flagsothers;   // Other .EXE flags
	private short ne_pretthunks;   // offset to return thunks
	private short ne_psegrefbytes; // offset to segment ref. bytes
	private short ne_swaparea;     // Minimum code swap area size
	private short ne_expver;       // Expected windows version number

	InformationBlock(FactoryBundledWithBinaryReader reader, short index)
			throws InvalidWindowsHeaderException, IOException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(Conv.shortToInt(index));

		ne_magic = reader.readNextShort();

		if (ne_magic != WindowsHeader.IMAGE_NE_SIGNATURE) {
			throw new InvalidWindowsHeaderException();
		}

		ne_ver = reader.readNextByte();
		ne_rev = reader.readNextByte();
		ne_enttab = reader.readNextShort();
		ne_cbenttab = reader.readNextShort();
		ne_crc = reader.readNextInt();
		ne_flags_prog = reader.readNextByte();
		ne_flags_app = reader.readNextByte();
		ne_autodata = reader.readNextShort();
		ne_heap = reader.readNextShort();
		ne_stack = reader.readNextShort();
		ne_csip = reader.readNextInt();
		ne_sssp = reader.readNextInt();
		ne_cseg = reader.readNextShort();
		ne_cmod = reader.readNextShort();
		ne_cbnrestab = reader.readNextShort();
		ne_segtab = reader.readNextShort();
		ne_rsrctab = reader.readNextShort();
		ne_restab = reader.readNextShort();
		ne_modtab = reader.readNextShort();
		ne_imptab = reader.readNextShort();
		ne_nrestab = reader.readNextInt();
		ne_cmovent = reader.readNextShort();
		ne_align = reader.readNextShort();
		ne_cres = reader.readNextShort();
		ne_exetyp = reader.readNextByte();
		ne_flagsothers = reader.readNextByte();
		ne_pretthunks = reader.readNextShort();
		ne_psegrefbytes = reader.readNextShort();
		ne_swaparea = reader.readNextShort();
		ne_expver = reader.readNextShort();

		reader.setPointerIndex(oldIndex);
	}

	/**
	 * Returns the magic number.
	 * @return the magic number
	 */
	public short getMagicNumber() {
		return ne_magic;
	}

	/**
	 * Returns the version number.
	 * @return the version number
	 */
	public short getVersion() {
		return ne_ver;
	}

	/**
	 * Returns the revision number.
	 * @return the revision number
	 */
	public short getRevision() {
		return ne_rev;
	}

	/**
	 * Returns the checksum.
	 * @return the checksum
	 */
	public int getChecksum() {
		return ne_crc;
	}

	/**
	 * Returns the initial heap size.
	 * @return the initial heap size
	 */
	public short getInitialHeapSize() {
		return ne_heap;
	}

	/**
	 * Returns the initial stack size.
	 * @return the initial stack size
	 */
	public short getInitialStackSize() {
		return ne_stack;
	}

	/**
	 * Returns the target operating system.
	 * @return the target operating system
	 */
	public byte getTargetOpSys() {
		return ne_exetyp;
	}

	/**
	 * Returns the minimum code swap size.
	 * @return the minimum code swap size
	 */
	public short getMinCodeSwapSize() {
		return ne_swaparea;
	}

	/**
	 * Returns the expected windows version.
	 * @return the expected windows version
	 */
	public short getExpectedWindowsVersion() {
		return ne_expver;
	}

	/**
	 * Returns the automatic data segment.
	 * @return the automatic data segment
	 */
	public short getAutomaticDataSegment() {
		return ne_autodata;
	}

	/**
	 * Returns the other flags.
	 * @return the other flags
	 */
	public byte getOtherFlags() {
		return ne_flagsothers;
	}

	/**
	 * Returns a string representation of the other flags.
	 * @return a string representation of the other flags
	 */
	public String getOtherFlagsAsString() {
		StringBuffer buffer = new StringBuffer();
		if ((ne_flagsothers & OTHER_FLAGS_GANGLOAD_AREA) != 0) {
			buffer.append(TAB + "Gangload Area" + "\n");
		}
		if ((ne_flagsothers & OTHER_FLAGS_PROPORTIONAL_FONT) != 0) {
			buffer.append(TAB + "Proportional Font" + "\n");
		}
		if ((ne_flagsothers & OTHER_FLAGS_PROTECTED_MODE) != 0) {
			buffer.append(TAB + "Protected Mode" + "\n");
		}
		if ((ne_flagsothers & OTHER_FLAGS_SUPPORTS_LONG_NAMES) != 0) {
			buffer.append(TAB + "Long Name Support" + "\n");
		}
		return buffer.toString();
	}

	/**
	 * Returns the program flags.
	 * @return the program flags
	 */
	public byte getProgramFlags() {
		return ne_flags_prog;
	}

	/**
	 * Returns the application flags.
	 * @return the application flags
	 */
	public byte getApplicationFlags() {
		return ne_flags_app;
	}

	/**
	 * Returns the segment portion of the entry point.
	 * @return the segment portion of the entry point
	 */
	public short getEntryPointSegment() {
		return (short) ((ne_csip >> 16) & 0xffff);
	}

	/**
	 * Returns the offset portion of the entry point.
	 * @return the offset portion of the entry point
	 */
	public short getEntryPointOffset() {
		return (short) (ne_csip & 0xffff);
	}

	/**
	 * Returns the segment portion of the stack pointer.
	 * @return the segment portion of the stack pointer
	 */
	public short getStackPointerSegment() {
		return (short) ((ne_sssp >> 16) & 0xffff);
	}

	/**
	 * Returns the offset portion of the stack pointer.
	 * @return the offset portion of the stack pointer
	 */
	public short getStackPointerOffset() {
		return (short) (ne_sssp & 0xffff);
	}

	/**
	 * Returns the index to the start of the segment table,
	 * relative to the beginning of the NE windows header.
	 * 
	 * @return the index of start of the segment table
	 */
	short getSegmentTableOffset() {
		return ne_segtab;
	}

	/**
	 * Returns the number of segments in the segment table.
	 * @return the number of segments in the segment table
	 */
	short getSegmentCount() {
		return ne_cseg;
	}

	/**
	 * Returns a shift count that is used to align the logical sector.
	 * <br>
	 * This count is log2 of the segment sector size.
	 * This value corresponds to the Alignment [/a] linker
	 * switch.
	 * It is typically 4, but the default is 9.
	 * When the linker command line contains a/: 16, the shift count is 4.
	 * When the linker command line contains a/:256, the shift count is 9.
	 * 
	 * @return a shift count that is used to align the logical sector
	 */
	short getSegmentAlignmentShiftCount() {
		return ne_align;
	}

	/**
	 * Returns the index to the start of the resource table,
	 * relative to the beginning of the NE windows header.
	 * @return the index to the start of the resource table
	 */
	short getResourceTableOffset() {
		return ne_rsrctab;
	}

	/**
	 * Returns the index to the start of the resident name table,
	 * relative to the beginning of the NE windows header.
	 * @return the index to the start of the resident name table
	 */
	short getResidentNameTableOffset() {
		return ne_restab;
	}

	/**
	 * Returns the index to the start of the modules reference table,
	 * relative to the beginning of the NE windows header.
	 * @return the index to the start of the modules reference table
	 */
	short getModuleReferenceTableOffset() {
		return ne_modtab;
	}

	/**
	 * Returns the number of entries in the module reference table.
	 * @return the number of entries in the module reference table
	 */
	short getModuleReferenceTableCount() {
		return ne_cmod;
	}

	/**
	 * Returns the index to the start of the imported names table,
	 * relative to the beginning of the NE windows header.
	 * @return the index to the start of the imported names table
	 */
	short getImportedNamesTableOffset() {
		return ne_imptab;
	}

	/**
	 * Returns the index to the start of the entry table,
	 * relative to the beginning of the NE windows header.
	 * @return the index to the start of the entry table
	 */
	short getEntryTableOffset() {
		return ne_enttab;
	}

	/**
	 * Returns the number of bytes in the entry table.
	 * @return the number of bytes in the entry table
	 */
	short getEntryTableSize() {
		return ne_cbenttab;
	}

	/**
	 * Returns the index to the start of the segment table,
	 * relative to the beginning of the file.
	 * @return the index to the start of the segment table
	 */
	int getNonResidentNameTableOffset() {
		return ne_nrestab;
	}

	/**
	 * Returns the number of bytes in the non-resident name table.
	 * @return the number of bytes in the non-resident name table
	 */
	short getNonResidentNameTableSize() {
		return ne_cbnrestab;
	}

	short getMoveableEntriesCount() {
		return ne_cmovent;
	}

	short getResourceSegmentCount() {
		return ne_cres;
	}

	short getReturnOffsetThunk() {
		return ne_pretthunks;
	}

	short getSegmentRefByteOffset() {
		return ne_psegrefbytes;
	}

	////////////////////////////////////////////////////////////////////

	/**
	 * Returns a string representation of the target operating system.
	 * @return a string representation of the target operating system
	 */
	public String getTargetOpSysAsString() {
		switch (ne_exetyp) {
			case EXETYPE_UNKNOWN:
				return "Unknown";
			case EXETYPE_OS2:
				return "OS/2";
			case EXETYPE_WINDOWS:
				return "Windows";
			//case EXETYPE_EUROPEAN_DOS_4: return "European DOS 4.x";
			case EXETYPE_RESERVED4:
				return "Reserved 4";
			case EXETYPE_WINDOWS_386:
				return "Windows 386";
			case EXETYPE_BOSS:
				return "Borland Operating System Services";
			case EXETYPE_PHARLAP_286_OS2:
				return "Pharlap 286 OS/2";
			case EXETYPE_PHARLAP_286_WIN:
				return "Pharlap 286 Windows";
		}
		return null;
	}

	/**
	 * Returns a string representation of the application flags.
	 * @return a string representation of the application flags
	 */
	public String getApplicationFlagsAsString() {
		StringBuffer buffer = new StringBuffer();
		byte application_type = (byte) (ne_flags_app & 0x03);
		if (application_type == FLAGS_APP_FULL_SCREEN) {
			buffer.append(TAB + "Full Screen" + "\n");
		}
		else if (application_type == FLAGS_APP_WIN_PM_COMPATIBLE) {
			buffer.append(TAB + "Windows P.M. API Compatible" + "\n");
		}
		else if (application_type == FLAGS_APP_WINDOWS_PM) {
			buffer.append(TAB + "Windows P.M. API" + "\n");
		}

		if ((ne_flags_app & FLAGS_APP_LIBRARY_MODULE) != 0) {
			buffer.append(TAB + "Library Module" + "\n");
		}
		if ((ne_flags_app & FLAGS_APP_LINK_ERRS) != 0) {
			buffer.append(TAB + "Link Errors" + "\n");
		}
		if ((ne_flags_app & FLAGS_APP_LOAD_CODE) != 0) {
			buffer.append(TAB + "Load Code" + "\n");
		}
		if ((ne_flags_app & FLAGS_APP_NONCONFORMING_PROG) != 0) {
			buffer.append(TAB + "Nonconforming" + "\n");
		}
		return buffer.toString();
	}

	/**
	 * Returns a string representation of the program flags.
	 * @return a string representation of the program flags
	 */
	public String getProgramFlagsAsString() {
		StringBuffer buffer = new StringBuffer();
		if ((ne_flags_prog & FLAGS_PROG_80286) != 0) {
			buffer.append(TAB + "80286" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_80386) != 0) {
			buffer.append(TAB + "80386" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_8086) != 0) {
			buffer.append(TAB + "8086" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_GLOBAL_INIT) != 0) {
			buffer.append(TAB + "Global Init" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_SINGLE_DATA) != 0) {
			buffer.append(TAB + "Single Data" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_MULTIPLE_DATA) != 0) {
			buffer.append(TAB + "Multi Data" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_NO_AUTO_DATA) != 0) {
			buffer.append(TAB + "No Auto Data" + "\n");
		}
		if ((ne_flags_prog & FLAGS_PROG_PROTECTED_MODE) != 0) {
			buffer.append(TAB + "Protected Mode" + "\n");
		}
		return buffer.toString();
	}
}
