/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.xcoff;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public final class XCoffOptionalHeader implements StructConverter {
	private final static char NL = '\n';

	public final static int AOUTHDRSZ = 72;	// First 28 bytes same as for COFF

	private short   o_magic;      //type of file (0x010B)
	private short   o_vstamp;     //version stamp (1)
	private long    o_tsize;      //text size in bytes, padded to FW boundary
	private long    o_dsize;      //initialized data "  "
	private long    o_bsize;      //uninitialized data "   "
	private long    o_entry;      //entry point.
	private long    o_text_start; //base of text used for this file
	private long    o_data_start; //base of data used for this file
	private long    o_toc;        //Address of TOC anchor
	private short   o_snentry;    //Section number for entry point
	private short   o_sntext;     //Section number for .text
	private short   o_sndata;     //Section number for .data
	private short   o_sntoc;      //Section number for TOC
	private short   o_snloader;   //Section number for loader data
	private short   o_snbss;      //Section number for .bss
	private short   o_algntext;   //Maximum alignment for .text
	private short   o_algndata;   //Maximum alignment for .data
	private byte [] o_modtype;    //Module Type Field
	private byte    o_cpuflag;    //Bit flags - cpu types of objects
	private byte    o_cputype;    //Reserved for cpu type
	private long    o_maxstack;   //Maximum stack size allowed (bytes)
	private long    o_maxdata;    //Maximum data size allowed (bytes)
	private long    o_debugger;   //Reserved for debuggers
	private byte    o_flags;      //Flags and thread-local storage alignment
	private short   o_sntdata;    //Section number for .tdata
	private short   o_sntbss;     //Section number for .tbss

	XCoffOptionalHeader(BinaryReader reader, XCoffFileHeader header) throws IOException {
		o_magic             = reader.readNextShort();
		o_vstamp            = reader.readNextShort();

		if (XCoffFileHeaderMagic.is32bit(header)) {
			o_tsize         = reader.readNextInt() & 0xffffffffL;
			o_dsize         = reader.readNextInt() & 0xffffffffL;
			o_bsize         = reader.readNextInt() & 0xffffffffL;
			o_entry         = reader.readNextInt() & 0xffffffffL;
			o_text_start    = reader.readNextInt() & 0xffffffffL;
			o_data_start    = reader.readNextInt() & 0xffffffffL;
			o_toc           = reader.readNextInt() & 0xffffffffL;
		}
		else if (XCoffFileHeaderMagic.is64bit(header)) {
			o_tsize         = reader.readNextLong();
			o_dsize         = reader.readNextLong();
			o_bsize         = reader.readNextLong();
			o_entry         = reader.readNextLong();
			o_text_start    = reader.readNextLong();
			o_data_start    = reader.readNextLong();
			o_toc           = reader.readNextLong();
		}

		o_snentry           = reader.readNextShort();
		o_sntext            = reader.readNextShort();
		o_sndata            = reader.readNextShort();
		o_sntoc             = reader.readNextShort();
		o_snloader          = reader.readNextShort();
		o_snbss             = reader.readNextShort();
		o_algntext          = reader.readNextShort();
		o_algndata          = reader.readNextShort();
		o_modtype           = reader.readNextByteArray(2);
		o_cpuflag           = reader.readNextByte();
		o_cputype           = reader.readNextByte();

		if (XCoffFileHeaderMagic.is32bit(header)) {
			o_maxstack      = reader.readNextInt() & 0xffffffffL;
			o_maxdata       = reader.readNextInt() & 0xffffffffL;
			o_debugger      = reader.readNextInt() & 0xffffffffL;
		}
		else if (XCoffFileHeaderMagic.is64bit(header)) {
			o_maxstack      = reader.readNextLong();
			o_maxdata       = reader.readNextLong();
			o_debugger      = reader.readNextLong();
		}

		o_flags             = reader.readNextByte();
		o_sntdata           = reader.readNextShort();
		o_sntbss            = reader.readNextShort();
	}

	@Override
    public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("OPTIONAL HEADER VALUES").append(NL);
		buffer.append("magic      = ").append(o_magic).append(NL);
		buffer.append("vstamp     = ").append(o_vstamp).append(NL);
		buffer.append("tsize      = ").append(o_tsize).append(NL);
		buffer.append("dsize      = ").append(o_dsize).append(NL);
		buffer.append("bsize      = ").append(o_bsize).append(NL);
		buffer.append("entry      = ").append(o_entry).append(NL);
		buffer.append("text_start = ").append(o_text_start).append(NL);
		buffer.append("data_start = ").append(o_data_start).append(NL);
		buffer.append("o_toc      = ").append(o_toc).append(NL);
		buffer.append("o_snentry  = ").append(o_snentry).append(NL);
		buffer.append("o_sntext   = ").append(getSectionNumberForText()).append(NL);
		buffer.append("o_sndata   = ").append(o_sndata).append(NL);
		buffer.append("o_sntoc    = ").append(o_sntoc).append(NL);
		buffer.append("o_snloader = ").append(o_snloader).append(NL);
		buffer.append("o_snbss    = ").append(o_snbss).append(NL);
		buffer.append("o_algntext = ").append(o_algntext).append(NL);
		buffer.append("o_algndata = ").append(o_algndata).append(NL);
		buffer.append("o_modtype  = ").append(o_modtype).append(NL);
		buffer.append("o_cpuflag  = ").append(o_cpuflag).append(NL);
		buffer.append("o_cputype  = ").append(o_cputype).append(NL);
		buffer.append("o_maxstack = ").append(o_maxstack).append(NL);
		buffer.append("o_maxdata  = ").append(o_maxdata).append(NL);
		buffer.append("o_flags    = ").append(o_flags).append(NL);
		buffer.append("o_debugger = ").append(o_debugger).append(NL);
		buffer.append("o_sntdata  = ").append(o_sntdata).append(NL);
		buffer.append("o_sntbss   = ").append(o_sntbss).append(NL);
		return buffer.toString();
	}

	/**
	 * Returns the magic value. The binder assigns the following value: 0x010b.
	 * @return the magic value
	 */
	public short getMagic() {
		return o_magic;
	}
	/**
	 * Returns the format version for this auxiliary header.
	 * The only valid value is 1.
	 * @return the format version for this auxiliary header
	 */
	public short getVersionStamp() {
		return o_vstamp;
	}
	/**
	 * Returns the size (in bytes) of the raw data for the .text section.
	 * @return the size (in bytes) of the raw data for the .text section
	 */
	public long getTextSize() {
		return o_tsize;
	}
	/**
	 * Returns the size (in bytes) of the raw data for the .data section.
	 * @return the size (in bytes) of the raw data for the .data section
	 */
	public long getInitializedDataSize() {
		return o_dsize;
	}
	/**
	 * Returns the size (in bytes) of the .bss section.
	 * No raw data exists in the file for the .bss section.
	 * @return the size (in bytes) of the .bss section
	 */
	public long getUninitializedDataSize() {
		return o_bsize;
	}
	/**
	 * Returns the virtual address of the entry point.
	 * @return the virtual address of the entry point
	 */
	public long getEntry() {
		return o_entry;
	}
	/**
	 * Returns the virtual address of the .text section.
	 * @return the virtual address of the .text section
	 */
	public long getTextStart() {
		return o_text_start;
	}
	/**
	 * Returns the virtual address of the .data section.
	 * @return the virtual address of the .data section
	 */
	public long getDataStart() {
		return o_data_start;
	}
	/**
	 * Returns the virtual address of the TOC anchor.
	 * @return the virtual address of the TOC anchor
	 */
	public long getTOC() {
		return o_toc;
	}
	/**
	 * Returns the number of the section that contains the entry point.
	 * The entry point must be in the .text or .data section.
	 * @return the number of the section that contains the entry point
	 */
	public short getSectionNumberForEntry() {
		return o_snentry;
	}
	/**
	 * Returns the number of the .text section.
	 * @return the number of the .text section
	 */
	public short getSectionNumberForText() {
		return o_sntext;
	}
	/**
	 * Returns the number of the .data section.
	 * @return the number of the .data section
	 */
	public short getSectionNumberForData() {
		return o_sndata;
	}
	/**
	 * Returns the number of the section that contains the TOC.
	 * @return the number of the section that contains the TOC
	 */
	public short getSectionNumberForTOC() {
		return o_sntoc;
	}
	/**
	 * Returns the number of the section that contains the system loader information.
	 * @return the number of the section that contains the system loader information
	 */
	public short getSectionNumberForLoader() {
		return o_snloader;
	}
	/**
	 * Returns the number of the .bss section.
	 * @return the number of the .bss section
	 */
	public short getSectionNumberForBss() {
		return o_snbss;
	}
	/**
	 * Returns log (base-2) of the maximum alignment needed for 
	 * any csect in the .text section.
	 * @return the maximum alignment for the .text section
	 */
	public short getMaxAlignmentForText() {
		return o_algntext;
	}
	/**
	 * Returns log (base-2) of the maximum alignment needed for 
	 * any csect in the .data or .bss section.
	 * @return the maximum alignment for the .data or .bss section
	 */
	public short getMaxAlignmentForData() {
		return o_algndata;
	}
	/**
	 * Returns the module type.
	 * Valid module types:
	 * 		RO - Specifies a read-only module.
	 * @return the module type
	 */
	public String getModuleType() {
		return new String(o_modtype);
	}
	/**
	 * Returns the CPU bit flags.
	 * @return the CPU bit flags
	 */
	public byte getCpuFlag() {
		return o_cpuflag;
	}
	/**
	 * Reserved. Always returns 0.
	 * @return always returns 0
	 */
	public byte getCpuType() {
		return o_cputype;
	}
	/**
	 * Returns the maximum stack size allowed for this executable.
	 * If the value is 0, then the default value is used.
	 * @return the maximum stack size allow for this executable
	 */
	public long getMaxStackSize() {
		return o_maxstack;
	}
	/**
	 * Returns the maximum data size allowed for this executable.
	 * If the value is 0, then the default value is used.
	 * @return the maximum data size allow for this executable
	 */
	public long getMaxDataSize() {
		return o_maxdata;
	}
	/**
	 * This field should be 0. When the loaded program
	 * is being debugged, the memory image of this field
	 * may be modified by the debugger to insert
	 * a trap instruction.
	 * @return should return 0
	 */
	public long getDebugger() {
		return o_debugger;
	}
	/**
	 * This field consists of 4 1-bit flags and a 4-bit .tdata alignment.
	 * @return the flags
	 */
	public byte getFlags() {
		return o_flags;
	}
	
	public short getSectionNumberForTData() {
		return o_sntdata;
	}
	public short getSectionNumberForTBss() {
		return o_sntbss;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(XCoffOptionalHeader.class);
	}
}
