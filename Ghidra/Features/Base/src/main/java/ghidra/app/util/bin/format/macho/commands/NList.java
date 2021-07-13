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

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents an nlist and nlist_64 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/nlist.h.auto.html">mach-o/nlist.h</a> 
 */
public class NList implements StructConverter {
	private int n_strx;
	private byte n_type;
	private byte n_sect;
	private short n_desc;
	private long n_value;

	private String string;
	private boolean is32bit;

	public static NList createNList(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		NList nList = (NList) reader.getFactory().create(NList.class);
		nList.initNList(reader, is32bit);
		return nList;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public NList() {
	}

	private void initNList(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		this.is32bit = is32bit;

		n_strx = reader.readNextInt();
		n_type = reader.readNextByte();
		n_sect = reader.readNextByte();
		n_desc = reader.readNextShort();
		if (is32bit) {
			n_value = reader.readNextInt() & 0xffffffffL;
		}
		else {
			n_value = reader.readNextLong();
		}
	}

	/**
	 * Initialize the string from the string table.
	 * <p>
	 * You MUST call this method after the NLIST element is created!
	 * <p>
	 * Reading a large NList table can cause a large performance issue if the strings
	 * are initialized as the NList entry is created.  The string table indexes are
	 * scattered.  Initializing the strings linearly from the string table is much
	 * faster.
	 * 
	 * @param reader 
	 * @param stringTableOffset offset of the string table
	 */
	public void initString(FactoryBundledWithBinaryReader reader, long stringTableOffset) {
		try {
			string = reader.readAsciiString(stringTableOffset + n_strx);
		}
		catch (Exception e) {
			string = "";
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("nlist", 0);
		struct.add(DWORD, "n_strx", null);
		struct.add(BYTE, "n_type", null);
		struct.add(BYTE, "n_sect", null);
		struct.add(WORD, "n_desc", null);
		if (is32bit) {
			struct.add(DWORD, "n_value", null);
		}
		else {
			struct.add(QWORD, "n_value", null);
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	/**
	 * Returns the symbol string defined at the symbol table command
	 * string table offset plus n_strx.
	 * @return the symbol string
	 */
	public String getString() {
		if (string == null) {
			throw new AssertException("initString must be called first");
		}
		return string;
	}

	/**
	 * Returns the index into the string table.
	 * @return the index into the string table
	 */
	public int getStringTableIndex() {
		return n_strx;
	}

	/**
	 * Returns the symbol type flag.
	 * @return the symbol type flag
	 */
	public byte getType() {
		return n_type;
	}

	public boolean isTypeUndefined() {
		return n_sect == NListConstants.NO_SECT &&
			(n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_UNDF;
	}

	public boolean isTypeAbsolute() {
		return n_sect == NListConstants.NO_SECT &&
			(n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_ABS;
	}

	public boolean isTypePreboundUndefined() {
		return n_sect == NListConstants.NO_SECT &&
			(n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_PBUD;
	}

	public boolean isIndirect() {
		return n_sect == NListConstants.NO_SECT &&
			(n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_INDR;
	}

	public boolean isSymbolicDebugging() {
		return (n_type & NListConstants.MASK_N_STAB) != 0;
	}

	public boolean isPrivateExternal() {
		return (n_type & NListConstants.MASK_N_PEXT) != 0;
	}

	public boolean isExternal() {
		return (n_type & NListConstants.MASK_N_EXT) != 0;
	}

	public boolean isLazyBind() {
		return (n_desc & NListConstants.REFERENCE_TYPE) != 0;
	}

	public boolean isThumbSymbol() {
		return (n_desc & NListConstants.DESC_N_ARM_THUMB_DEF) != 0;
	}

	/**
	 * An integer specifying the number of the section that this
	 * symbol can be found in, or NO_SECT if
	 * symbol is not found in a section of this image.
	 * @return the number of the section
	 */
	public byte getSection() {
		return n_sect;
	}

	/**
	 * A 16-bit value providing additional information about this symbol.
	 * @return a 16-bit value providing additional information about this symbol
	 */
	public short getDescription() {
		return n_desc;
	}

	/**
	 * An integer that contains the value of this symbol.
	 * The format of this value is different for each type of symbol.
	 * @return the value of this symbol
	 */
	public long getValue() {
		return n_value;
	}

	public int getLibraryOrdinal() {
		return (((n_desc) >> 8) & 0xff);
	}

	@Override
	public String toString() {
		return string;
	}
}
