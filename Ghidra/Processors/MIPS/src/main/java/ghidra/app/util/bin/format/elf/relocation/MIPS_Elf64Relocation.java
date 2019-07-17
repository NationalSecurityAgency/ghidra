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
package ghidra.app.util.bin.format.elf.relocation;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.program.model.data.*;
import ghidra.util.*;

/**
 * <code>MIPS_Elf64Relocation</code> provides a MIPS-64 extension implementation
 * for {@link ElfRelocation} which supports the modified ELF-64 relocation entry format
 * utilized.
 */
public class MIPS_Elf64Relocation extends ElfRelocation {

	private int symbolIndex;
	private int specialSymbolIndex;
	private int type; // contains upto 3 relocation types (1-byte each)

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 * @see ElfRelocation#createElfRelocation
	 */
	public MIPS_Elf64Relocation() {
	}

	@Override
	protected void initElfRelocation(FactoryBundledWithBinaryReader reader, ElfHeader elfHeader,
			int relocationTableIndex, boolean withAddend) throws IOException {
		super.initElfRelocation(reader, elfHeader, relocationTableIndex, withAddend);
		long info = getRelocationInfo();
		if (elfHeader.isLittleEndian()) {
			// revert to big-endian byte order
			info = DataConverter.swapBytes(info, 8);
		}
		DataConverter converter = elfHeader.isLittleEndian() ? LittleEndianDataConverter.INSTANCE
				: BigEndianDataConverter.INSTANCE;
		byte[] rSymBytes = BigEndianDataConverter.INSTANCE.getBytes((int) (info >>> 32));
		symbolIndex = converter.getInt(rSymBytes);
		specialSymbolIndex = ((int) info >>> 24) & 0xff;
		type = (int) info & 0xffffff;
	}

	@Override
	public int getSymbolIndex() {
		return symbolIndex;
	}

	/**
	 * Return the special symbol index associated with this relocation
	 * @return special symbol index (r_ssym)
	 */
	public int getSpecialSymbolIndex() {
		return specialSymbolIndex;
	}

	/**
	 * MIPS-64 supports upto 3-relocations to be packed into a single relocation entry (r_type3, r_type2, r_type1).
	 * @return MIPS-64 packed relocation type (contains upto three 1-byte types)
	 */
	@Override
	public int getType() {
		return type;
	}

	@Override
	public DataType toDataType() {
		String dtName = "Elf64_MIPS_Rel";
		if (hasAddend()) {
			dtName += "a";
		}
		Structure struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		struct.add(QWORD, "r_offset", R_OFFSET_COMMENT);
		struct.add(DWORD, "r_sym", null);
		struct.add(BYTE, "r_ssym", null);
		struct.add(BYTE, "r_rtype3", null);
		struct.add(BYTE, "r_rtype2", null);
		struct.add(BYTE, "r_rtype1", null);
		if (hasAddend()) {
			struct.add(QWORD, "r_addend", R_ADDEND_COMMENT);
		}
		return struct;
	}
}
