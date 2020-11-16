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
package ghidra.app.util.bin.format.elf;

import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;

/**
 * <code>ElfRelrRelocationTableDataType</code> is a Factory datatype which defines a markup
 * structure corresponding to a specified ELF REL relocation table.  The REL entry size and
 * total length in bytes is required when interpreting a RELR table.
 */
class ElfRelrRelocationTableDataType extends FactoryStructureDataType {

	private int length;
	private int entrySize;

	/**
	 * Constructor
	 * @param structName structure name for resulting structure
	 * @param length total length of RELR table in bytes
	 * @param entrySize RELR entry size.  This size also generally corresponds to the 
	 * size if a stored pointer.
	 */
	ElfRelrRelocationTableDataType(String structName, int length, int entrySize) {
		this(structName, length, entrySize, null);
	}

	private ElfRelrRelocationTableDataType(String structName, int length, int entrySize,
			DataTypeManager dtm) {
		super(structName, dtm);
		this.length = length;
		this.entrySize = entrySize;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == dataMgr) {
			return this;
		}
		return new ElfRelrRelocationTableDataType(getName(), length, entrySize, dtm);
	}

	private long readNextRelrEntry(MemBuffer buf, int bufOffset) throws MemoryAccessException {
		return entrySize == 8 ? buf.getLong(bufOffset) : buf.getUnsignedInt(bufOffset);
	}

	@Override
	protected void populateDynamicStructure(MemBuffer buf, Structure struct) {

		DataType entryDataType = entrySize == 8 ? QWordDataType.dataType : DWordDataType.dataType;

		int bufOffset = 0;
		int remaining = length; // limit to number of bytes specified for RELR table
		int index = 0; // relr base index

		struct.add(entryDataType, "r_relr_base_" + (++index), null);
		bufOffset += entrySize;
		remaining -= entrySize;

		int bitMaskCount = 0;

		try {
			while (remaining > 0) {
				long nextValue = readNextRelrEntry(buf, bufOffset);
				if ((nextValue & 1) == 1) {
					++bitMaskCount;
				}
				else {
					if (bitMaskCount != 0) {
						DataType maskArray = new ArrayDataType(entryDataType, bitMaskCount, entrySize);
						struct.add(maskArray, "r_relr_bits_" + index, null);
						bitMaskCount = 0;
					}
					struct.add(entryDataType, "r_relr_base_" + (++index), null);
				}
				bufOffset += entrySize;
				remaining -= entrySize;
			}

			if (bitMaskCount != 0) {
				DataType maskArray = new ArrayDataType(entryDataType, bitMaskCount, entrySize);
				struct.add(maskArray, "r_relr_bits_" + index, null);
			}
		}
		catch (MemoryAccessException | IllegalArgumentException e) {
			// ignore
		}
	}

	@Override
	protected Structure setCategoryPath(Structure struct, MemBuffer buf) {
		try {
			struct.setCategoryPath(new CategoryPath("/ELF"));
		}
		catch (DuplicateNameException e) {
			// ignore - will not happen
		}
		return struct;
	}

}
