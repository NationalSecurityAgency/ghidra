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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * See Apple's -- PEFBinaryFormat.h
 * <pre>
 * struct PEFLoaderRelocationHeader {
 *     UInt16   sectionIndex;     // Index of the section to be fixed up.
 *     UInt16   reservedA;        // Reserved, must be zero.
 *     UInt32   relocCount;       // Number of 16 bit relocation chunks.
 *     UInt32   firstRelocOffset; // Offset of first relocation instruction.
 * };
 * 
 * typedef UInt16 PEFRelocChunk;
 * </pre>
 */
public class LoaderRelocationHeader implements StructConverter {
	private short sectionIndex;
	private short reservedA;
	private int   relocCount;
	private int   firstRelocOffset;

	private List<Relocation> _relocations = new ArrayList<Relocation>();

	LoaderRelocationHeader(BinaryReader reader, LoaderInfoHeader loader) throws IOException {
		sectionIndex     = reader.readNextShort();
		reservedA        = reader.readNextShort();
		relocCount       = reader.readNextInt();
		firstRelocOffset = reader.readNextInt();

		long oldIndex = reader.getPointerIndex();
		int indexToRelocations = loader.getSection().getContainerOffset() + loader.getRelocInstrOffset();
		reader.setPointerIndex(indexToRelocations);
		long endIndex = indexToRelocations + (relocCount * 2);

		try {
			while (reader.getPointerIndex() < endIndex) {
				Relocation reloc = RelocationFactory.getRelocation(reader);
				_relocations.add(reloc);
			}
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	/**
	 * The sectionIndex field (2 bytes) designates the 
	 * section number to which this relocation header refers.
	 * @return section number to which this relocation header refers
	 */
	public short getSectionIndex() {
		return sectionIndex;
	}
	/**
	 * Reserved, must be set to zero (0).
	 * @return reserved, must be set to zero (0)
	 */
	public short getReservedA() {
		return reservedA;
	}
	/**
	 * The relocCount field (4 bytes) indicates the 
	 * number of 16-bit relocation blocks for this section.
	 * @return number of 16-bit relocation blocks for this section
	 */
	public int getRelocCount() {
		return relocCount;
	}
	/**
	 * The firstRelocOffset field (4 bytes) indicates the byte 
	 * offset from the start of the relocations area to the first relocation 
	 * instruction for this section.
	 * @return offset from the start of the relocations area to the first relocation
	 */
	public int getFirstRelocOffset() {
		return firstRelocOffset;
	}

	public List<Relocation> getRelocations() {
		return _relocations;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
