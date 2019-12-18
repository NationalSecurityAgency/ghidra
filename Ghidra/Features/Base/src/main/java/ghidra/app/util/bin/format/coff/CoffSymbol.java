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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CoffSymbol implements StructConverter {
	private String e_name;
	private int e_value;
	private short e_scnum;
	private short e_type;
	private byte e_sclass;
	private byte e_numaux;

	private List<CoffSymbolAux> _auxiliarySymbols = new ArrayList<CoffSymbolAux>();

	CoffSymbol(BinaryReader reader, CoffFileHeader header) throws IOException {

		if (reader.peekNextInt() == 0) {//look up name in string table
			reader.readNextInt();//skip null
			int nameIndex = reader.readNextInt();//string table index
			int stringTableIndex =
				header.getSymbolTablePointer() +
					(header.getSymbolTableEntries() * CoffConstants.SYMBOL_SIZEOF);
			e_name = reader.readAsciiString(stringTableIndex + nameIndex);
		}
		else {
			e_name = reader.readNextAsciiString(CoffConstants.SYMBOL_NAME_LENGTH);
		}

		e_value = reader.readNextInt();
		e_scnum = reader.readNextShort();
		e_type = reader.readNextShort();
		e_sclass = reader.readNextByte();
		e_numaux = reader.readNextByte();

		for (int i = 0; i < e_numaux; ++i) {
			_auxiliarySymbols.add(CoffSymbolAuxFactory.read(reader, this));
		}
	}

//	public void dump(PrintWriter w) {
//		w.println(e_name + ", " + e_type + ", " + e_scnum + ", " + e_sclass + ", 0x" + Integer.toHexString(e_value) + ", " + e_numaux );
//	}

	public String getName() {
		return e_name;
	}

	public long getValue() {
		//return e_value & 0xffffffff;
		return (e_value) & 0xffffffffL;
	}

	/**
	 * Adds offset to the value; this must be performed before
	 * relocations in order to achieve the proper result.
	 * @param offset the offset to add to the value
	 */
	public void move(int offset) {
		e_value += offset;
	}

	public short getSectionNumber() {
		return e_scnum;
	}

	public int getBasicType() {
		return e_type & 0xf;
	}

	public int getDerivedType(int derivedIndex) {
		if (derivedIndex < 1 || derivedIndex > 6) {
			throw new RuntimeException("1 <= derivedIndex <= 6");
		}
		int derivedType = (e_type & 0xffff) >> 4;
		if (derivedIndex > 1) {
			derivedType = derivedType >> (derivedIndex * 2);
		}
		return derivedType & 0x3;
	}

	public byte getStorageClass() {
		return e_sclass;
	}

	public byte getAuxiliaryCount() {
		return e_numaux;
	}

	public List<CoffSymbolAux> getAuxiliarySymbols() {
		return new ArrayList<CoffSymbolAux>(_auxiliarySymbols);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(getClass()), 0);
		struct.add(new ArrayDataType(ASCII, CoffConstants.SYMBOL_NAME_LENGTH, ASCII.getLength()),
			"e_name", null);
		struct.add(DWORD, "e_value", null);
		struct.add(WORD, "e_scnum", null);
		struct.add(WORD, "e_type", null);
		struct.add(BYTE, "e_sclass", null);
		struct.add(BYTE, "e_numaux", null);
		return struct;
	}

	/**
	 * Returns true if this symbol represents a section.
	 * @return true if this symbol represents a section
	 */
	public boolean isSection() {
		if (e_type == CoffSymbolType.T_NULL) {
			if (e_value == 0) {
				if (e_sclass == CoffSymbolStorageClass.C_STAT) {
					for (CoffSymbolAux aux : _auxiliarySymbols) {
						if (aux instanceof CoffSymbolAuxSection) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append(getName());
		buffer.append(' ');
		buffer.append("Value=0x" + Long.toHexString(getValue()));
		buffer.append(' ');
		buffer.append(e_scnum);
		buffer.append(' ');
		buffer.append(e_type);
		buffer.append(' ');
		buffer.append(e_sclass);
		return buffer.toString();
	}
}
