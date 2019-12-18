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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class CoffFileHeader implements StructConverter {

	private short f_magic;   // magic number
	private short f_nscns;   // number of sections
	private int f_timdat;  // time and date stamp
	private int f_symptr;  // file pointer to symbol table
	private int f_nsyms;   // number of entries in symbol table
	private short f_opthdr;  // size of optional header
	private short f_flags;   // flags

	private short f_target_id; // target id (TI-specific)

	private AoutHeader _aoutHeader;
	private List<CoffSectionHeader> _sections = new ArrayList<CoffSectionHeader>();
	private List<CoffSymbol> _symbols = new ArrayList<CoffSymbol>();

	public CoffFileHeader(ByteProvider provider) throws IOException {
		BinaryReader reader = getBinaryReader(provider);

		f_magic = reader.readNextShort();
		f_nscns = reader.readNextShort();
		f_timdat = reader.readNextInt();
		f_symptr = reader.readNextInt();
		f_nsyms = reader.readNextInt();
		f_opthdr = reader.readNextShort();
		f_flags = reader.readNextShort();

		if (isCoffLevelOneOrTwo()) {
			f_target_id = reader.readNextShort();
		}
	}

	private BinaryReader getBinaryReader(ByteProvider provider) {
		BinaryReader reader = new BinaryReader(provider, true/*COFF is always LE!!!*/);
		return reader;
	}

	private boolean isCoffLevelOneOrTwo() {
		return f_magic == CoffMachineType.TICOFF1MAGIC || f_magic == CoffMachineType.TICOFF2MAGIC;
	}

	/**
	 * Returns the magic COFF file identifier.
	 * @return the magic COFF file identifier
	 */
	public short getMagic() {
		return f_magic;
	}

	/**
	 * Returns the number of sections in this COFF file.
	 * @return the number of sections in this COFF file
	 */
	public short getSectionCount() {
		return f_nscns;
	}

	/**
	 * Returns the time stamp of when this file was created.
	 * @return the time stamp of when this file was created
	 */
	public int getTimestamp() {
		return f_timdat;
	}

	/**
	 * Returns the file offset to the symbol table.
	 * @return the file offset to the symbol table
	 */
	public int getSymbolTablePointer() {
		return f_symptr;
	}

	/**
	 * Returns the number of symbols in the symbol table.
	 * @return the number of symbols in the symbol table
	 */
	public int getSymbolTableEntries() {
		return f_nsyms;
	}

	/**
	 * Returns the size in bytes of the optional header.
	 * The optional header immediately follows the file header
	 * and immediately proceeds the sections headers.
	 * @return the size in bytes of the optional header
	 */
	public short getOptionalHeaderSize() {
		return f_opthdr;
	}

	/**
	 * Returns the flags about this COFF.
	 * @return the flags about this COFF
	 */
	public short getFlags() {
		return f_flags;
	}

	/**
	 * Returns the specific target id
	 * @return the specific target id
	 */
	public short getTargetID() throws CoffException {
		if (!isCoffLevelOneOrTwo()) {
			throw new CoffException("Calling this method is not valid for this COFF header type.");
		}
		return f_target_id;
	}

	/**
	 * Returns the image base.
	 * @return the image base
	 */
	public long getImageBase(boolean isWindowsPlatform) {
		if (isWindowsPlatform && f_opthdr != 0) {
			return 0x80;
		}
		return 0;
	}

	/**
	 * Returns the machine name.
	 * @return the machine name
	 */
	public String getMachineName() {
		if (isCoffLevelOneOrTwo()) {
			return "" + f_target_id;
		}
		return "" + f_magic;
	}

	public short getMachine() {
		if (isCoffLevelOneOrTwo()) {
			return f_target_id;
		}
		return f_magic;
	}

	/**
	 * Read just the section headers, not including line numbers and relocations
	 * @param provider
	 * @throws IOException
	 */
	public void parseSectionHeaders(ByteProvider provider) throws IOException {
		BinaryReader reader = getBinaryReader(provider);

		long originalIndex = reader.getPointerIndex();
		try {
			reader.setPointerIndex(sizeof() + f_opthdr);
			for (int i = 0; i < f_nscns; ++i) {
				CoffSectionHeader section =
					CoffSectionHeaderFactory.createSectionHeader(reader, this);
				_sections.add(section);
			}
		}
		finally {
			reader.setPointerIndex(originalIndex);
		}
	}

	/**
	 * Finishes the parsing of this file header.
	 * @param monitor the task monitor
	 * @throws IOException if an i/o error occurs
	 */
	public void parse(ByteProvider provider, TaskMonitor monitor) throws IOException {
		BinaryReader reader = getBinaryReader(provider);

		monitor.setMessage("Completing file header parsing...");
		long originalIndex = reader.getPointerIndex();
		try {
			reader.setPointerIndex(sizeof());
			_aoutHeader = AoutHeaderFactory.createAoutHeader(reader, this);

			reader.setPointerIndex(sizeof() + f_opthdr);
			for (int i = 0; i < f_nscns; ++i) {
				CoffSectionHeader section =
					CoffSectionHeaderFactory.createSectionHeader(reader, this);
				_sections.add(section);
				section.parse(reader, this, monitor);
			}
			reader.setPointerIndex(f_symptr);
			for (int i = 0; i < f_nsyms; ++i) {
				CoffSymbol symbol = new CoffSymbol(reader, this);
				_symbols.add(symbol);
				i += symbol.getAuxiliaryCount();
			}
		}
		finally {
			reader.setPointerIndex(originalIndex);
		}
	}

	/**
	 * Returns the sections in this COFF header.
	 * @return the sections in this COFF header
	 */
	public List<CoffSectionHeader> getSections() {
		return _sections;
	}

	/**
	 * Returns the symbols in this COFF header.
	 * @return the symbols in this COFF header
	 */
	public List<CoffSymbol> getSymbols() {
		return _symbols;
	}

	public CoffSymbol getSymbolAtIndex(long index) {
		int actualIndex = 0;
		for (CoffSymbol symbol : _symbols) {
			if (actualIndex == index) {
				return symbol;
			}
			++actualIndex;
			for (CoffSymbolAux auxSymbol : symbol.getAuxiliarySymbols()) {
				if (auxSymbol == null) {
					//return auxSymbol;
				}
				++actualIndex;
			}
		}
		return null;
	}

	/**
	 * Returns the size (in bytes) of this COFF file header.
	 * @return the size (in bytes) of this COFF file header
	 */
	public int sizeof() {
		if (isCoffLevelOneOrTwo()) {
			return 22;
		}
		return 20;
	}

	/**
	 * Returns the a.out optional header.
	 * This return value may be null.
	 * @return the a.out optional header
	 */
	public AoutHeader getOptionalHeader() {
		return _aoutHeader;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(getClass()), 0);
		struct.add(WORD, "f_magic", null);
		struct.add(WORD, "f_nscns", null);
		struct.add(DWORD, "f_timdat", null);
		struct.add(DWORD, "f_symptr", null);
		struct.add(DWORD, "f_nsyms", null);
		struct.add(WORD, "f_opthdr", null);
		struct.add(WORD, "f_flags", null);
		if (isCoffLevelOneOrTwo()) {
			struct.add(WORD, "f_target_id", null);
		}
		return struct;
	}
}
