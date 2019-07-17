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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * See Apple's -- PEFBinaryFormat.h
 * <pre>
 * struct PEFExportedSymbol { //! This structure is 10 bytes long and arrays are packed.
 *     UInt32  classAndName;  //A combination of class and name offset.
 *     UInt32  symbolValue;   //Typically the symbol's offset within a section.
 *     SInt16  sectionIndex;  //The index of the section, or pseudo-section, for the symbol.
 * };
 * </pre>
 */
public class ExportedSymbol extends AbstractSymbol {
	public static final int kPEFExpSymClassShift = 24;

	/*
	 * Negative section indices indicate pseudo-sections.
	 */

	/** The symbol value is an absolute address.*/
	public static final int kPEFAbsoluteExport   = -2;
	/** The symbol value is the index of a reexported import.*/
	public static final int kPEFReexportedImport = -3;

	private int   classAndName;
	private int   symbolValue;
	private short sectionIndex;

	private String _name;

	ExportedSymbol(BinaryReader reader, LoaderInfoHeader loader, ExportedSymbolKey key) throws IOException {
		classAndName = reader.readNextInt();
		symbolValue  = reader.readNextInt();
		sectionIndex = reader.readNextShort();

		long offset = loader.getSection().getContainerOffset()+loader.getLoaderStringsOffset()+getNameOffset();
		_name = reader.readAsciiString(offset, key.getNameLength()); 
	}

	@Override
	public String getName() {
		return _name;
	}
	@Override
	public SymbolClass getSymbolClass() {
		return SymbolClass.get(classAndName >> kPEFExpSymClassShift);
	}
	/**
	 * Returns offset of symbol name in loader string table.  
	 * @return offset of symbol name in loader string table  
	 */
	public int getNameOffset() {
		return classAndName & 0x00ffffff;
	}
	/**
	 * Typically the symbol's offset within a section.
	 * @return the symbol's offset within a section
	 */
	public int getSymbolValue() {
		return symbolValue;
	}
	/**
	 * Returns the index of the section, or pseudo-section, for the symbol.
	 * @return the index of the section, or pseudo-section, for the symbol
	 */
	public short getSectionIndex() {
		return sectionIndex;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
