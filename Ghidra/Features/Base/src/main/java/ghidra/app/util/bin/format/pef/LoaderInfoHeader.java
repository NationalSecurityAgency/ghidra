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
 * <pre>{@literal
 * struct PEFLoaderInfoHeader {
 *     SInt32  mainSection;              // Section containing the main symbol, -1 => none.
 *     UInt32  mainOffset;               // Offset of main symbol.
 *     SInt32  initSection;              // Section containing the init routine's TVector, -1 => none.
 *     UInt32  initOffset;               // Offset of the init routine's TVector.
 *     SInt32  termSection;              // Section containing the term routine's TVector, -1 => none.
 *     UInt32  termOffset;               // Offset of the term routine's TVector.
 *     UInt32  importedLibraryCount;     // Number of imported libraries.  ('l')
 *     UInt32  totalImportedSymbolCount; // Total number of imported symbols.  ('i')
 *     UInt32  relocSectionCount;        // Number of sections with relocations.  ('r')
 *     UInt32  relocInstrOffset;         // Offset of the relocation instructions.
 *     UInt32  loaderStringsOffset;      // Offset of the loader string table.
 *     UInt32  exportHashOffset;         // Offset of the export hash table.
 *     UInt32  exportHashTablePower;     // Export hash table size as log 2.  (Log2('h'))
 *     UInt32  exportedSymbolCount;      // Number of exported symbols.  ('e')
 * };
 * }</pre>
 */
public class LoaderInfoHeader implements StructConverter {
	public final static int SIZEOF = 56;

	private SectionHeader _section;

	private int mainSection;
	private int mainOffset;
	private int initSection;
	private int initOffset;
	private int termSection;
	private int termOffset;
	private int importedLibraryCount;
	private int totalImportedSymbolCount;
	private int relocSectionCount;
	private int relocInstrOffset;
	private int loaderStringsOffset;
	private int exportHashOffset;
	private int exportHashTablePower;
	private int exportedSymbolCount;

	private List<ImportedLibrary>         _importedLibraries = new ArrayList<ImportedLibrary>();
	private List<ImportedSymbol>            _importedSymbols = new ArrayList<ImportedSymbol>();
	private List<LoaderRelocationHeader>        _relocations = new ArrayList<LoaderRelocationHeader>();
	private List<ExportedSymbolHashSlot>  _exportedHashSlots = new ArrayList<ExportedSymbolHashSlot>();
	private List<ExportedSymbolKey>      _exportedSymbolKeys = new ArrayList<ExportedSymbolKey>();
	private List<ExportedSymbol>            _exportedSymbols = new ArrayList<ExportedSymbol>();

	LoaderInfoHeader(BinaryReader reader, SectionHeader section) throws IOException {
		this._section = section;

		long oldIndex = reader.getPointerIndex();
		try {
			reader.setPointerIndex(section.getContainerOffset());

			mainSection               = reader.readNextInt();
			mainOffset                = reader.readNextInt();
			initSection               = reader.readNextInt();
			initOffset                = reader.readNextInt();
			termSection               = reader.readNextInt();
			termOffset                = reader.readNextInt();
			importedLibraryCount      = reader.readNextInt();
			totalImportedSymbolCount  = reader.readNextInt();
			relocSectionCount         = reader.readNextInt();
			relocInstrOffset          = reader.readNextInt();
			loaderStringsOffset       = reader.readNextInt();
			exportHashOffset          = reader.readNextInt();
			exportHashTablePower      = reader.readNextInt();
			exportedSymbolCount       = reader.readNextInt();

			for (int i = 0 ; i< importedLibraryCount ; ++i) {
				_importedLibraries.add(new ImportedLibrary(reader, this));
			}
			for (int i = 0 ; i< totalImportedSymbolCount ; ++i) {
				_importedSymbols.add(new ImportedSymbol(reader, this));
			}

			for (int i = 0 ; i< relocSectionCount ; ++i) {
				_relocations.add(new LoaderRelocationHeader(reader, this));
			}

			int exportIndex = section.getContainerOffset() + exportHashOffset;
			reader.setPointerIndex(exportIndex);

			int nExported = (int)Math.pow(2, exportHashTablePower);
			for (int i = 0 ; i< nExported ; ++i) {
				_exportedHashSlots.add(new ExportedSymbolHashSlot(reader));
			}
			for (int i = 0 ; i< exportedSymbolCount ; ++i) {
				_exportedSymbolKeys.add(new ExportedSymbolKey(reader));
			}
			for (int i = 0 ; i< exportedSymbolCount ; ++i) {
				_exportedSymbols.add(new ExportedSymbol(reader, this, _exportedSymbolKeys.get(i)));
			}
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	/**
	 * The mainSection field (4 bytes) specifies the number 
	 * of the section in this container that contains the main 
	 * symbol. If the fragment does not have a main symbol, 
	 * this field is set to -1.
	 * @return number of section containing main symbol
	 */
	public int getMainSection() {
		return mainSection;
	}
	/**
	 * The mainOffset field (4 bytes) indicates the offset (in bytes) from the 
	 * beginning of the section to the main symbol.
	 * @return offset to the main symbol
	 */
	public int getMainOffset() {
		return mainOffset;
	}
	/**
	 * The initSection field (4 bytes) contains the number of the 
	 * section containing the initialization function's transition 
	 * vector. If no initialization function exists, this field is set to -1.
	 * @return  number of the section containing the initialization function's transition vector
	 */
	public int getInitSection() {
		return initSection;
	}
	/**
	 * The initOffset field (4 bytes) indicates the offset (in bytes) from the 
	 * beginning of the section to the initialization function's transition vector.
	 * @return offset to initialization function's transition vector
	 */
	public int getInitOffset() {
		return initOffset;
	}
	/**
	 * The termSection field (4 bytes) contains the number of the section containing 
	 * the termination routine's transition vector. If no termination routine exists, 
	 * this field is set to -1.
	 * @return number of the section containing the termination routine's transition vector
	 */
	public int getTermSection() {
		return termSection;
	}
	/**
	 * The termOffset field (4 bytes) indicates the offset 
	 * (in bytes) from the beginning of the section to the termination routine's 
	 * transition vector.
	 * @return offset to termination routine's transition vector
	 */
	public int getTermOffset() {
		return termOffset;
	}
	/**
	 * The importedLibraryCount field (4 bytes) indicates the 
	 * number of imported libraries.
	 * @return number of imported libraries
	 */
	public int getImportedLibraryCount() {
		return importedLibraryCount;
	}
	/**
	 * The totalImportedSymbolCount field (4 bytes) 
	 * indicates the total number of imported symbols.
	 * @return number of imported symbols
	 */
	public int getTotalImportedSymbolCount() {
		return totalImportedSymbolCount;
	}
	/**
	 * The relocSectionCount field (4 bytes) indicates the 
	 * number of sections containing load-time relocations.
	 * @return number of sections containing load-time relocations
	 */
	public int getRelocSectionCount() {
		return relocSectionCount;
	}
	/**
	 * The relocInstrOffset field (4 bytes) indicates the offset (in bytes) from the 
	 * beginning of the loader section to the start of the relocations area.
	 * @return offset to the relocations
	 */
	public int getRelocInstrOffset() {
		return relocInstrOffset;
	}
	/**
	 * The loaderStringsOffset field (4 bytes) indicates the offset 
	 * (in bytes) from the beginning of the loader 
	 * section to the start of the loader string table.
	 * @return offset to the loader string table
	 */
	public int getLoaderStringsOffset() {
		return loaderStringsOffset;
	}
	/**
	 * The exportHashOffset field (4 bytes) indicates the offset 
	 * (in bytes) from the beginning of the loader section 
	 * to the start of the export hash table. The hash table should be 4-byte aligned 
	 * with padding added if necessary.
	 * @return offset to the export hash table
	 */
	public int getExportHashOffset() {
		return exportHashOffset;
	}
	/**
	 * The exportHashTablePower field (4 bytes) indicates the 
	 * number of hash index values (that is, the number of entries in the 
	 * hash table). The number of entries is specified as a power of two. For example, 
	 * a value of 0 indicates one entry, while a value of 2 indicates four entries. If 
	 * no exports exist, the hash table still contains one entry, and the value of this 
	 * field is 0.
	 * @return number of hash index values
	 */
	public int getExportHashTablePower() {
		return exportHashTablePower;
	}
	/**
	 * The exportedSymbolCount field (4 bytes) indicates the number of 
	 * symbols exported from this container.
	 * @return number of symbols exported from this container
	 */
	public int getExportedSymbolCount() {
		return exportedSymbolCount;
	}

	/**
	 * Returns the section corresponding to this loader.
	 * @return the section corresponding to this loader
	 */
	public SectionHeader getSection() {
		return _section;
	}

	/**
	 * Finds the PEF library that contains the specified imported symbol index.
	 * @param symbolIndex the imported symbol index
	 * @return PEF library that contains the specified imported symbol index
	 */
	public ImportedLibrary findLibrary(int symbolIndex) {
		for (ImportedLibrary library : _importedLibraries) {
			if (symbolIndex >= library.getFirstImportedSymbol() &&
				symbolIndex < library.getFirstImportedSymbol()+library.getImportedSymbolCount()) {
				return library;
			}
		}
		return null;
	}

	public List<ImportedLibrary> getImportedLibraries() {
		return _importedLibraries;
	}
	public List<ImportedSymbol> getImportedSymbols() {
		return _importedSymbols;
	}
	public List<LoaderRelocationHeader> getRelocations() {
		return _relocations;
	}
	public List<ExportedSymbolHashSlot> getExportedHashSlots() {
		return _exportedHashSlots;
	}
	public List<ExportedSymbolKey> getExportedSymbolKeys() {
		return _exportedSymbolKeys;
	}
	public List<ExportedSymbol> getExportedSymbols() {
		return _exportedSymbols;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
