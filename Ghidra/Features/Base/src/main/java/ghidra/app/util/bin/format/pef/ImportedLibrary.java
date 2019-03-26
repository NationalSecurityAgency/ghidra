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

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Imported Libraries
 * 
 * See Apple's -- PEFBinaryFormat.h
 * <pre>
 * struct PEFImportedLibrary {
 *   UInt32              nameOffset;             // Loader string table offset of library's name.
 *   UInt32              oldImpVersion;          // Oldest compatible implementation version.
 *   UInt32              currentVersion;         // Current version at build time.
 *   UInt32              importedSymbolCount;    // Imported symbol count for this library.
 *   UInt32              firstImportedSymbol;    // Index of first imported symbol from this library.
 *   UInt8               options;                // Option bits for this library.
 *   UInt8               reservedA;              // Reserved, must be zero.
 *   UInt16              reservedB;              // Reserved, must be zero.
 * };
 * </pre>
 */
public class ImportedLibrary implements StructConverter {
	public final static int SIZEOF = 24;

	/** The imported library is allowed to be missing. */
	public final static int OPTION_kPEFWeakImportLibMask  = 0x40;
	/** The imported library must be initialized first. */
	public final static int OPTION_kPEFInitLibBeforeMask  = 0x80;


	private int   nameOffset;
	private int   oldImpVersion;
	private int   currentVersion;
	private int   importedSymbolCount;
	private int   firstImportedSymbol;
	private byte  options;
	private byte  reservedA;
	private short reservedB;

	private String _name;

	ImportedLibrary(BinaryReader reader, LoaderInfoHeader loader) throws IOException {
		nameOffset           = reader.readNextInt();
		oldImpVersion        = reader.readNextInt();
		currentVersion       = reader.readNextInt();
		importedSymbolCount  = reader.readNextInt();
		firstImportedSymbol  = reader.readNextInt();
		options              = reader.readNextByte();
		reservedA            = reader.readNextByte();
		reservedB            = reader.readNextShort();

		long offset = loader.getSection().getContainerOffset()+loader.getLoaderStringsOffset()+nameOffset;
		_name = reader.readAsciiString(offset);
	}

	/**
	 * Returns the name of the library being imported.
	 * @return the name of the library being imported
	 */
	public String getName() {
		return _name;
	}
	/**
	 * The nameOffset field (4 bytes) indicates the offset (in bytes) from the beginning 
	 * of the loader string table to the start of the null-terminated library name.
	 * @return loader string table offset of library's name.
	 */
	public int getNameOffset() {
		return nameOffset;
	}
	/**
	 * The oldImpVersion and currentVersion fields (4 bytes each) provide version 
	 * information for checking the compatibility of the imported library.
	 * @return oldest compatible implementation version
	 */
	public int getOldImpVersion() {
		return oldImpVersion;
	}
	/**
	 * The oldImpVersion and currentVersion fields (4 bytes each) provide version 
	 * information for checking the compatibility of the imported library.
	 * @return current version at build time
	 */
	public int getCurrentVersion() {
		return currentVersion;
	}
	/**
	 * The importedSymbolCount field (4 bytes) indicates the number of symbols 
	 * imported from this library.
	 * @return imported symbol count for this library
	 */
	public int getImportedSymbolCount() {
		return importedSymbolCount;
	}
	/**
	 * The firstImportedSymbol field (4 bytes) holds the (zero-based) index of the 
	 * first entry in the imported symbol table for this library.
	 * @return index of first imported symbol from this library
	 */
	public int getFirstImportedSymbol() {
		return firstImportedSymbol;
	}
	/**
	 * The options byte contains bit flag information as follows:
	 * <p>
	 * The high-order bit (mask 0x80) controls the order that the import libraries 
	 * are initialized. If set to 0, the default initialization order is used, which 
	 * specifies that the Code Fragment Manager should try to initialize the 
	 * import library before the fragment that imports it. When set to 1, the import 
	 * library must be initialized before the client fragment.
	 * <p>
	 * The next bit (mask 0x40) controls whether the import library is weak. 
	 * When set to 1 (weak import), the Code Fragment Manager continues 
	 * preparation of the client fragment (and does not generate an error) even if 
	 * the import library cannot be found. If the import library is not found, all 
	 * imported symbols from that library have their addresses set to 0. You can 
	 * use this information to determine whether a weak import library is actually 
	 * present.
	 * 
	 * @return option bits for this library
	 */
	public byte getOptions() {
		return options;
	}
	/**
	 * Reserved, must be set to zero (0).
	 * @return reserved, must be set to zero (0)
	 */
	public byte getReservedA() {
		return reservedA;
	}
	/**
	 * Reserved, must be set to zero (0).
	 * @return reserved, must be set to zero (0)
	 */
	public short getReservedB() {
		return reservedB;
	}

	@Override
	public String toString() {
		return _name;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
