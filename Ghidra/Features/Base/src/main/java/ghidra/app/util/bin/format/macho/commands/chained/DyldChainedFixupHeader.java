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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_fixups_header structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedFixupHeader implements StructConverter {

	private int fixupsVersion;
	private int startsOffset;
	private int importsOffset;
	private int symbolsOffset;
	private int importsCount;
	private int importsFormat;
	private int symbolsFormat;

	private DyldChainedStartsInImage chainedStartsInImage;
	private DyldChainedImports chainedImports;

	/**
	 * Creates a new {@link DyldChainedFixupHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public DyldChainedFixupHeader(BinaryReader reader) throws IOException {
		long ptrIndex = reader.getPointerIndex();

		fixupsVersion = reader.readNextInt();
		startsOffset = reader.readNextInt();
		importsOffset = reader.readNextInt();
		symbolsOffset = reader.readNextInt();
		importsCount = reader.readNextInt();
		importsFormat = reader.readNextInt();
		symbolsFormat = reader.readNextInt();

		reader.setPointerIndex(ptrIndex + startsOffset);
		chainedStartsInImage = new DyldChainedStartsInImage(reader);

		reader.setPointerIndex(ptrIndex + importsOffset);
		chainedImports = new DyldChainedImports(reader, this);

		reader.setPointerIndex(ptrIndex + symbolsOffset);
		chainedImports.initSymbols(reader, this);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_fixups_header", 0);
		struct.add(DWORD, "fixups_version", "0");
		struct.add(DWORD, "starts_offset", "offset of dyld_chained_starts_in_image in chain_data");
		struct.add(DWORD, "imports_offset", "offset of imports table in chain_data");
		struct.add(DWORD, "symbols_offset", "offset of symbol strings in chain_data");
		struct.add(DWORD, "imports_count", "number of imported symbol names");
		struct.add(DWORD, "imports_format", "DYLD_CHAINED_IMPORT*");
		struct.add(DWORD, "symbols_format", "0 => uncompressed, 1 => zlib compressed");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getFixupsVersion() {
		return fixupsVersion;
	}

	public int getStartsOffset() {
		return startsOffset;
	}

	public int getImportsOffset() {
		return importsOffset;
	}

	public int getSymbolsOffset() {
		return symbolsOffset;
	}

	public int getImportsCount() {
		return importsCount;
	}

	public int getImportsFormat() {
		return importsFormat;
	}

	public int getSymbolsFormat() {
		return symbolsFormat;
	}

	public boolean isCompress() {
		return symbolsFormat != 0;
	}

	public DyldChainedStartsInImage getChainedStartsInImage() {
		return chainedStartsInImage;
	}

	public DyldChainedImports getChainedImports() {
		return chainedImports;
	}
}
