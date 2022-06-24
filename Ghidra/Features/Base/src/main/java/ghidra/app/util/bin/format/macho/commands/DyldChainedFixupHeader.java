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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_fixups_header structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/fixup-chains.h.auto.html">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedFixupHeader implements StructConverter {

	private int fixups_version;    // 0
	private int starts_offset;     // offset of dyld_chained_starts_in_image in chain_data
	private int imports_offset;    // offset of imports table in chain_data
	private int symbols_offset;    // offset of symbol strings in chain_data
	private int imports_count;     // number of imported symbol names
	private int imports_format;    // DYLD_CHAINED_IMPORT*
	private int symbols_format;    // 0 => uncompressed, 1 => zlib compressed

	DyldChainedStartsInImage chainedStartsInImage;
	DyldChainedImports chainedImports;

	DyldChainedFixupHeader(BinaryReader reader) throws IOException {
		long ptrIndex = reader.getPointerIndex();

		fixups_version = reader.readNextInt();
		starts_offset = reader.readNextInt();
		imports_offset = reader.readNextInt();
		symbols_offset = reader.readNextInt();
		imports_count = reader.readNextInt();
		imports_format = reader.readNextInt();
		symbols_format = reader.readNextInt();

		reader.setPointerIndex(ptrIndex + starts_offset);
		chainedStartsInImage = new DyldChainedStartsInImage(reader);

		reader.setPointerIndex(ptrIndex + imports_offset);
		chainedImports = new DyldChainedImports(reader, this);

		reader.setPointerIndex(ptrIndex + symbols_offset);
		chainedImports.initSymbols(reader, this);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_fixups_header", 0);
		struct.add(DWORD, "fixups_version", null);
		struct.add(DWORD, "starts_offset", null);
		struct.add(DWORD, "imports_offset", null);
		struct.add(DWORD, "symbols_offset", null);
		struct.add(DWORD, "imports_count", null);
		struct.add(DWORD, "imports_format", null);
		struct.add(DWORD, "symbols_format", null);

		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getFixups_version() {
		return fixups_version;
	}

	public int getStarts_offset() {
		return starts_offset;
	}

	public int getImports_offset() {
		return imports_offset;
	}

	public int getSymbols_offset() {
		return symbols_offset;
	}

	public int getImports_count() {
		return imports_count;
	}

	public int getImports_format() {
		return imports_format;
	}

	public int getSymbols_format() {
		return symbols_format;
	}

	public boolean isCompress() {
		return symbols_format != 0;
	}

	public DyldChainedStartsInImage getChainedStartsInImage() {
		return chainedStartsInImage;
	}

	public DyldChainedImports getChainedImports() {
		return chainedImports;
	}
}
