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
package ghidra.app.util.bin.format.unixaout;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.UnixAoutProgramLoader;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

public class UnixAoutSymbolTable implements Iterable<UnixAoutSymbol>, StructConverter {
	private static final int ENTRY_SIZE = 12;

	private final long fileSize;
	private List<UnixAoutSymbol> symbols;

	public UnixAoutSymbolTable(BinaryReader reader, long fileOffset, long fileSize,
			UnixAoutStringTable strtab, MessageLog log) throws IOException {
		this.fileSize = fileSize;
		this.symbols = new ArrayList<>();

		reader.setPointerIndex(fileOffset);
		int idx = 0;

		// read each symbol table entry
		while (reader.getPointerIndex() < (fileOffset + fileSize)) {
			long strOffset = reader.readNextUnsignedInt();
			byte typeByte = reader.readNextByte();
			byte otherByte = reader.readNextByte();
			short desc = reader.readNextShort();
			long value = reader.readNextUnsignedInt();

			UnixAoutSymbol symbol = new UnixAoutSymbol(strOffset, typeByte, otherByte, desc, value);
			if (symbol.type == UnixAoutSymbol.SymbolType.UNKNOWN) {
				log.appendMsg(UnixAoutProgramLoader.dot_symtab,
					String.format("Unknown symbol type 0x%02x at symbol index %d", typeByte, idx));
			}
			symbols.add(symbol);

			idx++;
		}

		// lookup and set each string table symbol name
		for (UnixAoutSymbol symbol : this) {
			symbol.name = strtab.readString(symbol.nameStringOffset);
		}
	}

	@Override
	public Iterator<UnixAoutSymbol> iterator() {
		return symbols.iterator();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String dtName = "nlist";
		Structure struct = new StructureDataType(new CategoryPath("/AOUT"), dtName, 0);
		struct.add(DWORD, "n_strx", null);
		struct.add(BYTE, "n_type", null);
		struct.add(BYTE, "n_other", null);
		struct.add(WORD, "n_desc", null);
		struct.add(DWORD, "n_value", null);
		return new ArrayDataType(struct, (int) (fileSize / ENTRY_SIZE), ENTRY_SIZE);
	}

	public UnixAoutSymbol get(int symbolNum) {
		return symbols.get(symbolNum);
	}

	public long size() {
		return symbols.size();
	}

	public void markup(Program program, MemoryBlock block)
			throws CodeUnitInsertionException, DuplicateNameException, IOException {
		Listing listing = program.getListing();
		Data array = listing.createData(block.getStart(), toDataType());

		int idx = 0;
		for (UnixAoutSymbol symbol : this) {
			if (!StringUtils.isBlank(symbol.name)) {
				Data structData = array.getComponent(idx);

				if (structData != null) {
					structData.setComment(CommentType.EOL, symbol.name);
				}
			}

			idx++;
		}
	}
}
