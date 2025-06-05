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
package ghidra.app.util.bin.format.plan9aout;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Plan9AoutProgramLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

public class Plan9AoutSymbolTable implements Iterable<Plan9AoutSymbol>, StructConverter {
	private final long fileSize;
	private final int pointerSize;
	private List<Plan9AoutSymbol> symbols;
	private Map<Long,String> files;

	public Plan9AoutSymbolTable(BinaryReader reader, long fileOffset, long fileSize, int pointerSize,
			Plan9AoutStringTable strtab, MessageLog log) throws IOException {
		this.fileSize = fileSize;
		this.pointerSize = pointerSize;
		this.symbols = new ArrayList<>();
		files = new HashMap<>();

		reader.setPointerIndex(fileOffset);
		int idx = 0;

		// read each symbol table entry
		while (reader.getPointerIndex() < (fileOffset + fileSize)) {
			long value = reader.readNextUnsignedValue(pointerSize);
			byte typeByte = reader.readNextByte();
			String name = reader.readNextUtf8String();
			if (name.isEmpty())
				name = reader.readNextUnicodeString();

			Plan9AoutSymbol symbol = new Plan9AoutSymbol(name, typeByte, value);
			switch (symbol.type) {
			case Plan9AoutSymbol.SymbolType.N_FILE:
				files.put(symbol.value, symbol.name);
				break;
			case Plan9AoutSymbol.SymbolType.UNKNOWN:
				log.appendMsg(Plan9AoutProgramLoader.dot_symtab,
					String.format("Unknown symbol type 0x%02x at symbol index %d", typeByte, idx));
			}
			symbols.add(symbol);

			idx++;
		}
	}

	@Override
	public Iterator<Plan9AoutSymbol> iterator() {
		return symbols.iterator();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// no uniform structure to be applied
		return null;
	}

	public Plan9AoutSymbol get(int symbolNum) {
		return symbols.get(symbolNum);
	}

	public long size() {
		return symbols.size();
	}

	public void markup(Program program, MemoryBlock block)
			throws CodeUnitInsertionException, DuplicateNameException, InvalidNameException, IOException {
		Listing listing = program.getListing();
		DataTypeManager dtmanager = program.getDataTypeManager();

		DataType mword = (pointerSize == 8 ? QWORD : DWORD).clone(null);
		DataType termUniBE = TerminatedUnicodeDataType.dataType.clone(null);
		mword.setName("PWORD_BE");
		termUniBE.setName("TerminatedUnicodeBE");
		mword = dtmanager.addDataType(mword, DataTypeConflictHandler.DEFAULT_HANDLER);
		mword.getDefaultSettings().setLong("endian", EndianSettingsDefinition.BIG);
		termUniBE = dtmanager.addDataType(termUniBE, DataTypeConflictHandler.DEFAULT_HANDLER);
		termUniBE.getDefaultSettings().setLong("endian", EndianSettingsDefinition.BIG);

		Address addr = block.getStart();

		int idx = 0;
		for (Plan9AoutSymbol symbol : this) {
			Data valData = listing.createData(addr, mword);
			addr = addr.add(valData.getLength());
			Data typeData = listing.createData(addr, BYTE);
			addr = addr.add(typeData.getLength());
			Data str = listing.createData(addr, TerminatedStringDataType.dataType);
			addr = addr.add(str.getLength());
			if (str.getLength() == 1) {
				Data ustr = listing.createData(addr, termUniBE);
				addr = addr.add(ustr.getLength());
			}
			switch (symbol.type) {
				case N_PATH:
					if (!StringUtils.isBlank(symbol.name)) {
						String comm = symbol.name.codePoints()
							.mapToObj(file -> files.getOrDefault((long)file, "(invalid)"))
							.collect(Collectors.joining("/"));
						valData.setComment(CommentType.EOL, comm);
					}
					break;
				default:
					if (!StringUtils.isBlank(symbol.name)) {
						valData.setComment(CommentType.EOL, symbol.name);
					}
			}

			idx++;
		}
	}
}
