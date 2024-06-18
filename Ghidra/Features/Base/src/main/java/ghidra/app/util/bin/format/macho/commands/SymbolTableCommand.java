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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a symtab_command structure
 */
public class SymbolTableCommand extends LoadCommand {
	private int symoff;
	private int nsyms;
	private int stroff;
	private int strsize;

	private List<NList> symbols = new ArrayList<NList>();

	/**
	 * Creates and parses a new {@link SymbolTableCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @param header The {@link MachHeader header} associated with this load command
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	public SymbolTableCommand(BinaryReader loadCommandReader, BinaryReader dataReader,
			MachHeader header) throws IOException {
		super(loadCommandReader);

		symoff = loadCommandReader.readNextInt();
		nsyms = loadCommandReader.readNextInt();
		stroff = loadCommandReader.readNextInt();
		strsize = loadCommandReader.readNextInt();

		List<NList> nlistList = new ArrayList<>(nsyms);
		dataReader.setPointerIndex(header.getStartIndex() + symoff);
		for (int i = 0; i < nsyms; ++i) {
			nlistList.add(new NList(dataReader, header.is32bit()));
		}
		
		// sort the entries by the index in the string table, so don't jump around reading
		List<NList> sortedList =
			nlistList.stream().sorted((o1, o2) -> Integer.compare(o1.getStringTableIndex(),
				o2.getStringTableIndex())).collect(Collectors.toList());
		
		// initialize the sorted NList strings from string table
		for (NList nList : sortedList) {
			nList.initString(dataReader, stroff);
		}
		
		// the symbol table should be in the original order.
		// The table is indexed by other tables in the MachO headers
		symbols = nlistList;
	}

	/**
	 * An integer containing the byte offset from the start
	 * of the file to the location of the symbol table entries.
	 * The symbol table is an array of nlist data structures.
	 * @return symbol table offset
	 */
	public int getSymbolOffset() {
		return symoff;
	}

	/**
	 * An integer indicating the number of entries in the symbol table.
	 * @return the number of entries in the symbol table
	 */
	public int getNumberOfSymbols() {
		return nsyms;
	}

	/**
	 * An integer containing the byte offset from the start of the image to the
	 * location of the string table.
	 * @return string table offset
	 */
	public int getStringTableOffset() {
		return stroff;
	}

	/**
	 * An integer indicating the size (in bytes) of the string table.
	 * @return string table size in bytes
	 */
	public int getStringTableSize() {
		return strsize;
	}

	public List<NList> getSymbols() {
		return symbols;
	}

	/**
	 * Adds the given {@link List} of {@link NList}s to this symbol/string table, and adjusts the
	 * affected symbol table load command fields appropriately
	 * 
	 * @param list The {@link List} of {@link NList}s to add
	 */
	public void addSymbols(List<NList> list) {
		if (list.isEmpty()) {
			return;
		}
		symbols.addAll(list);
		nsyms += list.size();
		stroff += list.size() * list.get(0).getSize();
		strsize = symbols.stream().mapToInt(e -> e.getString().length() + 1).sum();
	}

	public NList getSymbolAt(int index) {
		if ((index & DynamicSymbolTableConstants.INDIRECT_SYMBOL_LOCAL) != 0 ||
			(index & DynamicSymbolTableConstants.INDIRECT_SYMBOL_ABS) != 0) {
			return null;
		}
		if (index > symbols.size()) {
			return null;
		}
		return symbols.get(index);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "symoff", null);
		struct.add(DWORD, "nsyms", null);
		struct.add(DWORD, "stroff", null);
		struct.add(DWORD, "strsize", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "symtab_command";
	}

	@Override
	public int getLinkerDataOffset() {
		return symoff;
	}

	@Override
	public int getLinkerDataSize() {
		return NList.getSize(symbols);
	}

	@Override
	public void markup(Program program, MachHeader header, String source, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Address symbolTableAddr = fileOffsetToAddress(program, header, symoff, nsyms);
		if (symbolTableAddr == null) {
			return;
		}
		Address stringTableAddr = fileOffsetToAddress(program, header, stroff, strsize);

		markupPlateComment(program, symbolTableAddr, source, "symbols");
		markupPlateComment(program, stringTableAddr, source, "strings");

		ReferenceManager referenceManager = program.getReferenceManager();
		try {
			for (int i = 0; i < nsyms; i++) {
				NList nlist = symbols.get(i);
				DataType dt = nlist.toDataType();
				Address nlistAddr = symbolTableAddr.add(i * dt.getLength());
				Data d = DataUtilities.createData(program, nlistAddr, dt, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

				if (stringTableAddr != null && nlist.getStringTableIndex() != 0) {
					Address strAddr = stringTableAddr.add(nlist.getStringTableIndex());
					DataUtilities.createData(program, strAddr, STRING, -1,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					Reference ref = referenceManager.addMemoryReference(d.getMinAddress(), strAddr,
						RefType.DATA, SourceType.IMPORTED, 0);
					referenceManager.setPrimary(ref, true);
				}
			}

		}
		catch (Exception e) {
			log.appendMsg(SymbolTableCommand.class.getSimpleName(),
				"Failed to markup: " + getContextualName(source, "symbols"));
		}
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			if (getStringTableSize() > 0) {
				Address stringTableStart = baseAddress.getNewAddress(getStringTableOffset());
				api.createFragment(parentModule, "string_table", stringTableStart,
					getStringTableSize());
			}

			int symbolIndex = 0;
			Address symbolStartAddr = baseAddress.getNewAddress(getSymbolOffset());
			long offset = 0;
			for (NList symbol : symbols) {
				if (monitor.isCancelled()) {
					return;
				}

				DataType symbolDT = symbol.toDataType();
				Address symbolAddr = symbolStartAddr.add(offset);
				Data symbolData = api.createData(symbolAddr, symbolDT);

				Address stringAddress = baseAddress.getNewAddress(
					getStringTableOffset() + symbol.getStringTableIndex());
				Data stringData = api.createAsciiString(stringAddress);
				String string = (String) stringData.getValue();

				Reference ref =
					api.createMemoryReference(symbolData, stringAddress, RefType.DATA);
				api.setReferencePrimary(ref, false);

				api.setPlateComment(symbolAddr,
					string + "\n" + "Index:           0x" + Integer.toHexString(symbolIndex) +
						"\n" + "Value:           0x" + Long.toHexString(symbol.getValue()) +
						"\n" + "Description:     0x" +
						Long.toHexString(symbol.getDescription() & 0xffff) + "\n" +
						"Library Ordinal: 0x" +
						Long.toHexString(symbol.getLibraryOrdinal() & 0xff));

				offset += symbolDT.getLength();
				++symbolIndex;
			}

			if (getNumberOfSymbols() > 0) {
				api.createFragment(parentModule, "symbols", symbolStartAddr, offset);
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}
}
