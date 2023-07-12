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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dysymtab_command structure.
 */
public class DynamicSymbolTableCommand extends LoadCommand {

	private int ilocalsym;
	private int nlocalsym;
	private int iextdefsym;
	private int nextdefsym;
	private int iundefsym;
	private int nundefsym;
	private int tocoff;
	private int ntoc;
	private int modtaboff;
	private int nmodtab;
	private int extrefsymoff;
	private int nextrefsyms;
	private int indirectsymoff;
	private int nindirectsyms;
	private int extreloff;
	private int nextrel;
	private int locreloff;
	private int nlocrel;

	private List<TableOfContents> tocList = new ArrayList<TableOfContents>();
	private List<DynamicLibraryModule> moduleList = new ArrayList<DynamicLibraryModule>();
	private List<DynamicLibraryReference> referencedList = new ArrayList<DynamicLibraryReference>();
	private int[] indirectSymbols = new int[0];
	private List<RelocationInfo> externalRelocations = new ArrayList<RelocationInfo>();
	private List<RelocationInfo> localRelocations = new ArrayList<RelocationInfo>();

	/**
	 * Creates and parses a new {@link DynamicSymbolTableCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @param header The {@link MachHeader header} associated with this load command
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	DynamicSymbolTableCommand(BinaryReader loadCommandReader, BinaryReader dataReader,
			MachHeader header) throws IOException {
		super(loadCommandReader);

		ilocalsym = loadCommandReader.readNextInt();
		nlocalsym = loadCommandReader.readNextInt();
		iextdefsym = loadCommandReader.readNextInt();
		nextdefsym = loadCommandReader.readNextInt();
		iundefsym = loadCommandReader.readNextInt();
		nundefsym = loadCommandReader.readNextInt();
		tocoff = loadCommandReader.readNextInt();
		ntoc = loadCommandReader.readNextInt();
		modtaboff = loadCommandReader.readNextInt();
		nmodtab = loadCommandReader.readNextInt();
		extrefsymoff = loadCommandReader.readNextInt();
		nextrefsyms = loadCommandReader.readNextInt();
		indirectsymoff = loadCommandReader.readNextInt();
		nindirectsyms = loadCommandReader.readNextInt();
		extreloff = loadCommandReader.readNextInt();
		nextrel = loadCommandReader.readNextInt();
		locreloff = loadCommandReader.readNextInt();
		nlocrel = loadCommandReader.readNextInt();

		if (tocoff > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + tocoff);
			for (int i = 0; i < ntoc; ++i) {
				tocList.add(new TableOfContents(dataReader));
			}
		}
		if (modtaboff > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + modtaboff);
			for (int i = 0; i < nmodtab; ++i) {
				moduleList.add(new DynamicLibraryModule(dataReader, header));
			}
		}
		if (extrefsymoff > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + extrefsymoff);
			for (int i = 0; i < nextrefsyms; ++i) {
				referencedList.add(new DynamicLibraryReference(dataReader));
			}
		}
		if (indirectsymoff > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + indirectsymoff);
			indirectSymbols = new int[nindirectsyms];
			for (int i = 0; i < nindirectsyms; ++i) {
				indirectSymbols[i] = dataReader.readNextInt();
			}
		}
		if (extreloff > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + extreloff);
			for (int i = 0; i < nextrel; ++i) {
				externalRelocations.add(new RelocationInfo(dataReader));
			}
		}
		if (locreloff > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + locreloff);
			for (int i = 0; i < nlocrel; ++i) {
				localRelocations.add(new RelocationInfo(dataReader));
			}
		}
	}

	/**
	 * Returns the index of the first local symbol.
	 * @return the index of the first local symbol
	 */
	public int getLocalSymbolIndex() {
		return ilocalsym;
	}

	/**
	 * Returns the total number of local symbols.
	 * @return the total number of local symbols
	 */
	public int getLocalSymbolCount() {
		return nlocalsym;
	}

	/**
	 * Returns the index of the first external symbol.
	 * @return the index of the first external symbol
	 */
	public int getExternalSymbolIndex() {
		return iextdefsym;
	}

	/**
	 * Returns the total number of external symbols.
	 * @return the total number of external symbols
	 */
	public int getExternalSymbolCount() {
		return nextdefsym;
	}

	/**
	 * Returns the index of the first undefined symbol.
	 * @return the index of the first undefined symbol
	 */
	public int getUndefinedSymbolIndex() {
		return iundefsym;
	}

	/**
	 * Returns the total number of undefined symbols.
	 * @return the total number of undefined symbols
	 */
	public int getUndefinedSymbolCount() {
		return nundefsym;
	}

	/**
	 * Returns the byte index from the start of the file to the table of contents (TOC).
	 * @return the byte index of the TOC
	 */
	public int getTableOfContentsOffset() {
		return tocoff;
	}

	/**
	 * Returns the number of entries in the table of contents.
	 * @return the number of entries in the table of contents
	 */
	public int getTableOfContentsSize() {
		return ntoc;
	}

	public List<TableOfContents> getTableOfContentsList() {
		return tocList;
	}

	/**
	 * Returns the byte index from the start of the file to the module table.
	 * @return the byte index of the module table
	 */
	public int getModuleTableOffset() {
		return modtaboff;
	}

	/**
	 * Returns the number of entries in the module table.
	 * @return the number of entries in the module table
	 */
	public int getModuleTableSize() {
		return nmodtab;
	}

	public List<DynamicLibraryModule> getModuleList() {
		return moduleList;
	}

	/**
	 * Returns the byte index from the start of the file to the external reference table.
	 * @return the byte index of the external reference table
	 */
	public int getReferencedSymbolTableOffset() {
		return extrefsymoff;
	}

	/**
	 * Returns the number of entries in the external reference table.
	 * @return the number of entries in the external reference table
	 */
	public int getReferencedSymbolTableSize() {
		return nextrefsyms;
	}

	public List<DynamicLibraryReference> getReferencedSymbolList() {
		return referencedList;
	}

	/**
	 * Returns the byte index from the start of the file to the indirect symbol table.
	 * @return the byte index of the indirect symbol table
	 */
	public int getIndirectSymbolTableOffset() {
		return indirectsymoff;
	}

	/**
	 * Returns the number of entries in the indirect symbol table.
	 * @return the number of entries in the indirect symbol table
	 */
	public int getIndirectSymbolTableSize() {
		return nindirectsyms;
	}

	public int[] getIndirectSymbols() {
		return indirectSymbols;
	}

	/**
	 * Returns the byte index from the start of the file to the external relocation table.
	 * @return the byte index of the external relocation table
	 */
	public int getExternalRelocationOffset() {
		return extreloff;
	}

	/**
	 * Returns the number of entries in the external relocation table.
	 * @return the number of entries in the external relocation table
	 */
	public int getExternalRelocationSize() {
		return nextrel;
	}

	public List<RelocationInfo> getExternalRelocations() {
		return externalRelocations;
	}

	/**
	 * Returns the byte index from the start of the file to the local relocation table.
	 * @return the byte index of the local relocation table
	 */
	public int getLocalRelocationOffset() {
		return locreloff;
	}

	/**
	 * Returns the number of entries in the local relocation table.
	 * @return the number of entries in the local relocation table
	 */
	public int getLocalRelocationSize() {
		return nlocrel;
	}

	public List<RelocationInfo> getLocalRelocations() {
		return localRelocations;
	}

	@Override
	public int getLinkerDataOffset() {
		return indirectsymoff;
	}

	@Override
	public int getLinkerDataSize() {
		return nindirectsyms * Integer.BYTES;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "ilocalsym", null);
		struct.add(DWORD, "nlocalsym", null);
		struct.add(DWORD, "iextdefsym", null);
		struct.add(DWORD, "nextdefsym", null);
		struct.add(DWORD, "iundefsym", null);
		struct.add(DWORD, "nundefsym", null);
		struct.add(DWORD, "tocoff", null);
		struct.add(DWORD, "ntoc", null);
		struct.add(DWORD, "modtaboff", null);
		struct.add(DWORD, "nmodtab", null);
		struct.add(DWORD, "extrefsymoff", null);
		struct.add(DWORD, "nextrefsyms", null);
		struct.add(DWORD, "indirectsymoff", null);
		struct.add(DWORD, "nindirectsyms", null);
		struct.add(DWORD, "extreloff", null);
		struct.add(DWORD, "nextrel", null);
		struct.add(DWORD, "locreloff", null);
		struct.add(DWORD, "nlocrel", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "dysymtab_command";
	}

	@Override
	public Address getDataAddress(MachHeader header, AddressSpace space) {
		if (indirectsymoff != 0 && nindirectsyms != 0) {
			SegmentCommand segment = getContainingSegment(header, indirectsymoff);
			if (segment != null) {
				return space.getAddress(
					segment.getVMaddress() + (indirectsymoff - segment.getFileOffset()));
			}
		}
		return null;
	}

	@Override
	public void markup(Program program, MachHeader header, Address indirectSymbolTableAddr,
			String source, TaskMonitor monitor, MessageLog log) throws CancelledException {
		// TODO: Handle more than just the indirect symbol table
		if (indirectSymbolTableAddr == null) {
			return;
		}
		
		Listing listing = program.getListing();
		ReferenceManager referenceManager = program.getReferenceManager();
		String name = LoadCommandTypes.getLoadCommandName(getCommandType()) + " (indirect)";
		if (source != null) {
			name += " - " + source;
		}
		SymbolTableCommand symbolTable = header.getFirstLoadCommand(SymbolTableCommand.class);
		Address symbolTableAddr = null;
		Address stringTableAddr = null;
		if (symbolTable != null) {
			symbolTableAddr =
				symbolTable.getDataAddress(header, indirectSymbolTableAddr.getAddressSpace());
			if (symbolTable.getStringTableOffset() != 0) {
				stringTableAddr = symbolTableAddr
						.add(symbolTable.getStringTableOffset() - symbolTable.getSymbolOffset());
			}
		}
		try {
			listing.setComment(indirectSymbolTableAddr, CodeUnit.PLATE_COMMENT, name);
			for (int i = 0; i < nindirectsyms; i++) {
				int nlistIndex = indirectSymbols[i];
				Address dataAddr = indirectSymbolTableAddr.add(i * DWORD.getLength());
				DataUtilities.createData(program, dataAddr, DWORD, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				if (symbolTableAddr != null) {
					NList nlist = symbolTable.getSymbolAt(nlistIndex);
					if (nlist == null) {
						continue;
					}
					Reference ref = referenceManager.addMemoryReference(dataAddr,
						symbolTableAddr.add(nlistIndex * nlist.getSize()), RefType.DATA,
						SourceType.IMPORTED, 0);
					referenceManager.setPrimary(ref, true);
					if (stringTableAddr != null) {
						Address strAddr = stringTableAddr.add(nlist.getStringTableIndex());
						referenceManager.addMemoryReference(dataAddr, strAddr, RefType.DATA,
							SourceType.IMPORTED, 0);
					}
				}
			}
		}
		catch (Exception e) {
			log.appendMsg(DynamicSymbolTableCommand.class.getSimpleName(),
				"Failed to markup %s.".formatted(name));
		}
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			markupTOC(header, api, baseAddress, parentModule, monitor);
			markupModules(header, api, baseAddress, parentModule, monitor);
			markupReferencedSymbolTable(header, api, baseAddress, parentModule, monitor);
			makupIndirectSymbolTable(header, api, baseAddress, parentModule, monitor);
			markupExternalRelocations(api, baseAddress, parentModule, monitor);
			markupLocalRelocations(api, baseAddress, parentModule, monitor);
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
			log.appendException(e);
		}
	}

	private void markupReferencedSymbolTable(MachHeader header, FlatProgramAPI api,
			Address baseAddress, ProgramModule parentModule, TaskMonitor monitor)
			throws DuplicateNameException, IOException, CodeUnitInsertionException, Exception {
		if (getReferencedSymbolTableSize() == 0) {
			return;
		}
		int id = 0;
		Address dyrefStartAddr = baseAddress.getNewAddress(getReferencedSymbolTableOffset());
		Address dyrefAddr = dyrefStartAddr;
		int offset = 0;
		for (DynamicLibraryReference dyref : getReferencedSymbolList()) {
			if (monitor.isCancelled()) {
				return;
			}
			DataType dyrefDT = dyref.toDataType();
			api.createData(dyrefStartAddr.add(offset), dyrefDT);

			NList dyrefSym = header.getFirstLoadCommand(SymbolTableCommand.class).getSymbolAt(
				dyref.getSymbolIndex());

			DynamicLibraryModule module = findModuleContaining(id);

			api.setPlateComment(dyrefAddr, "0x" + Integer.toHexString(id) + " -- " +
				module.getModuleName() + "::" + dyrefSym.getString());

			offset += dyrefDT.getLength();
			++id;
		}
		api.createFragment(parentModule, "REFERENCED_SYMBOLS", dyrefStartAddr, offset);
	}

	private DynamicLibraryModule findModuleContaining(int symbolIndex) {
		for (DynamicLibraryModule module : moduleList) {
			if (symbolIndex >= module.getReferenceSymbolTableIndex() &&
				symbolIndex < module.getReferenceSymbolTableIndex() +
					module.getReferenceSymbolTableCount()) {
				return module;
			}
		}
		throw new RuntimeException();
	}

	private void makupIndirectSymbolTable(MachHeader header, FlatProgramAPI api,
			Address baseAddress, ProgramModule parentModule, TaskMonitor monitor) throws Exception {
		int SIZEOF_DWORD = 4;
		if (getIndirectSymbolTableSize() == 0) {
			return;
		}
		Address start = baseAddress.getNewAddress(getIndirectSymbolTableOffset());
		long length = getIndirectSymbolTableSize() * SIZEOF_DWORD;

		api.createFragment(parentModule, "INDIRECT_SYMBOLS", start, length);

		for (int i = 0; i < indirectSymbols.length; ++i) {
			if (monitor.isCancelled()) {
				return;
			}
			Address addr = start.add(i * SIZEOF_DWORD);
			NList symbol = header.getFirstLoadCommand(SymbolTableCommand.class).getSymbolAt(
				indirectSymbols[i]);
			if (symbol != null) {
				api.setEOLComment(addr, symbol.getString());
			}
		}

		api.createDwords(start, getIndirectSymbolTableSize());
	}

	private void markupExternalRelocations(FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor) throws Exception {
		if (getExternalRelocationSize() == 0) {
			return;
		}
		Address relocStartAddr = baseAddress.getNewAddress(getExternalRelocationOffset());
		long offset = 0;
		for (RelocationInfo reloc : externalRelocations) {
			if (monitor.isCancelled()) {
				return;
			}
			DataType relocDT = reloc.toDataType();
			Address relocAddr = relocStartAddr.add(offset);
			api.createData(relocAddr, relocDT);
			api.setPlateComment(relocAddr, reloc.toString());
			offset += relocDT.getLength();
		}
		api.createFragment(parentModule, "EXTERNAL_RELOCATIONS", relocStartAddr, offset);
	}

	private void markupLocalRelocations(FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor) throws Exception {
		if (getLocalRelocationSize() == 0) {
			return;
		}
		Address relocStartAddr = baseAddress.getNewAddress(getLocalRelocationOffset());
		long offset = 0;
		for (RelocationInfo reloc : localRelocations) {
			if (monitor.isCancelled()) {
				return;
			}
			Address relocAddr = relocStartAddr.add(offset);
			DataType relocDT = reloc.toDataType();
			api.createData(relocAddr, relocDT);
			api.setPlateComment(relocAddr, reloc.toString());
			offset += relocDT.getLength();
		}
		api.createFragment(parentModule, "LOCAL_RELOCATIONS", relocStartAddr, offset);
	}

	private void markupModules(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor) throws Exception {
		if (getModuleTableSize() == 0) {
			return;
		}
		SymbolTableCommand symtabCommand = header.getFirstLoadCommand(SymbolTableCommand.class);
		Address moduleStartAddr = baseAddress.getNewAddress(getModuleTableOffset());
		long offset = 0;
		int id = 0;
		for (DynamicLibraryModule module : moduleList) {
			if (monitor.isCancelled()) {
				return;
			}
			DataType moduleDT = module.toDataType();
			Address moduleAddr = moduleStartAddr.add(offset);
			Data moduleData = api.createData(moduleAddr, moduleDT);

			Address stringAddr = baseAddress.getNewAddress(
				symtabCommand.getStringTableOffset() + module.getModuleNameIndex());

			api.createMemoryReference(moduleData, stringAddr, RefType.DATA);
			api.createAsciiString(stringAddr);
			api.setPlateComment(moduleAddr,
				"0x" + Integer.toHexString(id++) + " - " + module.getModuleName());

			offset += moduleDT.getLength();
		}
		api.createFragment(parentModule, "MODULES", moduleStartAddr, offset);
	}

	private void markupTOC(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor) throws Exception {
		if (getTableOfContentsSize() == 0) {
			return;
		}
		Address tocStartAddr = baseAddress.getNewAddress(getTableOfContentsOffset());
		long offset = 0;
		for (TableOfContents toc : tocList) {
			if (monitor.isCancelled()) {
				return;
			}
			Address tocAddr = tocStartAddr.add(offset);
			api.setPlateComment(tocAddr,
				"Module: " + moduleList.get(toc.getModuleIndex()).getModuleName() + '\n' +
					"Symbol: " + header.getFirstLoadCommand(SymbolTableCommand.class).getSymbolAt(
						toc.getSymbolIndex()).getString());
			DataType tocDT = toc.toDataType();
			api.createData(tocAddr, tocDT);
			offset += tocDT.getLength();
		}
		api.createFragment(parentModule, "TOC", tocStartAddr, offset);
	}
}
