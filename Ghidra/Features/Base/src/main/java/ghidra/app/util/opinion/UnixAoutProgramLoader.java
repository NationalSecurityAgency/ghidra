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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.unixaout.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.MonitoredInputStream;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class UnixAoutProgramLoader {
	private final int EXTERNAL_BLOCK_MIN_SIZE = 0x10000; // 64K

	public final static String dot_text = ".text";
	public final static String dot_data = ".data";
	public final static String dot_bss = ".bss";
	public final static String dot_rel_text = ".rel.text";
	public final static String dot_rel_data = ".rel.data";
	public final static String dot_strtab = ".strtab";
	public final static String dot_symtab = ".symtab";

	private final Program program;
	private final TaskMonitor monitor;
	private final MessageLog log;
	private final UnixAoutHeader header;

	private FileBytes fileBytes;

	private UnixAoutRelocationTable relText;
	private UnixAoutRelocationTable relData;
	private UnixAoutSymbolTable symtab;
	private UnixAoutStringTable strtab;

	private Map<String, Long> possibleBssSymbols = new HashMap<>();
	private int extraBssSize = 0;
	private int undefinedSymbolCount = 0;

	public UnixAoutProgramLoader(Program program, UnixAoutHeader header, TaskMonitor monitor,
			MessageLog log) {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		this.header = header;
	}

	public void loadAout(long baseAddr) throws IOException, CancelledException {
		log.appendMsg(String.format("----- Loading %s -----",
			header.getReader().getByteProvider().getAbsolutePath()));
		log.appendMsg(String.format("Found a.out type %s.", header.getExecutableType().name()));

		ByteProvider byteProvider = header.getReader().getByteProvider();

		try {
			buildTables(byteProvider);
			preprocessSymbolTable();
			loadSections(baseAddr, byteProvider);
			loadSymbols();
			applyRelocations(baseAddr, program.getMemory().getBlock(dot_text), relText);
			applyRelocations(baseAddr, program.getMemory().getBlock(dot_data), relData);
			markupSections();
		}
		catch (AddressOverflowException | InvalidInputException | CodeUnitInsertionException
				| DuplicateNameException
				| MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private void buildTables(ByteProvider byteProvider) throws IOException {
		if (header.getStrSize() > 0) {
			strtab = new UnixAoutStringTable(header.getReader(), header.getStrOffset(),
				header.getStrSize());
		}
		if (header.getSymSize() > 0) {
			symtab = new UnixAoutSymbolTable(header.getReader(), header.getSymOffset(),
				header.getSymSize(),
				strtab, log);
		}
		if (header.getTextRelocSize() > 0) {
			relText = new UnixAoutRelocationTable(header.getReader(), header.getTextRelocOffset(),
				header.getTextRelocSize(), symtab);
		}
		if (header.getDataRelocSize() > 0) {
			relData = new UnixAoutRelocationTable(header.getReader(), header.getDataRelocOffset(),
				header.getDataRelocSize(), symtab);
		}
	}

	private void preprocessSymbolTable() {
		if (symtab == null) {
			return;
		}

		boolean foundStabs = false;
		for (UnixAoutSymbol symbol : symtab) {
			switch (symbol.type) {
				case N_UNDF:
					if (symbol.value > 0) {
						// This is a special case given by the A.out spec: if the linker cannot find
						// this symbol in any of the other binary files, then the fact that it is
						// marked as N_UNDF but has a non-zero value means that its value should be
						// interpreted as a size, and the linker should reserve space in .bss for it.
						possibleBssSymbols.put(symbol.name, symbol.value);
					}
					else {
						undefinedSymbolCount++;
					}
					break;
				case N_STAB:
					if (!foundStabs) {
						foundStabs = true;
						log.appendMsg(dot_symtab, "File contains STABS.");
					}
					break;
				default:
					break;
			}
		}

		for (Long value : possibleBssSymbols.values()) {
			extraBssSize += value;
		}

		if (extraBssSize > 0) {
			log.appendMsg(dot_bss,
				String.format("Added %d bytes for N_UNDF symbols.", extraBssSize));
		}
	}

	private void loadSections(long baseAddr, ByteProvider byteProvider)
			throws AddressOverflowException, IOException, CancelledException {
		monitor.setMessage("Loading FileBytes...");

		try (InputStream fileIn = byteProvider.getInputStream(0);
				MonitoredInputStream mis = new MonitoredInputStream(fileIn, monitor)) {
			// Indicate that cleanup is not neccessary for cancelled import operation.
			mis.setCleanupOnCancel(false);
			fileBytes = program.getMemory()
					.createFileBytes(byteProvider.getName(), 0, byteProvider.length(), mis,
						monitor);
		}

		final AddressSpace defaultAddressSpace =
			program.getAddressFactory().getDefaultAddressSpace();
		final Address otherAddress = AddressSpace.OTHER_SPACE.getMinAddress();
		Address address;
		Address nextFreeAddress = defaultAddressSpace.getAddress(0);

		if (header.getTextOffset() != 0 || header.getTextSize() < 32) {
			MemoryBlockUtils.createInitializedBlock(program, true, "_aoutHeader", otherAddress,
				fileBytes, 0, 32, null, null, false, false, false, log);
		}
		if (header.getTextSize() > 0) {
			address = defaultAddressSpace.getAddress(baseAddr + header.getTextAddr());
			nextFreeAddress = address.add(header.getTextSize());
			MemoryBlockUtils.createInitializedBlock(program, false, dot_text, address, fileBytes,
				header.getTextOffset(), header.getTextSize(), null, null, true, true, true, log);
		}
		if (header.getDataSize() > 0) {
			address = defaultAddressSpace.getAddress(baseAddr + header.getDataAddr());
			nextFreeAddress = address.add(header.getDataSize());
			MemoryBlockUtils.createInitializedBlock(program, false, dot_data, address, fileBytes,
				header.getDataOffset(), header.getDataSize(), null, null, true, true, false, log);
		}
		if ((header.getBssSize() + extraBssSize) > 0) {
			address = defaultAddressSpace.getAddress(baseAddr + header.getBssAddr());
			nextFreeAddress = address.add(header.getBssSize() + extraBssSize);
			MemoryBlockUtils.createUninitializedBlock(program, false, dot_bss, address,
				header.getBssSize() + extraBssSize, null, null, true, true, false, log);
		}
		if (undefinedSymbolCount > 0) {
			int externalSectionSize = undefinedSymbolCount * 4;
			if (externalSectionSize < EXTERNAL_BLOCK_MIN_SIZE) {
				externalSectionSize = EXTERNAL_BLOCK_MIN_SIZE;
			}
			MemoryBlock externalBlock = MemoryBlockUtils.createUninitializedBlock(program, false,
				MemoryBlock.EXTERNAL_BLOCK_NAME, nextFreeAddress, externalSectionSize, null, null,
				false, false, false, log);
			if (externalBlock != null) {
				externalBlock.setArtificial(true);
			}
		}
		if (header.getStrSize() > 0) {
			MemoryBlockUtils.createInitializedBlock(program, true, dot_strtab, otherAddress,
				fileBytes, header.getStrOffset(), header.getStrSize(), null, null, false, false,
				false, log);
		}
		if (header.getSymSize() > 0) {
			MemoryBlockUtils.createInitializedBlock(program, true, dot_symtab, otherAddress,
				fileBytes, header.getSymOffset(), header.getSymSize(), null, null, false, false,
				false, log);
		}
		if (header.getTextRelocSize() > 0) {
			MemoryBlockUtils.createInitializedBlock(program, true, dot_rel_text, otherAddress,
				fileBytes, header.getTextRelocOffset(), header.getTextRelocSize(), null, null,
				false, false, false, log);
		}
		if (header.getDataRelocSize() > 0) {
			MemoryBlockUtils.createInitializedBlock(program, true, dot_rel_data, otherAddress,
				fileBytes, header.getDataRelocOffset(), header.getDataRelocSize(), null, null,
				false, false, false, log);
		}
	}

	private void loadSymbols() throws InvalidInputException {
		monitor.setMessage("Loading symbols...");

		if (symtab == null) {
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		FunctionManager functionManager = program.getFunctionManager();
		MemoryBlock textBlock = program.getMemory().getBlock(dot_text);
		MemoryBlock dataBlock = program.getMemory().getBlock(dot_data);
		MemoryBlock bssBlock = program.getMemory().getBlock(dot_bss);
		MemoryBlock externalBlock = program.getMemory().getBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);

		int extraBssOffset = 0;
		int undefinedSymbolIdx = 0;
		List<String> aliases = new ArrayList<>();

		for (UnixAoutSymbol symbol : symtab) {
			Address address = null;
			MemoryBlock block = null;

			switch (symbol.type) {
				case N_TEXT:
					address = textBlock != null ? textBlock.getStart().add(symbol.value) : null;
					block = textBlock;
					break;
				case N_DATA:
					address = dataBlock != null ? dataBlock.getStart().add(symbol.value) : null;
					block = dataBlock;
					break;
				case N_BSS:
					address = bssBlock != null ? bssBlock.getStart().add(symbol.value) : null;
					block = bssBlock;
					break;
				case N_UNDF:
					if (symbol.value > 0) {
						address = bssBlock.getEnd().add(extraBssOffset);
						block = bssBlock;
						extraBssOffset += symbol.value;
					}
					else {
						address = externalBlock.getStart().add(undefinedSymbolIdx++ * 4);
						block = externalBlock;
						symbolTable.addExternalEntryPoint(address);
					}
					break;
				case N_INDR:
					aliases.add(symbol.name);
					break;
				case N_ABS:
				case N_FN:
				case N_STAB:
				case UNKNOWN:
					aliases.clear();
					break;
			}

			if (address == null || block == null) {
				continue;
			}

			switch (symbol.kind) {
				case AUX_FUNC:
					try {
						functionManager.createFunction(symbol.name, address,
							new AddressSet(address),
							SourceType.IMPORTED);
					}
					catch (OverlappingFunctionException e) {
						log.appendMsg(block.getName(), String.format(
							"Failed to create function %s @ %s, creating symbol instead.",
							symbol.name, address));
						symbolTable.createLabel(address, symbol.name, SourceType.IMPORTED);
					}
					break;
				default:
					Symbol label =
						symbolTable.createLabel(address, symbol.name, SourceType.IMPORTED);
					if (symbol.isExt) {
						label.setPrimary();
					}
					break;
			}

			for (String alias : aliases) {
				symbolTable.createLabel(address, alias, SourceType.IMPORTED);
			}

			aliases.clear();
		}
	}

	private void applyRelocations(long baseAddr, MemoryBlock targetBlock,
			UnixAoutRelocationTable relTable) throws MemoryAccessException {
		if (targetBlock == null || relTable == null) {
			return;
		}

		monitor.setMessage(
			String.format("Applying relocations for section %s...", targetBlock.getName()));

		DataConverter dc = DataConverter.getInstance(program.getLanguage().isBigEndian());
		SymbolTable symbolTable = program.getSymbolTable();
		RelocationTable relocationTable = program.getRelocationTable();
		Memory memory = program.getMemory();
		MemoryBlock textBlock = memory.getBlock(dot_text);
		MemoryBlock dataBlock = memory.getBlock(dot_data);
		MemoryBlock bssBlock = memory.getBlock(dot_bss);

		int idx = 0;
		for (UnixAoutRelocation relocation : relTable) {
			Address targetAddress = targetBlock.getStart().add(relocation.address);

			byte originalBytes[] = new byte[relocation.pointerLength];
			targetBlock.getBytes(targetAddress, originalBytes);
			long addend = dc.getValue(originalBytes, 0, relocation.pointerLength);

			Long value = null;
			Status status = Status.FAILURE;

			if (relocation.baseRelative || relocation.jmpTable || relocation.relative ||
				relocation.copy) {
				status = Status.UNSUPPORTED;
			}
			else {
				if (relocation.extern == true && relocation.symbolNum < symtab.size()) {
					SymbolIterator symbolIterator =
						symbolTable.getSymbols(symtab.get(relocation.symbolNum).name);
					if (symbolIterator.hasNext()) {
						value = symbolIterator.next().getAddress().getOffset();
					}
				}
				else if (relocation.extern == false) {
					switch (relocation.symbolNum) {
						case 4:
							value = textBlock.getStart().getOffset();
							break;
						case 6:
							value = dataBlock.getStart().getOffset();
							break;
						case 8:
							value = bssBlock.getStart().getOffset();
							break;
					}
				}
			}

			if (value != null) {
				if (relocation.pcRelativeAddressing) {
					// Addend is relative to start of target section.
					value -= targetBlock.getStart().getOffset();
				}

				// Apply relocation.
				byte newBytes[] = new byte[relocation.pointerLength];
				dc.putValue(value + addend, relocation.pointerLength, newBytes, 0);
				targetBlock.putBytes(targetAddress, newBytes);

				status = Status.APPLIED;
			}

			if (status != Status.APPLIED) {
				log.appendMsg(targetBlock.getName(),
					String.format("Failed to apply relocation entry %d with type 0x%02x @ %s.", idx,
						relocation.flags, targetAddress));
			}

			relocationTable.add(targetAddress, status, relocation.flags,
				new long[] { relocation.symbolNum },
				originalBytes, relocation.getSymbolName(symtab));
			idx++;
		}
	}

	private void markupSections() throws InvalidInputException, CodeUnitInsertionException,
			DuplicateNameException, IOException {
		final AddressSpace defaultAddressSpace =
			program.getAddressFactory().getDefaultAddressSpace();
		final FunctionManager functionManager = program.getFunctionManager();
		final SymbolTable symbolTable = program.getSymbolTable();

		monitor.setMessage("Marking up header...");

		// Markup header.
		Address headerAddress = null;
		MemoryBlock aoutHeader = program.getMemory().getBlock("_aoutHeader");
		MemoryBlock textBlock = program.getMemory().getBlock(dot_text);
		if (aoutHeader != null) {
			headerAddress = aoutHeader.getStart();
		}
		else if (textBlock != null && header.getTextOffset() == 0 && header.getTextSize() >= 32) {
			headerAddress = textBlock.getStart();
		}
		if (headerAddress != null) {
			header.markup(program, headerAddress);
		}

		// Markup entrypoint.
		if (header.getEntryPoint() != 0) {
			Address address = defaultAddressSpace.getAddress(header.getEntryPoint());
			try {
				functionManager.createFunction("entry", address, new AddressSet(address),
					SourceType.IMPORTED);
			}
			catch (OverlappingFunctionException e) {
				log.appendMsg(dot_text,
					"Failed to create entrypoint function @ %s, creating symbol instead.");
				symbolTable.createLabel(address, "entry", SourceType.IMPORTED);
			}
		}

		monitor.setMessage("Marking up relocation tables...");

		MemoryBlock relTextBlock = program.getMemory().getBlock(dot_rel_text);
		if (relTextBlock != null) {
			relText.markup(program, relTextBlock);
		}

		MemoryBlock relDataBlock = program.getMemory().getBlock(dot_rel_data);
		if (relDataBlock != null) {
			relData.markup(program, relDataBlock);
		}

		monitor.setMessage("Marking up symbol table...");

		MemoryBlock symtabBlock = program.getMemory().getBlock(dot_symtab);
		if (symtabBlock != null) {
			symtab.markup(program, symtabBlock);
		}

		monitor.setMessage("Marking up string table...");

		MemoryBlock strtabBlock = program.getMemory().getBlock(dot_strtab);
		if (strtabBlock != null) {
			strtab.markup(program, strtabBlock);
		}
	}
}
