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
package wasm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.format.StructureBuilder;
import wasm.format.WasmConstants;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmUnknownCustomSection;
import wasm.format.sections.structures.WasmCodeEntry;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmGlobalType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmLoader extends AbstractLibrarySupportLoader {

	public final static String WEBASSEMBLY = "WebAssembly";

	public final static long IMPORT_BASE = 0x7f000000L;
	public final static long CODE_BASE = 0x80000000L;
	/* Size of each register */
	public final static int REG_SIZE = 16;

	@Override
	public String getName() {
		return WEBASSEMBLY;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);

		if (Arrays.equals(WasmConstants.WASM_MAGIC, header.getMagic()) && WasmConstants.WASM_VERSION == header.getVersion()) {
			loadSpecs.add(new LoadSpec(this, CODE_BASE, new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	// #region Address computations
	public static long getFunctionAddressOffset(WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return IMPORT_BASE + funcidx * 4;
		} else {
			WasmCodeEntry codeEntry = module.getNonImportedFunctions().get(funcidx - imports.size());
			return CODE_BASE + codeEntry.getOffset();
		}
	}

	public static long getFunctionSize(WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return 4;
		} else {
			WasmCodeEntry codeEntry = module.getNonImportedFunctions().get(funcidx - imports.size());
			return codeEntry.getCodeSize();
		}
	}

	public static Address getFunctionAddress(AddressFactory addressFactory, WasmModule module, int funcidx) {
		return addressFactory.getAddressSpace("ram").getAddress(getFunctionAddressOffset(module, funcidx));
	}

	public static Address getTableAddress(AddressFactory addressFactory, int tableidx, long itemIndex) {
		return addressFactory.getAddressSpace("table").getAddress((((long) tableidx) << 32) + (itemIndex * 4));
	}

	public static Address getMemoryAddress(AddressFactory addressFactory, int memidx, long offset) {
		if (memidx != 0) {
			/* only handle memory 0 for now */
			throw new IllegalArgumentException("non-zero memidx is not supported");
		}

		return addressFactory.getAddressSpace("ram").getAddress(offset);
	}

	public static Address getGlobalAddress(AddressFactory addressFactory, int globalidx) {
		return addressFactory.getAddressSpace("global").getAddress(((long) globalidx) * REG_SIZE);
	}

	public static Address getModuleAddress(AddressFactory addressFactory) {
		return getCodeAddress(addressFactory, 0);
	}

	private static Address getCodeAddress(AddressFactory addressFactory, long fileOffset) {
		return addressFactory.getAddressSpace("ram").getAddress(CODE_BASE + fileOffset);
	}
	// #endregion

	// #region Naming
	private static Symbol createLabel(Program program, Address address, String name, Namespace namespace, SourceType sourceType) throws InvalidInputException {
		if (name == null || name.isEmpty()) {
			name = "unnamed";
		}

		// Make spaces into non-breaking spaces to avoid invalid chars
		name = name.replace(" ", "\u00A0");
		// Replace any other invalid chars with _
		name = SymbolUtilities.replaceInvalidChars(name, true);
		// Leave room for a suffix if necessary
		int maxLen = SymbolUtilities.MAX_SYMBOL_NAME_LENGTH - 16;
		if (name.length() > maxLen) {
			name = name.substring(0, maxLen);
		}
		String newname = name;
		int suffix = 0;
		while (!program.getSymbolTable().getSymbols(newname, namespace).isEmpty()) {
			suffix++;
			newname = name + "_" + suffix;
		}

		return program.getSymbolTable().createLabel(address, newname, namespace, sourceType);
	}

	private static Namespace getNamespace(Program program, Namespace parent, String name) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(parent, name, SourceType.IMPORTED);
		} catch (Exception e) {
			return parent;
		}
	}

	private static Namespace getObjectNamespace(Program program, WasmModule module, WasmExternalKind objectKind, int objidx) {
		Namespace globalNamespace = program.getGlobalNamespace();

		List<WasmImportEntry> imports = module.getImports(objectKind);
		if (objidx < imports.size()) {
			Namespace importNamespace = getNamespace(program, globalNamespace, "import");
			return getNamespace(program, importNamespace, imports.get(objidx).getModule());
		}
		WasmExportEntry entry = module.findExport(objectKind, objidx);
		if (entry != null) {
			return getNamespace(program, globalNamespace, "export");
		}
		return globalNamespace;
	}

	private static String getObjectName(WasmModule module, WasmExternalKind objectKind, int objidx) {
		List<WasmImportEntry> imports = module.getImports(objectKind);
		if (objidx < imports.size()) {
			return imports.get(objidx).getName();
		}
		WasmExportEntry entry = module.findExport(objectKind, objidx);
		if (entry != null) {
			return entry.getName();
		}
		return null;
	}

	public static Namespace getFunctionNamespace(Program program, WasmModule module, int funcidx) {
		return getObjectNamespace(program, module, WasmExternalKind.EXT_FUNCTION, funcidx);
	}

	public static String getFunctionName(WasmModule module, int funcidx) {
		String name;
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			name = nameSection.getFunctionName(funcidx);
			if (name != null) {
				return name;
			}
		}
		name = getObjectName(module, WasmExternalKind.EXT_FUNCTION, funcidx);
		if (name != null) {
			return name;
		}
		return "unnamed_function_" + funcidx;
	}

	public static Namespace getGlobalNamespace(Program program, WasmModule module, int globalidx) {
		return getObjectNamespace(program, module, WasmExternalKind.EXT_GLOBAL, globalidx);
	}

	public static String getGlobalName(Program program, WasmModule module, int globalidx) {
		String name;
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			name = nameSection.getGlobalName(globalidx);
			if (name != null) {
				return name;
			}
		}
		name = getObjectName(module, WasmExternalKind.EXT_GLOBAL, globalidx);
		if (name != null) {
			return name;
		}
		return "global_" + globalidx;
	}
	// #endregion

	// #region Memory blocks
	private static Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		} catch (CodeUnitInsertionException e) {
			Msg.warn(WasmLoader.class, "Data markup conflict at " + address, e);
		}
		return null;
	}

	private static MemoryBlock createModuleBlock(Program program, FileBytes fileBytes) throws Exception {
		Address start = getCodeAddress(program.getAddressFactory(), 0);
		MemoryBlock block = program.getMemory().createInitializedBlock(".module", start, fileBytes, 0, fileBytes.getSize(), false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
		block.setSourceName("Wasm Module");
		block.setComment("The full file contents of the Wasm module");
		return block;
	}

	private static void createImportStubBlock(Program program, Address startAddress, long length) {
		try {
			MemoryBlock block = program.getMemory().createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, startAddress, length, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setComment("NOTE: This block is artificial and is used to represent imported functions");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create imported function block at " + startAddress, e);
		}
	}

	private static void createTableBlock(Program program, DataType elementDataType, long numElements, int tableidx, TaskMonitor monitor) {
		if (numElements == 0) {
			return;
		}
		long byteSize = elementDataType.getLength() * numElements;
		Address dataStart = getTableAddress(program.getAddressFactory(), tableidx, 0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".table" + tableidx, dataStart, byteSize, (byte) 0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			DataType tableDataType = new ArrayDataType(elementDataType, (int) numElements, elementDataType.getLength());
			createData(program, program.getListing(), dataStart, tableDataType);
			createLabel(program, dataStart, "table" + tableidx, program.getGlobalNamespace(), SourceType.IMPORTED);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create table block " + tableidx + " at " + dataStart, e);
		}
	}

	private static void createMemoryBlock(Program program, int memidx, long length, TaskMonitor monitor) {
		if (length == 0) {
			return;
		}
		Address dataStart = getMemoryAddress(program.getAddressFactory(), memidx, 0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".memory" + memidx, dataStart, length, (byte) 0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			block.setSourceName("Wasm Memory");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create memory block " + memidx + " at " + dataStart, e);
		}
	}

	private static void createGlobalBlock(Program program, DataType dataType, byte[] initBytes, int globalidx, int mutability, TaskMonitor monitor) {
		Address dataStart = getGlobalAddress(program.getAddressFactory(), globalidx);
		try {
			MemoryBlock block;
			if (initBytes == null) {
				block = program.getMemory().createUninitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), false);
			} else {
				block = program.getMemory().createInitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), (byte) 0x00, monitor, false);
				program.getMemory().setBytes(dataStart, initBytes);
			}
			block.setRead(true);
			block.setWrite((mutability != 0) ? true : false);
			block.setExecute(false);
			createData(program, program.getListing(), dataStart, dataType);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create global block " + globalidx + " at " + dataStart, e);
		}
	}

	private static void createCodeLengthData(Program program, MemoryBlock moduleBlock, WasmModule module) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		List<WasmCodeEntry> codeEntries = module.getNonImportedFunctions();
		for (int i = 0; i < codeEntries.size(); i++) {
			WasmCodeEntry entry = codeEntries.get(i);
			StructureBuilder builder = new StructureBuilder("code_" + (i + imports.size()));
			builder.addUnsignedLeb128(entry.getCodeSizeLeb128(), "code_size");
			long offset = entry.getOffset() - entry.getCodeSizeLeb128().getLength();
			createData(program, program.getListing(), moduleBlock.getStart().add(offset), builder.toStructure());
		}
	}
	// #endregion

	public void createImportExportSymbols(Program program, WasmModule module, int funcidx, Function function) throws Exception {

		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		// imported function
		if (funcidx < imports.size()) {
			WasmImportEntry importEntry = imports.get(funcidx);
			// create Import symbol
			ExternalLocation extLoc = program.getExternalManager().addExtFunction(
					importEntry.getModule(), importEntry.getName(), function.getEntryPoint(),
					SourceType.IMPORTED);
			function.setThunkedFunction(extLoc.getFunction());
			return;
		}

		WasmExportEntry entry = module.findExport(WasmExternalKind.EXT_FUNCTION, funcidx);
		// exported function
		if (entry != null) {
			program.getSymbolTable().addExternalEntryPoint(function.getEntryPoint());
		}
	}

	private void loadFunctions(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading functions");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		List<WasmCodeEntry> codeEntries = module.getNonImportedFunctions();
		int numFunctions = imports.size() + codeEntries.size();

		if (imports.size() > 0) {
			createImportStubBlock(program, getFunctionAddress(program.getAddressFactory(), module, 0), imports.size() * 4);
		}

		monitor.initialize(numFunctions);
		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			Address startAddress = getFunctionAddress(program.getAddressFactory(), module, funcidx);
			long functionLength = getFunctionSize(module, funcidx);
			String functionName = getFunctionName(module, funcidx);
			Namespace functionNamespace = getFunctionNamespace(program, module, funcidx);

			try {
				Symbol symbol = createLabel(program, startAddress, functionName, functionNamespace, SourceType.IMPORTED);
				Function function = program.getFunctionManager().createFunction(symbol.getName(false), symbol.getParentNamespace(),
						startAddress, new AddressSet(startAddress, startAddress.add(functionLength - 1)), SourceType.IMPORTED);
				try {
					createImportExportSymbols(program, module, funcidx, function);
				} catch (Exception e) {
					Msg.error(this, "Failed to create import/export symbol for function index " + funcidx + " (" + functionName + ") at " + startAddress, e);
				}
			} catch (Exception e) {
				Msg.error(this, "Failed to create function index " + funcidx + " (" + functionName + ") at " + startAddress, e);
			}
		}
	}

	private void loadTables(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading tables");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_TABLE);
		List<WasmTableType> tables = module.getNonImportedTables();
		int numTables = imports.size() + tables.size();

		monitor.initialize(numTables);
		for (int tableidx = 0; tableidx < numTables; tableidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmTableType table;
			if (tableidx < imports.size()) {
				table = imports.get(tableidx).getTableType();
			} else {
				table = tables.get(tableidx - imports.size());
			}

			createTableBlock(program, table.getElementDataType(), table.getLimits().getInitial(), tableidx, monitor);
		}
	}

	/**
	 * Copy element segment to table.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * element segment once the dynamic table index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadElementsToTable(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), elemidx, tableidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadElementsToTable(Program program, WasmModule module, int elemidx, int tableidx, long offset, TaskMonitor monitor) throws Exception {
		WasmElementSegment elemSegment = module.getElementSegments().get(elemidx);

		byte[] initBytes = elemSegment.getInitData(module);
		if (initBytes == null)
			return;

		program.getMemory().setBytes(getTableAddress(program.getAddressFactory(), tableidx, offset), initBytes);

		Address[] refs = elemSegment.getAddresses(program.getAddressFactory(), module);
		for (int i = 0; i < refs.length; i++) {
			if (refs[i] != null) {
				Address elementAddr = getTableAddress(program.getAddressFactory(), tableidx, offset + i);
				program.getReferenceManager().removeAllReferencesFrom(elementAddr);
				program.getReferenceManager().addMemoryReference(elementAddr, refs[i], RefType.DATA, SourceType.IMPORTED, 0);
			}
		}
	}

	private void loadElementSegments(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		/* Load active element segments into tables */
		monitor.setMessage("Loading table elements");
		List<WasmElementSegment> entries = module.getElementSegments();

		monitor.initialize(entries.size());
		for (int elemidx = 0; elemidx < entries.size(); elemidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmElementSegment elemSegment = entries.get(elemidx);
			int tableidx = (int) elemSegment.getTableIndex();

			Long offset = elemSegment.getOffset();
			if (offset == null)
				continue;

			try {
				loadElementsToTable(program, module, elemidx, tableidx, offset, monitor);
			} catch (Exception e) {
				Msg.error(this, "Failed to initialize table " + tableidx + " with element segment " + elemidx + " at offset " + offset, e);
			}
		}
	}

	private void loadMemories(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading memories");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_MEMORY);
		List<WasmResizableLimits> memories = module.getNonImportedMemories();
		int numMemories = imports.size() + memories.size();

		monitor.initialize(numMemories);
		for (int memidx = 0; memidx < numMemories; memidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			if (memidx != 0) {
				/* only handle memory 0 for now */
				continue;
			}
			WasmResizableLimits mem;
			if (memidx < imports.size()) {
				mem = imports.get(memidx).getMemoryType();
			} else {
				mem = memories.get(memidx - imports.size());
			}
			createMemoryBlock(program, memidx, Math.min(mem.getInitial() * 65536L, CODE_BASE), monitor);
		}
	}

	/**
	 * Copy data segment to memory.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * data segment once the dynamic memory index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadDataToMemory(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), dataidx, memidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadDataToMemory(Program program, WasmModule module, int dataidx, int memidx, long offset, TaskMonitor monitor) throws Exception {
		WasmDataSegment dataSegment = module.getDataSegments().get(dataidx);
		Address memStart = getMemoryAddress(program.getAddressFactory(), memidx, offset);
		program.getMemory().setBytes(memStart, dataSegment.getData());
	}

	private void loadDataSegments(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		/* Load active data segments into memory */
		monitor.setMessage("Loading data segments");
		List<WasmDataSegment> dataSegments = module.getDataSegments();

		monitor.initialize(dataSegments.size());
		for (int dataidx = 0; dataidx < dataSegments.size(); dataidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmDataSegment dataSegment = dataSegments.get(dataidx);
			int memidx = (int) dataSegment.getIndex();
			if (memidx != 0) {
				/* only handle memory 0 for now */
				continue;
			}

			Long offset = dataSegment.getMemoryOffset();
			if (offset == null) {
				continue;
			}

			try {
				loadDataToMemory(program, module, dataidx, memidx, offset, monitor);
			} catch (Exception e) {
				Address memStart = getMemoryAddress(program.getAddressFactory(), memidx, offset);
				Msg.error(this, "Failed to initialize memory " + memidx + " with data segment " + dataidx + " at " + memStart, e);
			}
		}
	}

	private void loadGlobals(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Loading globals");
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_GLOBAL);
		List<WasmGlobalEntry> globals = module.getNonImportedGlobals();
		int numGlobals = imports.size() + globals.size();

		monitor.initialize(numGlobals);
		for (int globalidx = 0; globalidx < numGlobals; globalidx++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmGlobalType globalType;
			byte[] initBytes;
			Address initRef;
			Long initGlobal;
			if (globalidx < imports.size()) {
				globalType = imports.get(globalidx).getGlobalType();
				initBytes = null;
				initRef = null;
				initGlobal = null;
			} else {
				WasmGlobalEntry entry = globals.get(globalidx - imports.size());
				globalType = entry.getGlobalType();
				initBytes = entry.asBytes(module);
				initRef = entry.asAddress(program.getAddressFactory(), module);
				initGlobal = entry.asGlobalGet();
			}

			createGlobalBlock(program, globalType.getType().asDataType(), initBytes, globalidx, globalType.getMutability(), monitor);

			Address dataStart = getGlobalAddress(program.getAddressFactory(), globalidx);
			Namespace namespace = getGlobalNamespace(program, module, globalidx);
			String name = getGlobalName(program, module, globalidx);
			try {
				createLabel(program, dataStart, name, namespace, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to label global " + globalidx + " (" + name + ") at " + dataStart, e);
			}

			if (initRef != null) {
				program.getReferenceManager().removeAllReferencesFrom(dataStart);
				program.getReferenceManager().addMemoryReference(dataStart, initRef, RefType.DATA, SourceType.IMPORTED, 0);
			}
			if (initGlobal != null) {
				int commentType = CodeUnit.PLATE_COMMENT;
				String currentComment = program.getListing().getComment(commentType, dataStart);
				if (currentComment == null) {
					currentComment = "";
				} else if (!currentComment.isEmpty()) {
					currentComment += "\n";
				}
				Address otherAddress = getGlobalAddress(program.getAddressFactory(), (int) (long) initGlobal);
				program.getListing().setComment(dataStart, commentType, currentComment + "Initializer: {@symbol " + otherAddress + "}");
			}
		}
	}

	private MemoryBlock createCustomSectionBlock(Program program, FileBytes fileBytes, WasmUnknownCustomSection customSection, Address address)
			throws Exception {
		MemoryBlock block = program.getMemory().createInitializedBlock(customSection.getName(), address, fileBytes, customSection.getContentOffset(), customSection.getCustomSize(), false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
		block.setSourceName("Wasm Module");
		return block;
	}

	private void createCustomSections(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		monitor.setMessage("Creating custom sections");
		// start right after the module block
		Address address = AddressSpace.OTHER_SPACE.getAddress(fileBytes.getSize());
		for (WasmSection section : module.getCustomSections()) {
			if (!(section instanceof WasmUnknownCustomSection)) {
				continue;
			}
			WasmUnknownCustomSection customSection = (WasmUnknownCustomSection) section;
			try {
				if (customSection.getCustomSize() == 0) {
					continue;
				}
				monitor.setMessage("Creating custom section " + section.getName());
				MemoryBlock block = createCustomSectionBlock(program, fileBytes, customSection, address);
				address = address.add(block.getSize());
			} catch (Exception e) {
				Msg.error(this, "Failed to load Wasm Custom section " + customSection.getCustomName(), e);
			}
		}
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage("Start loading");

		try {
			doLoad(provider, program, monitor);
		} catch (Exception e) {
			monitor.setMessage("Error");
			Msg.error(this, "Failed to load Wasm module", e);
		}
	}

	private void doLoad(ByteProvider provider, Program program, TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, true);
		WasmModule module = new WasmModule(reader);

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);

		MemoryBlock moduleBlock = createModuleBlock(program, fileBytes);
		createData(program, program.getListing(), moduleBlock.getStart(), module.getHeader().toDataType());

		for (WasmSection section : module.getSections()) {
			monitor.setMessage("Creating section " + section.getName());
			createData(program, program.getListing(), moduleBlock.getStart().add(section.getSectionOffset()), section.toDataType());
		}

		createCodeLengthData(program, moduleBlock, module);

		createCustomSections(program, fileBytes, module, monitor);

		loadFunctions(program, fileBytes, module, monitor);
		loadTables(program, fileBytes, module, monitor);
		loadElementSegments(program, fileBytes, module, monitor);
		loadMemories(program, fileBytes, module, monitor);
		loadDataSegments(program, fileBytes, module, monitor);
		loadGlobals(program, fileBytes, module, monitor);
	}
}
