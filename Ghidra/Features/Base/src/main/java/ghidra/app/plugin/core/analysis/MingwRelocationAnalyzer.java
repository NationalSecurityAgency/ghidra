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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.services.*;
import ghidra.app.util.bin.InvalidDataException;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class MingwRelocationAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "MinGW Relocations";
	private final static String DESCRIPTION =
		"Identify, markup and apply MinGW pseudo-relocations (must be done immediately after import).";

	public MingwRelocationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run right before any other analyzer and immediately after import
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before().before().before().before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!MinGWPseudoRelocationHandler.isSupportedProgram(program)) {
			return false;
		}
		if (!program.hasExclusiveAccess()) {
			// Exclusive access required since relocation table lacks merge support
			if (!alreadyProcessed(program)) {
				Msg.error(this,
					NAME + " analyzer disabled; requires exclusive access to " +
						program.getDomainFile());
			}
			return false;
		}
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (alreadyProcessed(program)) {
			return true;
		}
		try {
			MinGWPseudoRelocationHandler handler = new MinGWPseudoRelocationHandler(program);
			boolean success = handler.processRelocations(log, monitor);
			markAsProcessed(program, handler.listLabelsFound(), success);
		}
		catch (InvalidDataException e) {
			markAsNotFound(program);
			log.appendMsg(NAME + ": " + e.getMessage());
			Msg.error(this, e.getMessage());
			return false;
		}
		return true;
	}

	private static boolean alreadyProcessed(Program program) {
		Options propList = program.getOptions(Program.PROGRAM_INFO);
		String status = propList.getString(NAME, null);
		return !StringUtils.isBlank(status);
	}

	private static void markAsProcessed(Program program, boolean listLabelsFound, boolean success) {
		Options propList = program.getOptions(Program.PROGRAM_INFO);
		String text = success ? "Applied" : "Failed";
		if (listLabelsFound) {
			text += " using labels";  // psudeo reloc list labels were used
		}
		propList.setString(NAME, text);
	}

	private static void markAsNotFound(Program program) {
		Options propList = program.getOptions(Program.PROGRAM_INFO);
		propList.setString(NAME, "Unsupported");
	}
}

class MinGWPseudoRelocList {

	static final String PSEUDO_RELOC_LIST_START_NAME = "__RUNTIME_PSEUDO_RELOC_LIST__";
	static final String PSEUDO_RELOC_LIST_END_NAME = "__RUNTIME_PSEUDO_RELOC_LIST_END__";

	private Program program;
	private Address pdwListStartAddr;
	private Address pdwListEndAddr;
	private boolean listLabelsFound;

	MinGWPseudoRelocList(Program program) throws InvalidDataException {
		this.program = program;
		if (!findLabeledPseudoRelocList()) {
			if (program.getDefaultPointerSize() == 8) {
				findUnlabeledPseudoRelocList64Bit();
			}
			else {
				findUnlabeledPseudoRelocList32Bit();
			}
		}
		if (getDataBlock(pdwListStartAddr) != getDataBlock(pdwListEndAddr)) {
			throw new InvalidDataException("Mismatched MinGW relocation list start/end: " +
				pdwListStartAddr + " / " + pdwListEndAddr);
		}
	}

	private MemoryBlock getDataBlock(Address addr) throws InvalidDataException {
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || !block.isInitialized()) {
			throw new InvalidDataException("Invalid MinGW relocation list location: " + addr);
		}
		return block;
	}

	boolean listLabelsFound() {
		return listLabelsFound;
	}

	private void findUnlabeledPseudoRelocList64Bit() throws InvalidDataException {
		// TODO: add logic for finding relocation list within stripped binary
		throw new InvalidDataException("MinGW pseudo-relocation list not found");
	}

	private void findUnlabeledPseudoRelocList32Bit() throws InvalidDataException {
		// TODO: add logic for finding relocation list within stripped binary
		throw new InvalidDataException("MinGW pseudo-relocation list not found");
	}

	private boolean findLabeledPseudoRelocList() throws InvalidDataException {
		Symbol pdwListStart = getLabel(program, PSEUDO_RELOC_LIST_START_NAME);
		if (pdwListStart == null) {
			return false;
		}
		Symbol pdwListEnd = getLabel(program, PSEUDO_RELOC_LIST_END_NAME);
		if (pdwListEnd != null) {
			listLabelsFound = true;
			pdwListStartAddr = pdwListStart.getAddress();
			pdwListEndAddr = pdwListEnd.getAddress();
			return true;
		}
		throw new InvalidDataException("Missing MinGW " + PSEUDO_RELOC_LIST_END_NAME + " symbol");
	}

	private static Symbol getLabel(Program program, String name) {
		return SymbolUtilities.getExpectedLabelOrFunctionSymbol(program, name, m -> {
			/* ignore */});
	}

	Address getListStartAddress() {
		return pdwListStartAddr;
	}

	Address getListEndAddress() {
		return pdwListEndAddr;
	}
}

/**
 * MinGW pseudo-relocation handler
 */
class MinGWPseudoRelocationHandler {

	private static final int RP_VERSION_V1 = 0;
	private static final int RP_VERSION_V2 = 1;

	private static final int OLD_STYLE_ENTRY_SIZE = 8;
	private static final int NEW_STYLE_ENTRY_HEADER_SIZE = 12;

	static final String RELOC_TABLE_HEADER_STRUCT_NAME = "pseudoRelocListHeader";
	static final String V1_RELOC_ITEM_STRUCT_NAME = "pseudoRelocItemV1";
	static final String V2_RELOC_ITEM_STRUCT_NAME = "pseudoRelocItemV2";

	private Program program;
	private MinGWPseudoRelocList relocList;
	private int pointerSize;
	private DataType dwAddressDataType;

	/**
	 * Construct MinGW pseudo-relocation handler for a Program.
	 * @param program program to be processed
	 * @throws InvalidDataException failed to locate pseudo relocation list in program memory
	 */
	MinGWPseudoRelocationHandler(Program program) throws InvalidDataException {
		this.program = program;
		relocList = new MinGWPseudoRelocList(program);
	}

	boolean listLabelsFound() {
		return relocList.listLabelsFound();
	}

	static boolean isSupportedProgram(Program program) {
		Language language = program.getLanguage();
		int size = language.getLanguageDescription().getSize();
		return "x86".equals(language.getProcessor().toString()) &&
			(size == 32 || size == 64) &&
			"windows".equals(program.getCompilerSpec().getCompilerSpecID().toString()) &&
			CompilerEnum.GCC.label.equals(program.getCompiler()) &&
			getRDataBlock(program) != null;
	}

	private static MemoryBlock getRDataBlock(Program program) {
		Memory mem = program.getMemory();
		return mem.getBlock(".rdata");
	}

	private Symbol createPrimaryLabel(Address address, String name) {
		try {
			SymbolTable SymbolList = program.getSymbolTable();
			Symbol symbol = SymbolList.createLabel(address, name, null, SourceType.ANALYSIS);
			if (!symbol.isPrimary()) {
				symbol.setPrimary();
			}
			return symbol;
		}
		catch (InvalidInputException e) {
			throw new AssertException("unexpected", e);
		}
	}


	boolean processRelocations(MessageLog log, TaskMonitor monitor) throws CancelledException {

		Address pdwListBeginAddr = relocList.getListStartAddress();
		Address pdwListEndAddr = relocList.getListEndAddress();
		if (pdwListBeginAddr.equals(pdwListEndAddr)) {
			return true; // empty list
		}

		pointerSize = program.getDefaultPointerSize();
		dwAddressDataType = new IBO32DataType(program.getDataTypeManager());

		long size = pdwListEndAddr.subtract(pdwListBeginAddr);

		Memory memory = program.getMemory();

		// First table entry is used to identify implementation version
		int version;

		try {
			if (size >= OLD_STYLE_ENTRY_SIZE && memory.getLong(pdwListBeginAddr) != 0) {
				version = RP_VERSION_V1; // header not used
			}
			else if (size >= NEW_STYLE_ENTRY_HEADER_SIZE) {
				applyPseudoRelocHeader(pdwListBeginAddr, log);
				version = memory.getInt(pdwListBeginAddr.add(8)); // 3rd DWORD is version
				// update table pointer to first item
				pdwListBeginAddr = pdwListBeginAddr.add(NEW_STYLE_ENTRY_HEADER_SIZE);
				size -= NEW_STYLE_ENTRY_HEADER_SIZE; // reduce size by header size
			}
			else {
				log.appendMsg("Unsupported MinGW relocation table at " + pdwListBeginAddr);
				return false;
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			String msg = "MinGW relocation table processing failed at " + pdwListBeginAddr;
			log.appendMsg(msg);
			Msg.error(this, msg, e);
			return false;
		}

		boolean success;
		switch (version) {
			case RP_VERSION_V1:
				success = relocateV1(pdwListBeginAddr, (int) (size / OLD_STYLE_ENTRY_SIZE), log,
					monitor);
				break;
			case RP_VERSION_V2:
				success = relocateV2(pdwListBeginAddr, (int) (size / NEW_STYLE_ENTRY_HEADER_SIZE),
					log, monitor);
				break;
			default:
				log.appendMsg("Unsupported MinGW relocation table (Version: " + version + ") at " +
					pdwListBeginAddr);
				return false;
		}

		// Cleanup duplicate External Import symbols
		ExternalManager extMgr = program.getExternalManager();
		ReferenceManager refMgr = program.getReferenceManager();
		SymbolTable SymbolList = program.getSymbolTable();
		for (Symbol extSym : program.getSymbolTable().getExternalSymbols()) {
			monitor.checkCancelled();
			ExternalLocation extLoc = extMgr.getExternalLocation(extSym);
			if (extLoc.getOriginalImportedName() != null) {
				continue; // skip - already demangled
			}
			if (refMgr.hasReferencesTo(extSym.getAddress())) {
				continue; // skip - reference exists
			}
			List<Symbol> globalSymbols = SymbolList.getGlobalSymbols(extSym.getName());
			if (globalSymbols.size() != 1) {
				continue;
			}
			Symbol s = globalSymbols.get(0);
			if (memory.isExternalBlockAddress(s.getAddress())) {
				extSym.delete();
			}
		}

		return success;
	}

	/**
	 * Maps IAT addresses to EXTERNAL block allocation identified by {@link ExternalIATSymbol}
	 */
	private class ExternalIATSymbolMap extends HashMap<Address, ExternalIATSymbol> {

		private Address nextExtAddr;

		ExternalIATSymbolMap(Address extBlockStart) {
			this.nextExtAddr = extBlockStart;
		}

		ExternalIATSymbol allocateIATEntry(Address iatEntryAddr, RelocationTable relocationTable)
				throws MemoryAccessException, CodeUnitInsertionException {
			/** 
			 * symbolAddr (0x41a724) - corresponds to IAT location which refers to 
			 *    __imp__ZTIPi -> _ZTIPi
			 *    following original IBO32 value points at IMAGE_IMPORT_BY_NAME:
			 *       dword index (0x135c)
			 *       ds name ("_ZTIPi")
			 *    The above was used to formulate external location and reference
			 *    
			 * targetAddr (0x410ea0) - location to be fixed-up (relocation applied)
			 * data at relocation target:
			 *   -original bytes: address of IAT entry (i.e., symbolAddr) - may vary by bitLength!
			 *   -post fixup: adjusted by offset from symbolAddr to real external 
			 *               symbol address (*symbolAddr - symbolAddr)
			 */

			ExternalIATSymbol existingEntry = get(iatEntryAddr);
			if (existingEntry != null) {
				return existingEntry;
			}

			Reference ref =
				program.getReferenceManager().getPrimaryReferenceFrom(iatEntryAddr, 0);
			if (!ref.isExternalReference()) {
				return null;
			}

			Symbol extSym = program.getSymbolTable().getSymbol(ref);
			if (extSym == null) {
				return null;
			}

			ExternalLocation extLoc =
				program.getExternalManager().getExternalLocation(extSym);
			if (extLoc == null) {
				return null;
			}

			// Update IAT value - reference to EXTERNAL block
			Listing listing = program.getListing();
			listing.clearCodeUnits(iatEntryAddr, iatEntryAddr, false);
			Memory memory = program.getMemory();
			if (pointerSize == 8) { // 64-bit
				memory.setLong(iatEntryAddr, nextExtAddr.getOffset());
			}
			else { // 32-bit
				memory.setInt(iatEntryAddr, (int) nextExtAddr.getOffset());
			}
			listing.createData(iatEntryAddr, PointerDataType.dataType);

			relocationTable.add(iatEntryAddr, Status.APPLIED_OTHER, 0, null, pointerSize,
				extSym.getName());

			try {
				if (extLoc.isFunction()) {
					Function func = listing.createFunction(null, nextExtAddr,
						new AddressSet(nextExtAddr, nextExtAddr), SourceType.DEFAULT);
					func.setThunkedFunction(extLoc.getFunction());
				}
				else {
					// TODO: Not sure how to preserve relationship to external symbol 
					// which refers to Library
					listing.setComment(nextExtAddr, CodeUnit.PLATE_COMMENT,
						"External Location: " + extSym.getName(true));
					String name = extLoc.getOriginalImportedName();
					boolean demangle = true;
					if (name == null) {
						name = extSym.getName();
						demangle = false;
					}

					createPrimaryLabel(nextExtAddr, name);

					if (demangle) {
						DemanglerCmd cmd = new DemanglerCmd(nextExtAddr, name);
						cmd.applyTo(program);
					}
				}
			}
			catch (Exception e) {
				Msg.error(this, "Failed to create EXTERNAL block symbol at " + nextExtAddr);
			}

			ExternalIATSymbol extIATSym = new ExternalIATSymbol(nextExtAddr, extLoc);
			put(iatEntryAddr, extIATSym);

			nextExtAddr = nextExtAddr.add(pointerSize);

			return extIATSym;
		}

	}

	/**
	 * External Import Address List (IAT) Symbol Record
	 */
	private static record ExternalIATSymbol(Address extAddr, ExternalLocation extLoc) {
		// record only
	}

	private Address getDWAddress(MemBuffer buf) {
		return (Address) dwAddressDataType.getValue(buf, dwAddressDataType.getDefaultSettings(),
			-1);
	}

	private boolean relocateV2(Address pdwListBeginAddr, int entryCount, MessageLog log,
			TaskMonitor monitor) throws CancelledException {

		Listing listing = program.getListing();
		Data d = listing.getDefinedDataAt(pdwListBeginAddr);
		if (d != null && (d.isArray() || d.isStructure())) {
			return false; // silent - appears to have been previously processed
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		DataTypeManager dtm = program.getDataTypeManager();
		RelocationTable relocationTable = program.getRelocationTable();

		// Determine number of unique IAT symbol locations referenced
		Address addr = pdwListBeginAddr;
		MemoryBufferImpl buf = new MemoryBufferImpl(memory, addr);
		HashSet<Address> uniqueIATAddressSet = new HashSet<>();
		for (int i = 0; i < entryCount; i++) {
			monitor.checkCancelled();
			Address iatSymbolAddr = getDWAddress(buf);
			if (iatSymbolAddr == null) {
				log.appendMsg("Failed to read Mingw pseudo-relocation symbol RVA at: " + addr);
				return false;
			}
			uniqueIATAddressSet.add(iatSymbolAddr);
			addr = addr.add(NEW_STYLE_ENTRY_HEADER_SIZE);
			buf.setPosition(addr);
		}

		// Allocate EXTERNAL block
		int extBlockSize = uniqueIATAddressSet.size() * pointerSize;
		Address extBlockStart;
		try {
			extBlockStart = allocateBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, extBlockSize);
		}
		catch (Exception e) {
			String msg = "Failed to allocate EXTERNAL block for MinGW relocation processing";
			log.appendMsg(msg);
			Msg.error(this, msg, e);
			return false;
		}
		ExternalIATSymbolMap extIATSymbolMap = new ExternalIATSymbolMap(extBlockStart);

		// relocation result counters
		int applied = 0;
		int failed = 0;
		int unsupported = 0;

		// Process relocations
		addr = pdwListBeginAddr; // 1st dword of item is symbol address
		buf.setPosition(addr);
		for (int i = 0; i < entryCount; i++) {
			monitor.checkCancelled();

			Address iatSymbolAddr = getDWAddress(buf);

			addr = addr.add(4); // 2nd dword of item is target address
			buf.setPosition(addr);
			Address targetAddr = getDWAddress(buf);
			if (targetAddr == null) {
				log.appendMsg("Failed to read Mingw pseudo-relocation target RVA at: " + addr);
				return false;
			}

			addr = addr.add(4); // 3rd dword of item is flags (treated as bit-length)
			buf.setPosition(addr);

			String symbolName = null;
			RelocationResult result;
			try {

				// read item flags as bit-length
				int bitLength = buf.getInt(0) & 0xff;

				ExternalIATSymbol extSymbolEntry =
					extIATSymbolMap.allocateIATEntry(iatSymbolAddr, relocationTable);
				if (extSymbolEntry == null) {
					throw new UnsupportedOperationException();
				}

				symbolName = extSymbolEntry.extLoc.getOriginalImportedName();
				if (symbolName == null) {
					symbolName = extSymbolEntry.extLoc.getSymbol().getName();
				}

				// compute relocation symbol offset value
				long impValue = pointerSize == 8 ? memory.getLong(iatSymbolAddr)
						: Integer.toUnsignedLong(memory.getInt(iatSymbolAddr));
				Address pointerValue = space.getAddress(impValue);

				long qwOffset = pointerValue.subtract(iatSymbolAddr);
				long addend = 0;

				result = new RelocationResult(Status.APPLIED_OTHER, bitLength / 8); // treat flags as bit length
				switch (bitLength) {
					case 8:
						byte val8 = (byte) (memory.getByte(targetAddr) + qwOffset);
						memory.setByte(targetAddr, val8);
						++applied;
						break;
					case 16:
						short val16 = (short) (memory.getShort(targetAddr) + qwOffset);
						memory.setShort(targetAddr, val16);
						++applied;
						break;
					case 32:
						int val32 = memory.getInt(targetAddr);
						if (pointerSize == 4) {
							addend = (val32 - (int) iatSymbolAddr.getOffset());
						}
						val32 += qwOffset;
						memory.setInt(targetAddr, val32);
						++applied;
						break;
					case 64:
						long val64 = memory.getLong(targetAddr);
						if (pointerSize == 8) {
							addend = val64 - iatSymbolAddr.getOffset();
						}
						val64 += qwOffset;
						memory.setLong(targetAddr, val64);
						++applied;
						break;
					default:
						result = RelocationResult.UNSUPPORTED;
						++unsupported;
				}

				if (addend != 0) {
					ElfRelocationHandler.warnExternalOffsetRelocation(program,
						targetAddr, pointerValue, symbolName, addend, null);
					if (!memory.getBlock(targetAddr).isExecute()) {
						// assume pointer if not in execute block
						ElfRelocationHandler.applyComponentOffsetPointer(program,
							targetAddr, addend);
					}
				}
			}
			catch (MemoryAccessException | UnsupportedOperationException
					| CodeUnitInsertionException e) {
				markAsError(targetAddr, symbolName, e.getMessage(), log);
				result = RelocationResult.FAILURE;
				++failed;
			}

			relocationTable.add(targetAddr, result.status(), 0, null, result.byteLength(),
				symbolName);

			addr = addr.add(4);
			buf.setPosition(addr); // position on next element
		}

		if (failed != 0 || unsupported != 0) {
			log.appendMsg("MinGW pseudo-relocations - applied:" + applied + " failed:" + failed +
				" unsupported:" + unsupported);
		}

		Structure relocEntryStruct = new StructureDataType(V2_RELOC_ITEM_STRUCT_NAME, 0, dtm);
		relocEntryStruct.setPackingEnabled(true);
		relocEntryStruct.add(dwAddressDataType, "sym", null);
		relocEntryStruct.add(DWordDataType.dataType, "target", null); // could be offcut
		relocEntryStruct.add(DWordDataType.dataType, "flags", null);

		Array a = new ArrayDataType(relocEntryStruct, entryCount, -1, dtm);

		try {
			DataUtilities.createData(program, pdwListBeginAddr, a, -1, false,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg(
				"Failed to markup Mingw pseudo-relocation List at: " + pdwListBeginAddr);
		}
		return true;
	}

	private void applyPseudoRelocHeader(Address relocHeaderAddr, MessageLog log) {

		Structure relocHeaderStruct =
			new StructureDataType(RELOC_TABLE_HEADER_STRUCT_NAME, 0, program.getDataTypeManager());
		relocHeaderStruct.setPackingEnabled(true);
		relocHeaderStruct.add(DWordDataType.dataType, "zero1", null);
		relocHeaderStruct.add(DWordDataType.dataType, "zero2", null);
		relocHeaderStruct.add(DWordDataType.dataType, "version", null);

		try {
			DataUtilities.createData(program, relocHeaderAddr, relocHeaderStruct, -1,
				false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg(
				"Failed to markup Mingw pseudo-relocation List header at: " + relocHeaderAddr);
		}
	}

	private void markAsError(Address relocationAddress, String symbolName, String msg,
			MessageLog log) {
		symbolName = StringUtils.isEmpty(symbolName) ? "<noname>" : symbolName;
		log.appendMsg("MinGW Relocation Error: at " + relocationAddress + ", Symbol = " +
			symbolName + ": " + msg);
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR, "MinGW Relocation",
			"MinGW Relocation Error: Symbol = " + symbolName + ": " + msg);
	}

	private void markAsError(Address relocationAddress, String msg, MessageLog log) {
		log.appendMsg("MinGW Relocation Error: at " + relocationAddress + ": " + msg);
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR, "MinGW Relocation",
			"MinGW Relocation Error: " + msg);
	}

	private Address allocateBlock(String blockName, int extBlockSize) throws Exception {

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		long delta = 0x10000000;
		Address startAddr = null;
		for (long offset = delta; offset < 0x100000000L; offset += delta) {
			Address addr = space.getAddress(offset);
			AddressIterator addresses = memory.getAddresses(addr, true);
			if (!addresses.hasNext()) {
				startAddr = addr;
				break;
			}
			Address nextAddr = addresses.next();
			if (!nextAddr.getAddressSpace().equals(space) ||
				nextAddr.subtract(addr) > extBlockSize) {
				startAddr = addr;
				break;
			}
		}
		if (startAddr != null) {
			memory.createUninitializedBlock(blockName, startAddr, extBlockSize, false);
			return startAddr;
		}
		throw new MemoryAccessException("Failed to allocate block: " + blockName);
	}

	private boolean relocateV1(Address pdwListPayloadAddr, int entryCount, MessageLog log,
			TaskMonitor monitor) throws CancelledException {

		Listing listing = program.getListing();
		Data d = listing.getDefinedDataAt(pdwListPayloadAddr);
		if (d != null && (d.isArray() || d.isStructure())) {
			return false; // silent - appears to have been previously processed
		}

		Memory memory = program.getMemory();
		DataTypeManager dtm = program.getDataTypeManager();
		RelocationTable relocationTable = program.getRelocationTable();

		Address addr = pdwListPayloadAddr;
		DumbMemBufferImpl buf = new DumbMemBufferImpl(memory, pdwListPayloadAddr);

		RelocationResult appliedResult = new RelocationResult(Status.APPLIED_OTHER, 4);

		// relocation result counters
		int applied = 0;
		int failed = 0;

		for (int i = 0; i < entryCount; i++) {
			monitor.checkCancelled();

			RelocationResult result = appliedResult;
			int dwOffset = 0;
			try {
				dwOffset = buf.getInt(0);
			}
			catch (MemoryAccessException e1) {
				log.appendMsg("Failed to read Mingw pseudo-relocation offset at: " + addr);
				return false;
			}

			addr = addr.add(4);
			buf.setPosition(addr); // position on 2nd value
			Address targetAddr = getDWAddress(buf);
			if (targetAddr == null) {
				log.appendMsg("Failed to read Mingw pseudo-relocation target RVA at: " + addr);
				return false;
			}

			try {
				int val32 = memory.getInt(targetAddr) + dwOffset;
				memory.setInt(targetAddr, val32);
				++applied;
			}
			catch (Exception e) {
				markAsError(targetAddr, e.getMessage(), log);
				result = RelocationResult.FAILURE;
				++failed;
			}

			relocationTable.add(targetAddr, result.status(), 0, null, result.byteLength(), null);

			addr = addr.add(4);
			buf.setPosition(addr); // position on next element
		}

		if (failed != 0) {
			log.appendMsg("MinGW pseudo-relocations - applied:" + applied + " failed:" + failed);
		}

		Structure s = new StructureDataType(V1_RELOC_ITEM_STRUCT_NAME, 0, dtm);
		s.setPackingEnabled(true);
		s.add(DWordDataType.dataType, "addend", null);
		s.add(DWordDataType.dataType, "target", null); // may be offcut

		Array a = new ArrayDataType(s, entryCount, -1, dtm);

		try {
			DataUtilities.createData(program, pdwListPayloadAddr, a, -1, false,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this,
				"Failed to markup Mingw pseudo-relocation List at: " + pdwListPayloadAddr);
		}
		return true;
	}

}
