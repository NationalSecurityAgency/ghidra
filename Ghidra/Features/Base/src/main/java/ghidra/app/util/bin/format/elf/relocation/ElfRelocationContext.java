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
package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * <code>ElfRelocationContext</code> provides a relocation handler context related
 * to the processing of entries contained within a specific relocation table.
 */
public class ElfRelocationContext {

	protected final ElfRelocationHandler handler;
	protected final ElfLoadHelper loadHelper;
	protected final ElfRelocationTable relocationTable;
	protected final ElfSymbol[] symbols;
	protected final Map<ElfSymbol, Address> symbolMap;
	protected final Program program;

	/**
	 * Relocation context for a specific Elf image and relocation table
	 * @param handler relocation handler or null if not available
	 * @param loadHelper the elf load helper
	 * @param relocationTable Elf relocation table
	 * @param symbolMap Elf symbol placement map
	 */
	protected ElfRelocationContext(ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
		this.handler = handler;
		this.loadHelper = loadHelper;
		this.relocationTable = relocationTable;
		this.symbols = relocationTable.getAssociatedSymbolTable().getSymbols();
		this.symbolMap = symbolMap;
		this.program = loadHelper.getProgram();
	}

	/**
	 * Process a relocation from the relocation table which corresponds to this context.
	 * All relocation entries must be processed in the order they appear within the table.
	 * @param relocation
	 * @param relocationAddress
	 */
	public final void processRelocation(ElfRelocation relocation, Address relocationAddress) {

		if (handler == null) {
			handleNoHandlerError(relocation, relocationAddress);
			return;
		}

		long symbolIndex = relocation.getSymbolIndex();
		if (symbolIndex < 0 || symbolIndex >= symbols.length) {
			ElfRelocationHandler.markAsUnhandled(program, relocationAddress, relocation.getType(),
				symbolIndex, "index " + Long.toString(symbolIndex), getLog());
			return;
		}
		ElfSymbol sym = symbols[(int) symbolIndex];
		if (sym.isTLS()) {
			handleUnsupportedTLSRelocation(relocation, relocationAddress);
			return;
		}

		try {
			handler.relocate(this, relocation, relocationAddress);
		}
		catch (MemoryAccessException | NotFoundException e) {
			loadHelper.log(e);
			ElfRelocationHandler.markAsUnhandled(program, relocationAddress, relocation.getType(),
				symbolIndex, sym.getNameAsString(), getLog());
		}
	}

	/**
	 * Get the RELR relocation type associated with the underlying
	 * relocation handler.
	 * @return RELR relocation type or 0 if not supported
	 */
	public long getRelrRelocationType() {
		return handler != null ? handler.getRelrRelocationType() : 0;
	}

	private void handleUnsupportedTLSRelocation(ElfRelocation relocation,
			Address relocationAddress) {
		long symbolIndex = relocation.getSymbolIndex();
		ElfSymbol sym = symbols[(int) symbolIndex];
		ElfRelocationHandler.markAsError(program, relocationAddress, relocation.getType(),
			sym.getNameAsString(), "TLS symbol relocation not yet supported", getLog());
	}

	private void handleNoHandlerError(ElfRelocation relocation, Address relocationAddress) {

		String symName = symbols[relocation.getSymbolIndex()].getNameAsString();

		program.getBookmarkManager().setBookmark(relocationAddress, BookmarkType.ERROR,
			"Relocation", "No handler to process ELF Relocation to : " + symName);

		loadHelper.log("WARNING: At " + relocationAddress +
			" no handler to process ELF Relocations to " + symName);
	}

	/**
	 * Get a relocation context for a specfic Elf image and relocation table
	 * @param loadHelper Elf load helper
	 * @param relocationTable Elf relocation table
	 * @param symbolMap Elf symbol placement map
	 * @return relocation context or null
	 */
	public static ElfRelocationContext getRelocationContext(ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
		ElfHeader elf = loadHelper.getElfHeader();
		ElfRelocationContext context = null;
		ElfRelocationHandler handler = ElfRelocationHandlerFactory.getHandler(elf);
		if (handler != null) {
			context = handler.createRelocationContext(loadHelper, relocationTable, symbolMap);
		}
		if (context == null) {
			context = new ElfRelocationContext(handler, loadHelper, relocationTable, symbolMap);
		}
		return context;
	}

	/**
	 * @return true if a relocation handler was found
	 */
	public final boolean hasRelocationHandler() {
		return handler != null;
	}

	/**
	 * Get image base addressable word adjustment value to be applied to any pre-linked address values
	 * such as those contained with the dynamic table. (Applies to default address space only)
	 * @return image base adjustment value
	 */
	public long getImageBaseWordAdjustmentOffset() {
		return loadHelper.getImageBaseWordAdjustmentOffset();
	}

	/**
	 * Determine if addend data must be extracted
	 * @return true if relocation does not provide addend data and it must be
	 * extracted from relocation target if appropriate
	 */
	public boolean extractAddend() {
		return !relocationTable.hasAddendRelocations();
	}

	public final Program getProgram() {
		return program;
	}

	public final boolean isBigEndian() {
		return program.getMemory().isBigEndian();
	}

	public final ElfHeader getElfHeader() {
		return loadHelper.getElfHeader();
	}

	public final ElfLoadHelper getLoadHelper() {
		return loadHelper;
	}

	public final ElfLoadAdapter getLoadAdapter() {
		return getElfHeader().getLoadAdapter();
	}

	public final MessageLog getLog() {
		return loadHelper.getLog();
	}

	/**
	 * Get the Elf symbol which corresponds to the specified index.  Each relocation table
	 * corresponds to a specific symbol table to which the specified symbolIndex will be
	 * applied.
	 * @param symbolIndex
	 * @return Elf symbol which corresponds to symbol index
	 */
	public final ElfSymbol getSymbol(int symbolIndex) {
		return symbols[symbolIndex];
	}

	/**
	 * Get the program address at which the specified Elf symbol was placed.
	 * @param symbol Elf symbol
	 * @return program address
	 */
	public Address getSymbolAddress(ElfSymbol symbol) {
		return symbolMap.get(symbol);
	}

	/**
	 * Get the adjusted symbol value based upon its placement within the program.
	 * This value may differ from symbol.getValue() and will reflect the addressable
	 * unit/word offset of it program address.
	 * @param symbol Elf symbol
	 * @return adjusted Elf symbol value or 0 if symbol mapping not found
	 */
	public long getSymbolValue(ElfSymbol symbol) {
		Address symAddr = symbolMap.get(symbol);
		return symAddr != null ? symAddr.getAddressableWordOffset() : 0;
	}

	/**
	 * Returns the appropriate .got section using the
	 * DT_PLTGOT value defined in the .dynamic section.
	 * If no such dynamic value defined, the symbol offset for _GLOBAL_OFFSET_TABLE_
	 * will be used, otherwise a NotFoundException will be thrown.
	 * @return the .got section address offset
	 * @throws NotFoundException if the dynamic DT_PLTGOT not defined and 
	 * _GLOBAL_OFFSET_TABLE_ symbol not defined
	 */
	public long getGOTValue() throws NotFoundException {
		Long gotValue = loadHelper.getGOTValue();
		if (gotValue == null) {
			throw new NotFoundException("Failed to identify _GLOBAL_OFFSET_TABLE_");
		}
		return gotValue;
	}

	/**
	 * Dispose relocation context when processing of corresponding relocation table is complete.
	 * Instance should be disposed to allow all program changes to be flushed prior to processing
	 * a subsequent relocation table.
	 */
	public void dispose() {
		Listing listing = program.getListing();
		try {
			String extendedBlockName = MemoryBlock.EXTERNAL_BLOCK_NAME + ".ext";
			ProgramFragment extendedFragment =
				listing.getFragment("Program Tree", extendedBlockName);
			if (extendedFragment != null) {
				ProgramFragment externalFragment =
					listing.getFragment("Program Tree", MemoryBlock.EXTERNAL_BLOCK_NAME);
				if (externalFragment == null) {
					extendedFragment.setName(MemoryBlock.EXTERNAL_BLOCK_NAME);
				}
				else {
					externalFragment.move(extendedFragment.getMinAddress(),
						extendedFragment.getMaxAddress());
					externalFragment.getParents()[0].removeChild(extendedBlockName);
				}
			}
		}
		catch (DuplicateNameException | NotEmptyException | NotFoundException e) {
			Msg.error(this, "Failed to reconcile extended EXTERNAL block fragment");
		}
	}

	/**
	 * Get relocation address
	 * @param baseAddress base address
	 * @param relocOffset relocation offset relative to baseAddress
	 * @return relocation address
	 */
	public Address getRelocationAddress(Address baseAddress, long relocOffset) {
		return baseAddress.addWrap(relocOffset);
	}

}
