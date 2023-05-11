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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.exception.*;

/**
 * <code>ElfRelocationContext</code> provides a relocation handler context related
 * to the processing of entries contained within a specific relocation table.
 */
public class ElfRelocationContext {

	protected final ElfRelocationHandler handler;
	protected final ElfLoadHelper loadHelper;
	protected final Map<ElfSymbol, Address> symbolMap;
	protected final Program program;

	protected ElfRelocationTable relocationTable;
	protected ElfSymbolTable symbolTable; // may be null

	private ElfSymbol nullSymbol; // corresponds to symbolIndex==0 when no symbolTable

	/**
	 * Relocation context for a specific Elf image and relocation table
	 * @param handler relocation handler or null if not available
	 * @param loadHelper the elf load helper
	 * @param symbolMap Elf symbol placement map
	 */
	protected ElfRelocationContext(ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		this.handler = handler;
		this.loadHelper = loadHelper;
		this.symbolMap = symbolMap;
		this.program = loadHelper.getProgram();
	}

	/**
	 * Invoked at start of relocation processing for specified table.
	 * The method {@link #endRelocationTableProcessing()} will be invoked after last relocation
	 * is processed.
	 * @param relocTable relocation table
	 */
	public void startRelocationTableProcessing(ElfRelocationTable relocTable) {
		this.relocationTable = relocTable;
		symbolTable = relocTable.getAssociatedSymbolTable();
		if (symbolTable == null) {
			nullSymbol = new ElfSymbol();
		}
	}

	/**
	 * Invoked at end of relocation processing for current relocation table.
	 * See {@link #startRelocationTableProcessing(ElfRelocationTable)}.
	 */
	public void endRelocationTableProcessing() {
		this.relocationTable = null;
	}

	/**
	 * Process a relocation from the relocation table which corresponds to this context.
	 * All relocation entries must be processed in the order they appear within the table.
	 * @param relocation relocation to be processed
	 * @param relocationAddress relocation address where it should be applied
	 * @return applied relocation result
	 */
	public final RelocationResult processRelocation(ElfRelocation relocation,
			Address relocationAddress) {

		if (handler == null) {
			handleNoHandlerError(relocation, relocationAddress);
			return RelocationResult.FAILURE;
		}

		int symbolIndex = relocation.getSymbolIndex();
		ElfSymbol sym = getSymbol(symbolIndex);
		if (sym == null) {
			ElfRelocationHandler.markAsUnhandled(program, relocationAddress, relocation.getType(),
				symbolIndex, "index " + symbolIndex, getLog());
			return RelocationResult.FAILURE;
		}
		if (sym.isTLS()) {
			handleUnsupportedTLSRelocation(relocation, relocationAddress, sym);
			return RelocationResult.FAILURE;
		}

		try {
			return handler.relocate(this, relocation, relocationAddress);
		}
		catch (MemoryAccessException | NotFoundException e) {
			loadHelper.log(e);
			ElfRelocationHandler.markAsUnhandled(program, relocationAddress, relocation.getType(),
				symbolIndex, sym.getNameAsString(), getLog());
		}
		return RelocationResult.FAILURE;
	}

	/**
	 * Get the RELR relocation type associated with the underlying
	 * relocation handler.
	 * @return RELR relocation type or 0 if not supported
	 */
	public long getRelrRelocationType() {
		return handler != null ? handler.getRelrRelocationType() : 0;
	}

	private void handleUnsupportedTLSRelocation(ElfRelocation relocation, Address relocationAddress,
			ElfSymbol sym) {
		ElfRelocationHandler.markAsError(program, relocationAddress, relocation.getType(),
			sym.getNameAsString(), "TLS symbol relocation not yet supported", getLog());
	}

	private void handleNoHandlerError(ElfRelocation relocation, Address relocationAddress) {

		String symName = getSymbolName(relocation.getSymbolIndex());

		String nameMsg = "";
		if (!StringUtils.isBlank(symName)) {
			nameMsg = " to: " + symName;
		}
		program.getBookmarkManager().setBookmark(relocationAddress, BookmarkType.ERROR,
			"Relocation", "No handler to process ELF Relocation" + nameMsg);

		loadHelper.log("WARNING: At " + relocationAddress +
			" no handler to process ELF Relocation" + nameMsg);
	}

	/**
	 * Get a relocation context for a specfic Elf image and relocation table
	 * @param loadHelper Elf load helper
	 * @param symbolMap Elf symbol placement map
	 * @return relocation context or null
	 */
	public static ElfRelocationContext getRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		ElfHeader elf = loadHelper.getElfHeader();
		ElfRelocationContext context = null;
		ElfRelocationHandler handler = ElfRelocationHandlerFactory.getHandler(elf);
		if (handler != null) {
			context = handler.createRelocationContext(loadHelper, symbolMap);
		}
		if (context == null) {
			context = new ElfRelocationContext(handler, loadHelper, symbolMap);
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
	 * may correspond to a specific symbol table to which the specified symbolIndex will be
	 * applied.  In the absense of a corresponding symbol table index 0 will return a special 
	 * null symbol.
	 * @param symbolIndex symbol index
	 * @return Elf symbol which corresponds to symbol index or <B>null</B> if out of range
	 */
	public final ElfSymbol getSymbol(int symbolIndex) {
		if (symbolTable == null) {
			return symbolIndex == 0 ? nullSymbol : null;
		}
		return symbolTable.getSymbol(symbolIndex);
	}

	/**
	 * Get the ELF symbol name which corresponds to the specified index.  
	 * @param symbolIndex symbol index
	 * @return symbol name which corresponds to symbol index or null if out of range
	 */
	public final String getSymbolName(int symbolIndex) {
		return symbolTable != null ? symbolTable.getSymbolName(symbolIndex) : null;
	}

	/**
	 * Get the program address at which the specified Elf symbol was placed.
	 * @param symbol Elf symbol
	 * @return program address
	 */
	public Address getSymbolAddress(ElfSymbol symbol) {
		return symbol != null ? symbolMap.get(symbol) : null;
	}

	/**
	 * Get the adjusted symbol value based upon its placement within the program.
	 * This value may differ from symbol.getValue() and will reflect the addressable
	 * unit/word offset of it program address.
	 * @param symbol Elf symbol
	 * @return adjusted Elf symbol value or 0 if symbol mapping not found
	 */
	public long getSymbolValue(ElfSymbol symbol) {
		Address symAddr = symbol != null ? symbolMap.get(symbol) : null;
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
			loadHelper.log("Failed to reconcile extended EXTERNAL block fragment");
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
