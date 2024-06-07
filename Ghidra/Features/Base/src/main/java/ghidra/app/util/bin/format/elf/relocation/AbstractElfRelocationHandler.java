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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.classfinder.ClassSearcher;

/**
 * <code>ElfRelocationHandler</code> provides the base class for processor specific
 * ELF relocation handlers.  Implementations may only specify a public default constructor
 * as they will be identified and instatiated by the {@link ClassSearcher}.  As such their
 * name must end with "ElfRelocationHandler" (e.g., MyProc_ElfRelocationHandler).
 * 
 * @param <T> ELF relocation type enum class
 * @param <C> ELF relocation context class
 */
abstract public class AbstractElfRelocationHandler<T extends ElfRelocationType, C extends ElfRelocationContext<?>>
		extends ElfRelocationHandler {

	private Map<Integer, T> relocationTypesMap;

	/**
	 * Abstract constructor for an {@link AbstractElfRelocationHandler}.
	 * 
	 * @param relocationEnumClass specifies the {@link ElfRelocationType} enum which defines
	 * all supported relocation types for this relocation handler.
	 */
	protected AbstractElfRelocationHandler(Class<T> relocationEnumClass) {
		super(); // must continue to use ElfRelocationHandler until eliminated
		initRelocationTypeMap(relocationEnumClass);
	}

	private void initRelocationTypeMap(Class<T> relocationEnumClass) {
		if (!relocationEnumClass.isEnum() ||
			!ElfRelocationType.class.isAssignableFrom(relocationEnumClass)) {
			throw new IllegalArgumentException(
				"Invalid class specified - expected enum which implements ElfRelocationType: " +
					relocationEnumClass.getName());
		}
		relocationTypesMap = new HashMap<>();
		for (T t : relocationEnumClass.getEnumConstants()) {
			relocationTypesMap.put(t.typeId(), t);
		}
	}

	/**
	 * Get the relocation type enum object which corresponds to the specified type ID value.
	 * 
	 * @param typeId relocation type ID value
	 * @return relocation type enum value or null if type not found or this handler was not
	 * constructed with a {@link ElfRelocationType} enum class.  The returned value may be
	 * safely cast to the relocation enum class specified during handler construction.
	 */
	public T getRelocationType(int typeId) {
		if (relocationTypesMap == null) {
			return null;
		}
		return relocationTypesMap.get(typeId);
	}

	/**
	 * Perform relocation fixup.
	 *
	 * @param elfRelocationContext relocation context
	 * @param relocation ELF relocation
	 * @param relocationAddress relocation target address (fixup location)
	 * @return applied relocation result (conveys status and applied byte-length)
	 * @throws MemoryAccessException memory access failure
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected final RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, Address relocationAddress) throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();

		int symbolIndex = relocation.getSymbolIndex();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);

		int typeId = relocation.getType();
		if (typeId == 0) {
			return RelocationResult.SKIPPED;
		}

		T type = getRelocationType(typeId);
		if (type == null) {
			markAsUndefined(program, relocationAddress, typeId, symbolName, symbolIndex,
				elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		}

		return relocate((C) elfRelocationContext, relocation, type, relocationAddress, sym,
			symbolAddr, symbolValue, symbolName);
	}

	/**
	 * Perform relocation fixup.
	 *
	 * @param elfRelocationContext relocation context
	 * @param relocation ELF relocation
	 * @param relocationType ELF relocation type enum value
	 * @param relocationAddress relocation target address (fixup location)
	 * @param elfSymbol relocation symbol (may be null)
	 * @param symbolAddr elfSymbol memory address (may be null)
	 * @param symbolValue unadjusted elfSymbol value (0 if no symbol)
	 * @param symbolName elfSymbol name (may be null)
	 * @return applied relocation result (conveys status and applied byte-length)
	 * @throws MemoryAccessException memory access failure
	 */
	protected abstract RelocationResult relocate(C elfRelocationContext, ElfRelocation relocation,
			T relocationType, Address relocationAddress, ElfSymbol elfSymbol, Address symbolAddr,
			long symbolValue, String symbolName) throws MemoryAccessException;

	//
	// Error and Warning markup methods
	//

//	private String getRelocationTypeDetail(int typeId) {
//		T relocationType = relocationTypesMap.get(typeId);
//		if (relocationType == null) {
//			return getDefaultRelocationTypeDetail(typeId);
//		}
//		return getRelocationTypeDetail(relocationType);
//	}

	private String getRelocationTypeDetail(T relocationType) {
		int typeId = relocationType.typeId();
		return relocationType.name() + " (" + typeId + ", 0x" + Integer.toHexString(typeId) + ")";
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating an unspportable
	 * COPY relocation.  A warning is produced for this COPY relocation failure.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param relocationType relocation type
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param symbolSize number of bytes associated with symbol that failed to be copied
	 * @param log import log
	 */
	protected void markAsUnsupportedCopy(Program program, Address relocationAddress,
			T relocationType, String symbolName, int symbolIndex, long symbolSize, MessageLog log) {
		markAsWarning(program, relocationAddress, relocationType, symbolName, symbolIndex,
			"Runtime copy not supported (" + symbolSize + "-bytes)", log);
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unhandled relocation.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	protected void markAsUndefined(Program program, Address relocationAddress, int typeId,
			String symbolName, int symbolIndex, MessageLog log) {
		markupErrorOrWarning(program, "Undefined ELF Relocation", null, relocationAddress,
			getDefaultRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.ERROR,
			log);
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unhandled relocation.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param relocationType relocation type
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	protected void markAsUnhandled(Program program, Address relocationAddress, T relocationType,
			int symbolIndex, String symbolName, MessageLog log) {
		markupErrorOrWarning(program, "Unhandled ELF Relocation", null, relocationAddress,
			getRelocationTypeDetail(relocationType), symbolIndex, symbolName, BookmarkType.ERROR,
			log);
	}

	/**
	 * Generate relocation warning log entry and bookmark at relocationAddress.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param relocationType relocation type
	 * @param symbolName symbol name
	 * @param symbolIndex symbol index (-1 to ignore)
	 * @param msg message associated with warning
	 * @param log import log
	 */
	protected void markAsWarning(Program program, Address relocationAddress, T relocationType,
			String symbolName, int symbolIndex, String msg, MessageLog log) {
		markupErrorOrWarning(program, "ELF Relocation Failure", msg, relocationAddress,
			getRelocationTypeDetail(relocationType), symbolIndex, symbolName, BookmarkType.WARNING,
			log);
	}

	/**
	 * Generate relocation error log entry and bookmark at relocationAddress.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param relocationType relocation type
	 * @param symbolName associated symbol name
	 * @param symbolIndex symbol index (-1 to ignore)
	 * @param msg additional error message
	 * @param log import log
	 */
	protected void markAsError(Program program, Address relocationAddress, T relocationType,
			String symbolName, int symbolIndex, String msg, MessageLog log) {
		markupErrorOrWarning(program, "Elf Relocation Failure", msg, relocationAddress,
			getRelocationTypeDetail(relocationType), symbolIndex, symbolName, BookmarkType.ERROR,
			log);
	}

//	@Override
//	protected void markAsError(Program program, Address relocationAddress, int typeId,
//			String symbolName, int symbolIndex, String msg, MessageLog log) {
//		markupErrorOrWarning(program, "ELF Relocation Error", msg, relocationAddress,
//			getRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.ERROR, log);
//	}

}
