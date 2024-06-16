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
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.NotFoundException;

/**
 * NOTE: ELF relocation handler implementations should extend {@link AbstractElfRelocationHandler} 
 * which now uses {@link ElfRelocationType} enum values instead of simple constants.  This class may 
 * transition to an interface in the future.  This abstract class remains exposed for backward 
 * compatibility with older implementations.
 * <br>
 * <code>ElfRelocationHandler</code> provides the base class for processor specific
 * ELF relocation handlers.  Implementations may only specify a public default constructor
 * as they will be identified and instatiated by the {@link ClassSearcher}.  As such their
 * name must end with "ElfRelocationHandler" (e.g., MyProc_ElfRelocationHandler).
 */
abstract public class ElfRelocationHandler implements ExtensionPoint {

	/**
	 * Fabricated Global Offset Table (GOT) name/prefix to be used when processing an object module
	 * and a GOT must be fabricated to allow relocation processing.
	 */
	public static final String GOT_BLOCK_NAME = "%got";

	/**
	 * Default abstract constructor for an {@link ElfRelocationHandler}.
	 * 
	 * @deprecated extending {@link AbstractElfRelocationHandler} in conjunction with the use of 
	 * a processor-specific {@link ElfRelocationType} enum is now preferred.
	 */
	@Deprecated(since = "11.1", forRemoval = true)
	protected ElfRelocationHandler() {
		// enumTypesMap use is not supported
	}

	abstract public boolean canRelocate(ElfHeader elf);

	/**
	 * Get the architecture-specific relative relocation type which should be applied to 
	 * RELR relocations.  The default implementation returns 0 which indicates RELR is unsupported.
	 * 
	 * @return RELR relocation type ID value
	 */
	public int getRelrRelocationType() {
		return 0;
	}

	/**
	 * Relocation context for a specific Elf image and relocation table.  The relocation context
	 * is used to process relocations and manage any data required to process relocations.
	 * 
	 * @param loadHelper Elf load helper
	 * @param symbolMap Elf symbol placement map
	 * @return relocation context or null if unsupported
	 */
	@SuppressWarnings("rawtypes")
	protected ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return null;
	}

	/**
	 * Perform relocation fixup.
	 * <br>
	 * IMPORTANT: this class must be overriden if this implementation does not specify an
	 * {@link ElfRelocationType} enum class (see {@link #ElfRelocationHandler()}).
	 * 
	 * @param elfRelocationContext relocation context
	 * @param relocation ELF relocation
	 * @param relocationAddress relocation target address (fixup location)
	 * @return applied relocation result (conveys status and applied byte-length)
	 * @throws MemoryAccessException memory access failure
	 * @throws NotFoundException NOTE: use of this exception is deprecated and should not be thrown
	 */
	@SuppressWarnings("rawtypes")
	protected abstract RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException;

	//
	// Error and Warning markup methods
	//

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unhandled relocation.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value
	 * @param symbolName associated symbol name
	 * @param symbolIndex symbol index within symbol table (-1 to ignore)
	 * @param log import log
	 */
	protected void markAsUnhandled(Program program, Address relocationAddress, int typeId,
			String symbolName, int symbolIndex, MessageLog log) {
		markupErrorOrWarning(program, "Unhandled ELF Relocation", null, relocationAddress,
			getDefaultRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.ERROR,
			log);
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress where relocation failed to 
	 * be applied.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value
	 * @param symbolName associated symbol name
	 * @param symbolIndex symbol index within symbol table (-1 to ignore)
	 * @param msg error message
	 * @param log import log
	 */
	protected void markAsError(Program program, Address relocationAddress, int typeId,
			String symbolName, int symbolIndex, String msg, MessageLog log) {
		markupErrorOrWarning(program, "ELF Relocation Error", msg, relocationAddress,
			getDefaultRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.ERROR,
			log);
	}

	/**
	 * Generate warning log entry and bookmark at relocationAddress where relocation failed to 
	 * be applied.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value
	 * @param symbolName associated symbol name
	 * @param symbolIndex symbol index within symbol table (-1 to ignore)
	 * @param msg error message
	 * @param log import log
	 */
	protected void markAsWarning(Program program, Address relocationAddress, int typeId,
			String symbolName, int symbolIndex, String msg, MessageLog log) {
		markupErrorOrWarning(program, "ELF Relocation Warning", msg, relocationAddress,
			getDefaultRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.WARNING,
			log);
	}

	//
	// Static methods
	//

	/**
	 * Apply a pointer-typedef with a specified component-offset if specified address
	 * is not contained within an execute block.
	 * 
	 * @param program program
	 * @param addr address where data should be applied
	 * @param componentOffset component offset
	 */
	public static void applyComponentOffsetPointer(Program program, Address addr,
			long componentOffset) {

		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || block.isExecute()) {
			return; // avoid pointer creation where instruction may reside
		}

		PointerTypedef dt =
			new PointerTypedef(null, null, -1, program.getDataTypeManager(), componentOffset);
		try {
			DataUtilities.createData(program, addr, dt, -1,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(ElfRelocationHandler.class,
				"Failed to apply component-offset pointer at " + addr);
		}
	}

	/**
	 * Determine if symbolAddr is contained within the EXTERNAL block with a non-zero adjustment.  
	 * If so, relocationAddress will be marked with a <code>EXTERNAL Data Elf Relocation with pointer-offset</code> 
	 * warning or error bookmark.  Bookmark and logged message will be conveyed as an error if 
	 * relocationAddress resides within an executable memory block.
	 * <br>
	 * NOTE: This method should only be invoked when the symbol offset will be adjusted with a non-zero 
	 * value (i.e., addend).
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked if EXTERNAL block relocation
	 * @param symbolAddr symbol address correspondng to relocation (may be null)
	 * @param symbolName symbol name (may not be null if symbolAddr is not null)
	 * @param adjustment relocation symbol offset adjustment/addend
	 * @param log import log
	 */
	public static void warnExternalOffsetRelocation(Program program, Address relocationAddress,
			Address symbolAddr, String symbolName, long adjustment, MessageLog log) {

		if (symbolAddr == null || adjustment == 0 ||
			!program.getMemory().isExternalBlockAddress(symbolAddr)) {
			return;
		}

		MemoryBlock block = program.getMemory().getBlock(relocationAddress);

		boolean showAsError = block == null || block.isExecute();

		String sign = "+";
		if (adjustment < 0) {
			adjustment = -adjustment;
			sign = "-";
		}
		String adjStr = sign + "0x" + Long.toHexString(adjustment);

		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		String msg1 = "EXTERNAL Data ELF Relocation with offset: at " + relocationAddress +
			" (External Location = " + symbolName + adjStr + ")";
		if (showAsError) {
			Msg.error(ElfRelocationHandler.class, msg1);
		}
		else {
			Msg.warn(ElfRelocationHandler.class, msg1);
		}
		if (block != null) {
			BookmarkManager bookmarkManager = program.getBookmarkManager();
			bookmarkManager.setBookmark(relocationAddress, BookmarkType.WARNING,
				"EXTERNAL Relocation",
				"EXTERNAL Data ELF Relocation with offset: External Location = " + symbolName +
					adjStr);
		}
	}

	/**
	 * Get default relocation type details.  This will not provide the name of the relocation 
	 * type and must be used for static method invocations or a specific relocation enum type
	 * is not found.
	 * 
	 * @param typeId relocation type ID value
	 * @return formatted relocation type detail for logging
	 */
	static String getDefaultRelocationTypeDetail(int typeId) {
		return "Type = " + Integer.toUnsignedLong(typeId) + " (0x" + Integer.toHexString(typeId) +
			")";
	}

	/**
	 * Generate error bookmark at relocationAddress indicating a missing relocation handler.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value
	 * @param symbolIndex associated symbol index within symbol table (-1 to ignore)
	 * @param symbolName associated symbol name
	 */
	public static void bookmarkNoHandlerError(Program program, Address relocationAddress,
			int typeId, int symbolIndex, String symbolName) {
		markupErrorOrWarning(program, "No relocation handler", null, relocationAddress,
			getDefaultRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.ERROR,
			null); // null log to prevent logging
	}

	/**
	 * Generate error bookmark at relocationAddress indicating an unsupported RELR relocation.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param symbolIndex associated symbol index within symbol table (-1 to ignore)
	 * @param symbolName associated symbol name
	 */
	public static void bookmarkUnsupportedRelr(Program program, Address relocationAddress,
			int symbolIndex, String symbolName) {
		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		String symbolIndexStr =
			symbolIndex < 0 ? "" : (" (0x" + Integer.toHexString(symbolIndex) + ")");
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR, "Relocation",
			"Unsupported RELR Relocation: Symbol = " + symbolName + symbolIndexStr +
				" - ELF Extension does not specify type");
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type
	 * @param symbolIndex associated symbol index within symbol table (-1 to ignore)
	 * @param symbolName associated symbol name
	 * @param msg error messge
	 * @param log import log
	 */
	public static void markAsError(Program program, Address relocationAddress, int typeId,
			int symbolIndex, String symbolName, String msg, MessageLog log) {
		markupErrorOrWarning(program, "Elf Relocation Error", msg, relocationAddress,
			getDefaultRelocationTypeDetail(typeId), symbolIndex, symbolName, BookmarkType.ERROR,
			log);
	}

	/**
	 * Generate error or warning log entry and bookmark at relocationAddress indicating a
	 * relocation failure.
	 * 
	 * @param program program
	 * @param mainMsg relocation error message (required)
	 * @param tailMsg relocation error cause (optional, may be null)
	 * @param relocationAddress relocation address to be bookmarked
	 * @param relocTypeDetail relocation type detail
	 * @param symbolIndex associated symbol index within symbol table (-1 to ignore)
	 * @param symbolName associated symbol name
	 * @param bookmarkType bookmark type: ({@link BookmarkType#ERROR} or ({@link BookmarkType#WARNING}
	 * @param log import log or null if no logging required
	 */
	static void markupErrorOrWarning(Program program, String mainMsg, String tailMsg,
			Address relocationAddress, String relocTypeDetail, int symbolIndex, String symbolName,
			String bookmarkType, MessageLog log) {
		tailMsg = StringUtils.isEmpty(tailMsg) ? "" : (" - " + tailMsg);
		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		String symbolIndexStr =
			symbolIndex < 0 ? "" : (" (0x" + Integer.toHexString(symbolIndex) + ")");
		if (log != null) {
			log.appendMsg(mainMsg + ": " + relocTypeDetail + " at " + relocationAddress +
				" (Symbol = " + symbolName + ")" + tailMsg);
		}
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, bookmarkType, "Relocation", mainMsg + ": " +
			relocTypeDetail + " Symbol = " + symbolName + symbolIndexStr + tailMsg);
	}

	//
	// Deprecated methods
	//

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unhandled relocation.
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value (limited to int value). 
	 * @param symbolIndex associated symbol index within symbol table (limited to int value).
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	@Deprecated
	public static void markAsUnhandled(Program program, Address relocationAddress, long typeId,
			long symbolIndex, String symbolName, MessageLog log) {
		markupErrorOrWarning(program, "Unhandled ELF Relocation", null, relocationAddress,
			getDefaultRelocationTypeDetail((int) typeId), (int) symbolIndex, symbolName,
			BookmarkType.ERROR, log);
	}

	/**
	 * Generate warning log entry and bookmark at relocationAddress
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type ID name
	 * @param msg message associated with warning
	 * @param log import log
	 */
	@Deprecated
	public static void markAsWarning(Program program, Address relocationAddress, String type,
			String msg, MessageLog log) {
		markAsWarning(program, relocationAddress, type, null, -1, msg, log);
	}

	/**
	 * Generate warning log entry and bookmark at relocationAddress
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type ID name
	 * @param symbolName symbol name
	 * @param symbolIndex symbol index (-1 to ignore)
	 * @param msg message associated with warning
	 * @param log import log
	 */
	@Deprecated
	public static void markAsWarning(Program program, Address relocationAddress, String type,
			String symbolName, int symbolIndex, String msg, MessageLog log) {
		markupErrorOrWarning(program, "Elf Relocation Warning", msg, relocationAddress,
			"Type = " + type, symbolIndex, symbolName, BookmarkType.WARNING, log);
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param typeId relocation type ID value
	 * @param symbolName associated symbol name
	 * @param msg error messge
	 * @param log import log
	 */
	@Deprecated
	public static void markAsError(Program program, Address relocationAddress, long typeId,
			String symbolName, String msg, MessageLog log) {
		markAsError(program, relocationAddress, typeId + " (0x" + Long.toHexString(typeId) + ")",
			symbolName, msg, log);
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress
	 * 
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type ID name
	 * @param symbolName associated symbol name
	 * @param msg additional error message
	 * @param log import log
	 */
	@Deprecated
	public static void markAsError(Program program, Address relocationAddress, String type,
			String symbolName, String msg, MessageLog log) {
		markupErrorOrWarning(program, "Elf Relocation Error", msg, relocationAddress,
			"Type = " + type, -1, symbolName, BookmarkType.ERROR, log);
	}

}
