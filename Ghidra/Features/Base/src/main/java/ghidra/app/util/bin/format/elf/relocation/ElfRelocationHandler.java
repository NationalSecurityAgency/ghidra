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
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.NotFoundException;

/**
 * <code>ElfRelocationHandler</code> provides the base class for processor specific
 * ELF relocation handlers.  
 */
abstract public class ElfRelocationHandler implements ExtensionPoint {

	/**
	 * Fabricated Global Offset Table (GOT) name/prefix to be used when processing an object module
	 * and a GOT must be fabricated to allow relocation processing.
	 */
	public static final String GOT_BLOCK_NAME = "%got";

	abstract public boolean canRelocate(ElfHeader elf);

	/**
	 * Get the architecture-specific relative relocation type 
	 * which should be applied to RELR relocations.  The
	 * default implementation returns 0 which indicates 
	 * RELR is unsupported.
	 * @return RELR relocation type 
	 */
	public int getRelrRelocationType() {
		return 0;
	}

	/**
	 * Relocation context for a specific Elf image and relocation table.  The relocation context
	 * is used to process relocations and manage any data required to process relocations.
	 * @param loadHelper Elf load helper
	 * @param symbolMap Elf symbol placement map
	 * @return relocation context or null if unsupported
	 */
	public ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return null;
	}

	/**
	 * Perform relocation fixup
	 * @param elfRelocationContext relocation context
	 * @param relocation ELF relocation
	 * @param relocationAddress relocation target address (fixup location)
	 * @return applied relocation result (conveys status and applied byte-length)
	 * @throws MemoryAccessException memory access failure
	 * @throws NotFoundException required relocation data not found
	 */
	abstract public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException;

	/**
	 * Apply a pointer-typedef with a specified component-offset if specified address
	 * is not contained within an execute block.
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
	 * NOTE: This method should only be invoked when the symbol offset will be adjusted with a non-zero 
	 * value (i.e., addend).
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked if EXTERNAL block relocation
	 * @param symbolAddr symbol address correspondng to relocation (may be null)
	 * @param symbolName symbol name (may not be null if symbolAddr is not null)
	 * @param adjustment relocation symbol offset adjustment/addend
	 * @param log import log
	 */
	public static void warnExternalOffsetRelocation(Program program,
			Address relocationAddress, Address symbolAddr, String symbolName, long adjustment,
			MessageLog log) {

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
		String msg1 = "EXTERNAL Data Elf Relocation with offset: at " + relocationAddress +
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
				"EXTERNAL Data Elf Relocation with offset: External Location = " + symbolName +
					adjStr);
		}
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unhandled relocation.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	public static void markAsUnhandled(Program program, Address relocationAddress, long type,
			long symbolIndex, String symbolName, MessageLog log) {

		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		log.appendMsg("Unhandled Elf Relocation: Type = " + type + " (0x" + Long.toHexString(type) +
			") at " + relocationAddress + " (Symbol = " + symbolName + ")");
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR,
			"Relocation Type " + type,
			"Unhandled Elf Relocation: Type = " + type + " (0x" + Long.toHexString(type) +
				") Symbol = " + symbolName + " (0x" + Long.toHexString(symbolIndex) + ").");
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unsupported RELR relocation.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 */
	public static void markAsUnsupportedRelr(Program program, Address relocationAddress) {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR,
			"Unsupported RELR Relocation", "ELF Extension does not specify type");
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress where
	 * import failed to transition block to initialized while processing relocation.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	public static void markAsUninitializedMemory(Program program, Address relocationAddress,
			long type, long symbolIndex, String symbolName, MessageLog log) {

		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		log.appendMsg("Unable to perform relocation: Type = " + type + " (0x" +
			Long.toHexString(type) + ") at " + relocationAddress + " (Symbol = " + symbolName +
			") - uninitialized memory");
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR,
			"Relocation_Type_" + type,
			"Unable to perform relocation: Type = " + type + " (0x" + Long.toHexString(type) +
				") Symbol = " + symbolName + " (0x" + Long.toHexString(symbolIndex) +
				") - uninitialized memory.");
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress where
	 * import failed to be applied.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolName associated symbol name
	 * @param msg error messge
	 * @param log import log
	 */
	public static void markAsError(Program program, Address relocationAddress, long type,
			String symbolName, String msg, MessageLog log) {
		markAsError(program, relocationAddress, type + " (0x" + Long.toHexString(type) + ")",
			symbolName, msg, log);
	}

	/**
	 * Generate error log entry and bookmark at relocationAddress where
	 * import failed to be applied.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolName associated symbol name
	 * @param msg additional error message
	 * @param log import log
	 */
	public static void markAsError(Program program, Address relocationAddress, String type,
			String symbolName, String msg, MessageLog log) {

		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		log.appendMsg("Elf Relocation Error: Type = " + type + " at " + relocationAddress +
			", Symbol = " + symbolName + ": " + msg);
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR, "Relocation_" + type,
			"Elf Relocation Error: Symbol = " + symbolName + ": " + msg);
	}

	/**
	 * Generate warning log entry and bookmark at relocationAddress where
	 * import issue occurred.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param msg message associated with warning
	 * @param log import log
	 */
	public static void markAsWarning(Program program, Address relocationAddress, String type,
			String msg, MessageLog log) {

		markAsWarning(program, relocationAddress, type, null, 0, msg, log);
	}

	/**
	 * Generate warning log entry and bookmark at relocationAddress where
	 * import issue occurred.
	 * @param program program
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolName symbol name
	 * @param symbolIndex symbol index
	 * @param msg message associated with warning
	 * @param log import log
	 */
	public static void markAsWarning(Program program, Address relocationAddress, String type,
			String symbolName, long symbolIndex, String msg, MessageLog log) {
		
		symbolName = StringUtils.isEmpty(symbolName) ? ElfSymbol.FORMATTED_NO_NAME : symbolName;
		log.appendMsg("Elf Relocation Warning: Type = " + type + " at " + relocationAddress +
			", Symbol = " + symbolName + ": " + msg);
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.WARNING,
			"Relocation_Type_" + type,
			"Unhandled Elf relocation ("+type+") at address: " + relocationAddress +
				". Symbol = " + symbolName + " (" + Long.toHexString(symbolIndex) + ")" +
				". " + msg);
	}

}
