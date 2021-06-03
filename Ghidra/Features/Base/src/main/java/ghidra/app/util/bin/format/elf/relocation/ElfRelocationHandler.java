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
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.NotFoundException;

/**
 * <code>ElfRelocationHandler</code> provides the base class for processor specific
 * ELF relocation handlers.  
 */
abstract public class ElfRelocationHandler implements ExtensionPoint {

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
	 * @param relocationTable Elf relocation table
	 * @param symbolMap Elf symbol placement map
	 * @return relocation context or null if unsupported
	 */
	public ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
		return null;
	}

	/**
	 * Perform relocation fixup
	 * @param elfRelocationContext relocation context
	 * @param relocation ELF relocation
	 * @param relocationAddress relocation target address (fixup location)
	 * @throws MemoryAccessException memory access failure
	 * @throws NotFoundException required relocation data not found
	 */
	abstract public void relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException;

	/**
	 * Generate error log entry and bookmark at relocationAddress indicating 
	 * an unhandled relocation.
	 * @param program 
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	public static void markAsUnhandled(Program program, Address relocationAddress, long type,
			long symbolIndex, String symbolName, MessageLog log) {

		symbolName = symbolName == null ? "<no name>" : symbolName;
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
	 * @param program 
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
	 * @param program 
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolIndex associated symbol index within symbol table
	 * @param symbolName associated symbol name
	 * @param log import log
	 */
	public static void markAsUninitializedMemory(Program program, Address relocationAddress,
			long type, long symbolIndex, String symbolName, MessageLog log) {

		symbolName = symbolName == null ? "<no name>" : symbolName;
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
	 * @param program 
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolName associated symbol name
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
	 * @param program 
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolName associated symbol name
	 * @param msg additional error message
	 * @param log import log
	 */
	public static void markAsError(Program program, Address relocationAddress, String type,
			String symbolName, String msg, MessageLog log) {

		symbolName = symbolName == null ? "<no name>" : symbolName;
		log.appendMsg("Elf Relocation Error: Type = " + type + " at " + relocationAddress +
			", Symbol = " + symbolName + ": " + msg);
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(relocationAddress, BookmarkType.ERROR, "Relocation_" + type,
			"Elf Relocation Error: Symbol = " + symbolName + ": " + msg);
	}

	/**
	 * Generate warning log entry and bookmark at relocationAddress where
	 * import issue occurred.
	 * @param program 
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
	 * @param program 
	 * @param relocationAddress relocation address to be bookmarked
	 * @param type relocation type
	 * @param symbolName symbol name
	 * @param symbolIndex symbol index
	 * @param msg message associated with warning
	 * @param log import log
	 */
	public static void markAsWarning(Program program, Address relocationAddress, String type,
			String symbolName, long symbolIndex, String msg, MessageLog log) {
		
		symbolName = symbolName == null ? "<no name>" : symbolName;
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
