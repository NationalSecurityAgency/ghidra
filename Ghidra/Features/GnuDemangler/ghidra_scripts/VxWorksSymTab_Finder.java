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
// Locates and parses the VxWorks symbol table.  Names the table "vxSymTbl"
// and names the table length variable "vxSymTblLen" (if the length variable
// appears either directly before or after the symbol table).  Defines the
// symbol table as SYMBOL[vxSymTblLen].
//
// Extracts symbol name, location, and type from each entry.  Disassembles,
// creates, and names functions.  Names global variables.
//
// Any existing Ghidra symbol table entries that collide with VxWorks symbol
// table entries are deleted.  Mangled C++ symbol names are demangled.
//
// The VxWorks symbol table is an array [0..n-1] of (struct SYMBOL) entries.
// The table may be immediately followed or preceeded by an (int) vxSymTblLen
// value.
//
// Prerequisites:
//
//		- Program memory block(s) is(are) aligned with actual load addresses
//		  (run something like MemAlignARM_LE.java)
//
//		- Symbol table cannot be in a memory block with a name that contains
//		  the string "text" or "bss"
//
//		- Modify getVxSymbolClass() to recognize your program's VxWorks
//		  symbol table entry structure, if necessary
//
// @category VxWorks

import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class VxWorksSymTab_Finder extends GhidraScript {

	boolean debug = false;

	//------------------------------------------------------------------------
	// getDataTypeManagerByName
	//
	// Retrieves data type manager by name.
	//
	// Returns:
	//		Success: DataTypeManager
	//		Failure: null
	//------------------------------------------------------------------------
	private DataTypeManager getDataTypeManagerByName(String name) {

		DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);

		// Loop through all managers in the data type manager service
		for (DataTypeManager manager : service.getDataTypeManagers()) {
			if (manager.getName().equals(name)) {
				return manager;
			}
		}
		return null;
	}

	//------------------------------------------------------------------------
	// VxSymbol
	//
	// Contains a SYMBOL data type representing a VxWorks symbol table entry
	// and several associated methods.
	//------------------------------------------------------------------------
	private class VxSymbol {

		StructureDataType dt = null;
		int nameOffset = 0;
		int locOffset = 0;
		int typeOffset = 0;
		int length = 0;

		public VxSymbol(StructureDataType struct) {
			dt = struct;
			nameOffset = getFieldOffset(dt, "symNameOff");
			locOffset = getFieldOffset(dt, "symLocOff");
			typeOffset = getFieldOffset(dt, "symType");
			length = dt.getLength();
		}

		private int getFieldOffset(StructureDataType dataType, String name) {
			for (DataTypeComponent comp : dataType.getComponents()) {
				if (comp.getFieldName().equals(name)) {
					return comp.getOffset();
				}
			}
			return -1;
		}

		public DataType dataType() {
			return dt;
		}

		public int length() {
			return length;
		}

		public int nameOffset() {
			return nameOffset;
		}

		public int locOffset() {
			return locOffset;
		}

		public int typeOffset() {
			return typeOffset;
		}

		// Add SYMBOL data type to Program DataTypeManager
		// (if data type already exists, replace it)
		public void createGhidraType() {
			currentProgram.getDataTypeManager()
					.addDataType(dt,
						DataTypeConflictHandler.REPLACE_HANDLER);
		}
	}

	//------------------------------------------------------------------------
	// getVxSymbolClass
	//
	// Creates a SYMBOL structure data type and uses it to create a new
	// VxSymbol class instance.
	//
	// Returns:
	//		Success: VxSymbol
	//		Failure: null
	//------------------------------------------------------------------------
	private VxSymbol getVxSymbolClass(int type) {

		// Pre-define base data types used to define symbol table entry data type
		DataTypeManager builtin = getDataTypeManagerByName("BuiltInTypes");
		DataType charType = builtin.getDataType("/char");
		DataType charPtrType = PointerDataType.getPointer(charType, 4);
		DataType byteType = builtin.getDataType("/byte");
		DataType ushortType = builtin.getDataType("/ushort");
		DataType intType = builtin.getDataType("/int");
		DataType uintType = builtin.getDataType("/uint");
		DataType voidType = builtin.getDataType("/void");
		DataType voidPtrType = PointerDataType.getPointer(voidType, 4);

		// Define a SYMBOL data type (try to put most common first).
		// Each SYMBOL data type must include at least 3 fields named
		// symNameOff, symLocOff, and symType.
		StructureDataType dt = null;
		switch (type) {
			case 0:

				// Version 5.4, 6.4 and 6.8
				//
				// Total length: 0x14 bytes
				//    0x00    uint symHashNode	// NULL
				//    0x04    char *symNameOff
				//    0x08    void *symLocOff
				//    0x0c    int NULL
				//    0x10    ushort symGroup
				//    0x12    uchar symType
				//    0x13    uchar undef
				dt = new StructureDataType("SYMBOL", 0x14);
				dt.replaceAtOffset(0, uintType, 4, "symHashNode", "");
				dt.replaceAtOffset(4, charPtrType, 4, "symNameOff", "");
				dt.replaceAtOffset(8, voidPtrType, 4, "symLocOff", "");
				dt.replaceAtOffset(0x0c, intType, 4, "", "");
				dt.replaceAtOffset(0x10, ushortType, 2, "symGroup", "");
				dt.replaceAtOffset(0x12, byteType, 1, "symType", "");
				break;

			case 1:

				// Version 6.1
				//
				// Total length: 0x18 bytes
				//    0x00    uint symHashNode	// NULL
				//    0x04    char *symNameOff
				//    0x08    void *symLocOff
				//    0x0c    int NULL
				//    0x10    int NULL
				//    0x14    uchar symType
				//    0x15    uchar undef[3]
				dt = new StructureDataType("SYMBOL", 0x18);
				dt.replaceAtOffset(0, uintType, 4, "symHashNode", "");
				dt.replaceAtOffset(4, charPtrType, 4, "symNameOff", "");
				dt.replaceAtOffset(8, voidPtrType, 4, "symLocOff", "");
				dt.replaceAtOffset(0x0c, intType, 4, "", "");
				dt.replaceAtOffset(0x10, intType, 4, "", "");
				dt.replaceAtOffset(0x14, byteType, 1, "symType", "");
				break;

			case 2:

				// Unknown VxWorks version(s)
				//
				// Total length: 0x1c bytes
				//    0x00    uint symHashNode	// NULL
				//    0x04    char *symNameOff
				//    0x08    void *symLocOff
				//    0x0c    int unk;				// no clear pattern to values
				//    0x10    int NULL
				//    0x14    int NULL
				//    0x18    uchar symType
				//    0x19    uchar undef[3]
				dt = new StructureDataType("SYMBOL", 0x1c);
				dt.replaceAtOffset(0, uintType, 4, "symHashNode", "");
				dt.replaceAtOffset(4, charPtrType, 4, "symNameOff", "");
				dt.replaceAtOffset(8, voidPtrType, 4, "symLocOff", "");
				dt.replaceAtOffset(0x0c, intType, 4, "", "");
				dt.replaceAtOffset(0x10, intType, 4, "", "");
				dt.replaceAtOffset(0x14, intType, 4, "", "");
				dt.replaceAtOffset(0x18, byteType, 1, "symType", "");
				break;

			case 3:

				// Version 5.5
				//
				// Total length: 0x10 bytes
				//    0x00    uint symHashNode	// NULL
				//    0x04    char *symNameOff
				//    0x08    void *symLocOff
				//    0x0c    ushort symGroup		// NULL
				//    0x0e    uchar symType
				//    0x0f    uchar undef
				dt = new StructureDataType("SYMBOL", 0x10);
				dt.replaceAtOffset(0, uintType, 4, "symHashNode", "");
				dt.replaceAtOffset(4, charPtrType, 4, "symNameOff", "");
				dt.replaceAtOffset(8, voidPtrType, 4, "symLocOff", "");
				dt.replaceAtOffset(0x0c, ushortType, 2, "symGroup", "");
				dt.replaceAtOffset(0x0e, byteType, 1, "symType", "");
				break;

			default:

				return null;
		}

		// Return a VxSymbol class for this SYMBOL data type
		return new VxSymbol(dt);
	}

	//------------------------------------------------------------------------
	// isExecute
	//
	// Is address in an executable memory block?
	//------------------------------------------------------------------------
	private boolean isExecute(Address addr) {

		// Search all program memory blocks
		for (MemoryBlock block : getMemoryBlocks()) {
			if (block.contains(addr)) {
				return block.isExecute();
			}
		}

		return false;
	}

	//------------------------------------------------------------------------
	// isAddress
	//
	// Is offset in an existing memory block?
	//------------------------------------------------------------------------
	private boolean isAddress(long offset) {

		// Search all program memory blocks
		for (MemoryBlock block : getMemoryBlocks()) {

			if (block.getStart().getOffset() <= offset && block.getEnd().getOffset() >= offset) {
				return true;
			}
		}
		return false;    // no match
	}

	//------------------------------------------------------------------------
	// isAddress
	//
	// Is offset in the specified memory block?
	//------------------------------------------------------------------------
	private boolean isAddress(long offset, MemoryBlock block) {

		if (block.getStart().getOffset() <= offset && block.getEnd().getOffset() >= offset) {
			return true;
		}
		return false;
	}

	//------------------------------------------------------------------------
	// isString
	//
	// Are the bytes starting at addr a C string?
	//
	// Algorithm:  Scan bytes until finding either an invalid char or null.
	//             If scan stops at null, return true -- else false.
	//------------------------------------------------------------------------
	private boolean isString(Address addr) {
		byte _byte;

		try {
			_byte = getByte(addr);
		}
		catch (Exception except) {
			return false;
		}

		while (	// May need to add valid character examples here.
		(_byte == 0x09 || _byte == 0x0a || _byte == 0x0d || (_byte > 0x19 && _byte < 0x80)) &&
			_byte != 0x00) {

			if (monitor.isCancelled()) {
				return false;
			}

			addr = addr.add(1);
			try {
				_byte = getByte(addr);
			}
			catch (Exception except) {
				return false;
			}
		}

		if (_byte == 0x00) {
			return true;  // Scan stopped at null.
		}
		return false; // Scan stopped at invalid char.
	}

	//------------------------------------------------------------------------
	// clearString
	//
	// Remove data or instructions that overlap the null-terminated
	// string at addr (may happen if disassembly creates invalid references
	// or compiler optimization creates shared strings).
	//
	// Use get*Containing() in case a string that ends with the string
	// at addr has already been defined (e.g., the string at addr is
	// "CoolFunc" and the string "g_pfCoolFunc" overlaps it).
	//------------------------------------------------------------------------
	private void clearString(Address addr) throws Exception {
		Data data;
		Instruction inst;

		// Clear the string, breaking on the terminating null character
		while (getByte(addr) != 0) {
			data = getDataContaining(addr);
			if (data != null) {
				removeDataAt(data.getAddress());
			}
			inst = getInstructionContaining(addr);
			if (inst != null) {
				removeInstructionAt(inst.getAddress());
			}

			addr = addr.add(1);
		}

		// Now clear at string's terminating null character
		data = getDataContaining(addr);
		if (data != null) {
			removeDataAt(data.getAddress());
		}
		inst = getInstructionContaining(addr);
		if (inst != null) {
			removeInstructionAt(inst.getAddress());
		}
	}

	//------------------------------------------------------------------------
	// isSymTblEntry
	//
	// Does data pointed to by entry look like a VxWorks symbol table entry?
	// Test is weak.
	//------------------------------------------------------------------------
	private boolean isSymTblEntry(Address entry, VxSymbol vxSymbol) throws Exception {

		// First dword must be null or a valid ptr (typically into the sym table)
		long value = getInt(entry) & 0xffffffffL;
		if ((value != 0) && !isAddress(value)) {
			if (debug) {
				println("1: " + entry + " --> " + Long.toHexString(value));
			}
			return false;
		}

		// symNameOff field must point to a non-null C string
		value = getInt(entry.add(vxSymbol.nameOffset())) & 0xffffffffL;
		if (!isAddress(value)) {
			if (debug) {
				println("2: " + entry + " --> " + Long.toHexString(value));
			}
			return false;
		}
		Address symNameAddr = toAddr(value);
		if (!isString(symNameAddr)) {
			if (debug) {
				println("3: " + entry + " --> " + Long.toHexString(value));
			}
			return false;
		}
		if (getByte(symNameAddr) == 0) {
			return false;
		}

		// symLocOff field can be almost anything (e.g., external mem ref)
		//value = (long)getInt(entry.add(vxSymbol.locOffset())) & 0xffffffffL;
		//if (value == 0) {
		//	if (debug) println("4: " + entry);
		//	return false;
		//}

		// symType field must be recognized type code (this test is weak)
		byte symType = getByte(entry.add(vxSymbol.typeOffset()));
		if (!isValidSymType(symType)) {
			if (debug) {
				println("5: " + entry + " --> " + symType);
			}
			return false;
		}

		return true;
	}

	private boolean isValidSymType(byte symType) {
		switch (symType) {
			case 0: // Undefined Symbol
				return false;
			case 2: // Local Absolute
			case 3: // Global Absolute
			case 6: // Local Data
			case 7: // Global Data
			case 8: // Local BSS
			case 9: // Global BSS
			case 4: // Local .text
			case 5: // Global .text
			case 0x11: // External ref -- ignore
				return true;
			default:
				return false;
		}
	}

	//------------------------------------------------------------------------
	// findSymTbl
	//
	// Searches all memory blocks for data that looks like a run of testLen
	// VxWorks symbol table entries.
	//
	// Returns:
	//		Success: table address
	//		Failure: null
	//------------------------------------------------------------------------
	private Address findSymTbl(VxSymbol vxSymbol) throws Exception {

		int testLen = 100;		// number of symbol tbl entries to look for

		boolean hasNonExecute = checkNonExecute();

		// Iterate through all memory blocks
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {

			// Skip code/execute blocks if there are non-execute blocks,
			//  otherwise search everything.
			if (hasNonExecute && block.isExecute()) {
				continue;
			}

			// skip uninit
			if (!block.isInitialized()) {
				continue;
			}

			// Search current block for run of testLen symbol table entries
			int testBlkSize = vxSymbol.length * testLen;
			printf("   block: " + block.getName() + " (" + block.getStart() + ", " +
				block.getEnd() + ") ");
			printf("testBlkSize = " + Integer.toHexString(testBlkSize) + "  ");
			System.out.flush();
			long prevOffset = 0;
			Address cursor = block.getStart();
			while ((cursor != null) && isAddress(cursor.getOffset() + testBlkSize, block)) {

				// Script cancel check and visual feedback
				if (monitor.isCancelled()) {
					return null;
				}
				if ((cursor.getOffset() - prevOffset) >= 0x100000) {
					printf(".");
					System.out.flush();
					prevOffset = cursor.getOffset();
				}

				// Determine whether cursor now points to a symbol table
				int i = 0;
				for (Address entry = cursor; isSymTblEntry(entry, vxSymbol) &&
					(i < testLen); entry = entry.add(vxSymbol.length()), i++) {
				}
				if (i == testLen) {
					// May have symbol table -- verify length
					if (getSymTblLen(cursor, vxSymbol) != 0) {
						printf("\n");
						System.out.flush();
						return cursor;	// found  table -- stop searching
					}
					if (debug) {
						printf("Possible symbol table at " + cursor + " has length error\n");
					}
				}

				cursor = cursor.add(4);
			}
			printf("\n");
			printf("   search terminated at:  " + cursor + "\n");
			System.out.flush();
		}
		return null;
	}

	private boolean checkNonExecute() {
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isExecute()) {
				return true;
			}
		}
		return false;
	}

	//------------------------------------------------------------------------
	// getSymTblLen
	//
	// Counts number of entries in VxWorks table at address symTbl.
	//
	// Returns:
	//		Success: number of table entries (> 0)
	//		Failure: 0
	//------------------------------------------------------------------------
	private int getSymTblLen(Address symTbl, VxSymbol vxSymbol) throws Exception {

		Address entry = symTbl;
		int j = 0;
		while (isSymTblEntry(entry, vxSymbol)) {
			entry = entry.add(vxSymbol.length());
			j++;
		}

		return j;

		// NOTE: Found an example of a VxWorks symbol table that was not
		//	      directly adjacent to the symbol table length variable...
		//	      so removed the following constraint.

		/*
		// Symbol table length entry may be at beginning or end of the symbol
		// table...so compare computed length with both values.  If either
		// matches, table length is verified.
		if ((j == getInt(entry)) || (j == getInt(symTbl.subtract(4)))) {
			return j;
		} else {
			return 0;
		}
		*/
	}

	/**
	 * Look before/after the table to see if there is a size value there and mark it if it agrees with TableLen
	 * 
	 * @param symTbl
	 * @param vxSymbol
	 * @param tableLen
	 * @throws Exception
	 */
	private void markSymbolTableLen(Address symTbl, VxSymbol vxSymbol, int symTblLen)
			throws Exception {
		// NOTE: Found an example of a VxWorks symbol table that was not
		//	      directly adjacent to the symbol table length variable...

		// Name the VxWorks symbol length variable
		// (if it appears either directly before or after the symbol table)
		Address symTblLenPtr = null;
		long foreOff = symTbl.getOffset() - 4;
		long aftOff = symTbl.getOffset() + symTblLen * vxSymbol.length();
		if (isAddress(foreOff) && getInt(toAddr(foreOff)) == symTblLen) {
			symTblLenPtr = toAddr(foreOff);
		}
		else if (isAddress(aftOff) && getInt(toAddr(aftOff)) == symTblLen) {
			symTblLenPtr = toAddr(aftOff);
		}
		if (symTblLenPtr != null) {
			removeConflictingSymbols("vxSymTblLen", symTblLenPtr);
			createLabel(symTblLenPtr, "vxSymTblLen", true);
			createDWord(symTblLenPtr);
		}
		else {
			println("Warning: Symbol Table Size not found before of after table");
		}
	}

	//------------------------------------------------------------------------
	// removeConflictingSymbols
	//
	// Deletes all symbols with the same name and the primary symbol at addr.
	//------------------------------------------------------------------------
	private void removeConflictingSymbols(String name, Address addr) {

		// Delete any existing symbols with the same name
		for (Symbol sym : currentProgram.getSymbolTable().getSymbols(name)) {
			sym.delete();
		}

		// Delete primary Ghidra symbol at the same address
		Symbol sym = getSymbolAt(addr);
		if (sym != null) {
			sym.delete();
		}

		return;
	}

	//------------------------------------------------------------------------
	// applyDemangled
	//
	// Apply demangled symbol name to symbol.
	//------------------------------------------------------------------------
	private void applyDemangled(Address addr, String mangled, String demangled) {

		if (demangled != null) {
			new DemanglerCmd(addr, mangled).applyTo(currentProgram, monitor);
			List<Symbol> symbols =
				getSymbols(mangled, currentProgram.getGlobalNamespace());
			if (!symbols.isEmpty()) {
				currentProgram.getSymbolTable().removeSymbolSpecial(symbols.get(0));
			}
		}

		return;
	}

	//------------------------------------------------------------------------
	// doLocalDisassemble
	//
	// Do our own disassembly, and don't let auto-analysis start until after
	// this script finishes.  This speeds up the script substantially and
	// allows auto-analysis to operate with more information (and code/data
	// that isn't rapidly changing).
	//------------------------------------------------------------------------
	private void doLocalDisassemble(Address addr) {

		// Only disassemble in memory blocks marked executable
		if (!isExecute(addr)) {
			return;
		}

		DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
		cmd.enableCodeAnalysis(false);	// Queues changes up for later analysis
		cmd.applyTo(currentProgram, monitor);

		AddressSet set = cmd.getDisassembledAddressSet();
		AutoAnalysisManager.getAnalysisManager(currentProgram).codeDefined(set);

		return;
	}

	//------------------------------------------------------------------------
	// getScriptAnalysisMode
	//
	// Force auto-analysis to wait until script completes.
	//------------------------------------------------------------------------
	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.SUSPENDED;
	}

	//========================================================================
	// Main
	//========================================================================
	@Override
	public void run() throws Exception {

		// Find VxWorks symbol table
		Address symTbl = null;
		VxSymbol vxSymbol = getVxSymbolClass(0);
		for (int i = 0; ((vxSymbol != null) && !monitor.isCancelled()); i++, vxSymbol =
			getVxSymbolClass(i)) {

			println("Searching for symbol table variant " + i);
			if ((symTbl = findSymTbl(vxSymbol)) != null) {
				break;
			}
		}
		if (vxSymbol == null) {
			return;
		}
		int symTblLen = getSymTblLen(symTbl, vxSymbol);
		println("Symbol table at " + symTbl + " (" + symTblLen + " entries)");

		// Name the VxWorks symbol table
		removeConflictingSymbols("vxSymTbl", symTbl);
		createLabel(symTbl, "vxSymTbl", true);
		markSymbolTableLen(symTbl, vxSymbol, symTblLen);

		// Create symbol data type and symbol table structure
		println("Creating SYMBOL data type and symbol table structure...");
		vxSymbol.createGhidraType();
		clearListing(symTbl, symTbl.add(symTblLen * vxSymbol.length() - 1));
		createData(symTbl, new ArrayDataType(vxSymbol.dataType(), symTblLen, vxSymbol.length()));

		// Create a GNU demangler instance
		GnuDemangler demangler = new GnuDemangler();
		if (!demangler.canDemangle(currentProgram)) {
			println("Unable to create demangler.");
			return;
		}

		// Process VxWorks symbol table entries
		println("Processing symbol table entries.");
		Address symEntry = symTbl;
		for (int i = 0; (i < symTblLen) && !monitor.isCancelled(); i++, symEntry =
			symEntry.add(vxSymbol.length())) {

			// Extract symbol table entry values
			Address symNameAddr = toAddr(getInt(symEntry.add(vxSymbol.nameOffset())) & 0xffffffffL);
			Address symLoc = toAddr(getInt(symEntry.add(vxSymbol.locOffset())) & 0xffffffffL);
			byte symType = getByte(symEntry.add(vxSymbol.typeOffset()));

			// Remove any data or instructions that overlap string at *symNameAddr
			clearString(symNameAddr);

			// Turn *symNameAddr into a string and store it in symName
			String symName;
			try {
				symName = (String) createAsciiString(symNameAddr).getValue();
			}
			catch (Exception e) {
				println("createAsciiString: caught exception...");
				println(e.getMessage());
				println(e.toString());
				return;
			}
			if (symName.length() > 2000) {
				symName = symName.substring(0, 2000);
			}

			// Demangle symName
			String symDemangledName = null;
			try {
				symDemangledName = demangler.demangle(symName).getSignature(false);
			}
			catch (DemangledException e) {		// report demangling error
				if (!e.isInvalidMangledName()) {
					println("demangle: Demangling error");
				}
			}
			catch (RuntimeException e) {		// ignore unmangled symNames
			}

			// Status update
			if (symDemangledName != null) {
				println("i=" + i + ", nameAddr: " + symNameAddr + ", loc: " + symLoc + ", type: " +
					symType + ", name: " + symName + ", demangled: " + symDemangledName);
			}
			else {
				println("i=" + i + ", nameAddr: " + symNameAddr + ", loc: " + symLoc + ", type: " +
					symType + ", name: " + symName);
			}

			// Clear any conflicting symbols from the Ghidra symbol table
			removeConflictingSymbols(symName, symLoc);

			// If entry type is data, simply create a Ghidra symbol for it.
			// If entry type is code, disassemble it and create function.
			switch (symType) {

				case 0: // Undefined Symbol
					println("NULL symType!");
					break;

				case 2: // Local Absolute 
				case 3: // Global Absolute
				case 6: // Local Data
				case 7: // Global Data
				case 8: // Local BSS
				case 9: // Global BSS
					createLabel(symLoc, symName, true);
					applyDemangled(symLoc, symName, symDemangledName);
					break;

				case 4: // Local .text
				case 5: // Global .text  
					doLocalDisassemble(symLoc);
					createFunction(symLoc, symName);
					if (getFunctionAt(symLoc) != null) {
						getFunctionAt(symLoc).setName(symName, SourceType.USER_DEFINED);
						applyDemangled(symLoc, symName, symDemangledName);
					}
					else {
						println("createFunction: Failed to create function");
						createLabel(symLoc, symName, true);
						applyDemangled(symLoc, symName, symDemangledName);
					}
					break;

				case 0x11: // External ref -- ignore
					break;

				default:
					println("Invalid symType!");
					break;
			}
		}
	}
}
