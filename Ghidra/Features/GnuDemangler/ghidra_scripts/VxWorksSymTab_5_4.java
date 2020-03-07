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
// VxWorksSymTab_5_4 is a copy of VxWorksSymTab_6_1 with a different value for SYM_ENTRY_SIZE
// It was replaced at the request of a customer who tested that it worked with the slight modification
// VxWorksSymTab_6_1 is an adaptation of the vxWorksSymTab script.  It was modified by a customer 
// to use a single loop, instead of two.  It also added demangling of C++ symbol names - at least
// those that Ghidra knows how to demangle.
//
// Extracts all symbols in a VxWorks symbol table and disassembles
// the global functions.  Any existing symbols in the Ghidra symbol table
// that collide with symbols defined in the VxWorks symbol table are deleted.
// 
// The VxWorks symbol table is an array of symbol table entries [0..n-1]
// followed by a 32-bit value that is equal to n (number of sym tbl entries).
//  Each entry in the array has the following structure:
//
//    // Total size: 0x18 (24) bytes
//    0x00    int NULL
//    0x04    char *symNameAddr    // symbol name
//    0x08    void *symLocAddr     // location of object named by symbol
//    0x0c    int NULL
//    0x10    int NULL
//    0x14    uchar symType        // see switch statement below
//    0x15    uchar fill[3]
//
// The script requests:
//    -  Output file name:  Each symbol name and address is recorded here.
//                          (Errors are also logged to this file.)
//    -  Address of "number of symbols" value:  At the end of the symbol table,
//                          its length is recorded as a 32-bit integer.  The
//                          script needs the address of that value to calculate
//                          the symbol table's start address.
//
// @category CustomerSubmission.vxWorks

import java.io.FileOutputStream;
import java.io.PrintWriter;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class VxWorksSymTab_5_4 extends GhidraScript {

	static final int SYM_ENTRY_SIZE = 16;
	static final int SYM_NAME_OFF = 4;
	static final int SYM_LOC_OFF = 8;
	static final int SYM_TYPE_OFF = 0x14;

	@Override
	public void run() throws Exception {

		// Get Memory and SymbolTable objects (used later)
		Memory mem = currentProgram.getMemory();
		SymbolTable ghidraSymTbl = currentProgram.getSymbolTable();

		// Open output file
		// All symbols found (address and name) will be logged to this file
		try (PrintWriter output =
			new PrintWriter(new FileOutputStream(askFile("vxWorks Symbol Table Parser",
				"Output file name?")))) {

			// Get address of "total number of sym tbl entries" value
			Address vxNumSymEntriesAddr =
				askAddress("vxWorks Symbol Table Parser",
					"Address of \"total number of symbol table entries\" value?");
			int vxNumSymEntries = mem.getInt(vxNumSymEntriesAddr);
			println("VxWorks symbol table has " + vxNumSymEntries + " entries");

			// Create a GNU demangler instance
			GnuDemangler demangler = new GnuDemangler();
			if (!demangler.canDemangle(currentProgram)) {
				println("Unable to create demangler.");
				return;
			}

			// Process entries in VxWorks symbol table
			Address vxSymTbl = vxNumSymEntriesAddr.subtract(vxNumSymEntries * SYM_ENTRY_SIZE);
			for (int i = 0; i < vxNumSymEntries; i++) {

				if (monitor.isCancelled()) {
					return; // check for cancel button
				}
				println("i=" + i); // visual counter

				// Extract symbol table entry values
				Address symEntry = vxSymTbl.add(i * SYM_ENTRY_SIZE);
				Address symNameAddr = toAddr(mem.getInt(symEntry.add(SYM_NAME_OFF)));
				Address symLocAddr = toAddr(mem.getInt(symEntry.add(SYM_LOC_OFF)));
				byte symType = mem.getByte(symEntry.add(SYM_TYPE_OFF));
				println("symNameAddr: 0x" + symNameAddr.toString() + ", symLocAddr: 0x" +
					symLocAddr.toString() + ", symType: " + symType);

				// Remove any data or instructions that overlap this symName
				// (May happen if disassembly creates invalid references)
				Address a;
				String symName;
				for (a = symNameAddr; mem.getByte(a) != 0; a = a.add(1)) {
					if (getDataAt(a) != null) {
						removeDataAt(a);
					}
					if (getInstructionAt(a) != null) {
						removeInstructionAt(a);
					}
				}
				if (getDataAt(a) != null) {
					removeDataAt(a);
				}
				if (getInstructionAt(a) != null) {
					removeInstructionAt(a);
				}

				// Turn *symNameAddr into a string and store it in symName
				try {
					symName = (String) createAsciiString(symNameAddr).getValue();
				}
				catch (Exception e) {
					println("createAsciiString: caught exception...");
					println(e.getMessage());
					return;
				}
				println("symName: " + symName);

				// Demangle symName
				String symDemangledName = null;
				try {
					// if successful, symDemangledName will be non-NULL
					symDemangledName = demangler.demangle(symName).getSignature(false);
				}
				catch (DemangledException e) {
					// if symName wasn't a mangled name, silently continue
					if (!e.isInvalidMangledName()) {
						println("demangle: Demangling error");
						output.println("demangle: Demangling error");
					}
				}
				catch (RuntimeException e) {
					println("demangle: Caught runtime exception");
					output.println("demangle: Caught runtime exception");
				}
				if (symDemangledName != null) {
					println("symDemangledName: " + symDemangledName);
				}

				// Delete any symbol in the Ghidra symbol table with the same name
				SymbolIterator syms = ghidraSymTbl.getSymbols(symName);
				Symbol sym;
				while (syms.hasNext()) {
					sym = syms.next();
					println("Deleting matching Ghidra symbol: " + sym.getName());
					ghidraSymTbl.removeSymbolSpecial(sym);
				}

				// Delete any symbol in the Ghidra symbol table at the same address
				if ((sym = getSymbolAt(symLocAddr)) != null) {
					println("Deleting symbol at target address: " + sym.getName());
					ghidraSymTbl.removeSymbolSpecial(sym);
				}

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
						// Data: log the symbol & create a Ghidra symbol at symLocAddr
						output.println(symLocAddr.toString() + "\t" + symName);
						createLabel(symLocAddr, symName, true);
						if (symDemangledName != null) {
							new DemanglerCmd(symLocAddr, symName).applyTo(currentProgram, monitor);
							ghidraSymTbl.removeSymbolSpecial(getSymbol(symName,
								currentProgram.getGlobalNamespace()));
						}
						break;
					case 4: // Local .text
					case 5: // Global .text  
						// Code: log the symbol, disassemble, & create/name function
						output.println(symLocAddr.toString() + "\t" + symName);
						goTo(symLocAddr);
						disassemble(symLocAddr);
						createFunction(symLocAddr, symName);
						if (getFunctionAt(symLocAddr) != null) {
							getFunctionAt(symLocAddr).setName(symName, SourceType.USER_DEFINED);
							if (symDemangledName != null) {
								new DemanglerCmd(symLocAddr, symName).applyTo(currentProgram,
									monitor);
								ghidraSymTbl.removeSymbolSpecial(getSymbol(symName,
									currentProgram.getGlobalNamespace()));
							}
						}
						else {
							println("createFunction: Failed  to create function");
							output.println("createFunction: Failed to create function");
							createLabel(symLocAddr, symName, true);
							if (symDemangledName != null) {
								new DemanglerCmd(symLocAddr, symName).applyTo(currentProgram,
									monitor);
								ghidraSymTbl.removeSymbolSpecial(getSymbol(symName,
									currentProgram.getGlobalNamespace()));
							}
						}
						break;
					default:
						println("Invalid symType!");
						break;
				}

				symEntry = symEntry.add(SYM_ENTRY_SIZE); // goto next entry
			}
		}
	}
}
