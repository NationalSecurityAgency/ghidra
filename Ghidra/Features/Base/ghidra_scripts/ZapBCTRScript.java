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
// The script assumes that the cursor is on a 'bctrl' instruction.
//
// First, a vtbl location is requested. Either the vtbl address or
// the name of the owning class can be specified as the vtbl location.
// If the owning class name is given, the script searches for a symbol
// named "<class>::__vtbl" and uses its address as the vtbl address.
//
// Second, the offset of the target function within the vtbl is
// requested.  That offset is used to extract the target function
// pointer from the vtbl.
//
// Given the target function pointer, the script finds the associated
// function name, inserts that function name as an EOL_COMMENT at the
// current address, and creates a mnemonic reference from the current
// instruction to the function.
//
// NOTE:  Adresses must be hex values -- without "0x" prefixes.
//
//@category CustomerSubmission.Analysis
//@keybinding alt Z

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class ZapBCTRScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		Address vtblAddr;

		// get listing and mem -- used later
		Listing listing = currentProgram.getListing();
		Memory mem = currentProgram.getMemory();

		// get vtbl location (can be class name or address)
		String classNameOrAddr = askString("Vtbl location", "Class name or address");
		if (classNameOrAddr == null) { // exit, if null input
			return;
		}

		// first try input as class and search for symbol "<class>::__vtbl"
		List<Symbol> symbols = currentProgram.getSymbolTable().getSymbols("__vtbl",
			getNamespace(null, classNameOrAddr));
		// if symbol found, then vtblAddr is the symbol's address
		if (symbols.size() == 1) {
			vtblAddr = symbols.get(0).getAddress();
			// else see if input was address
		}
		else {
			vtblAddr = toAddr(0);
			try {
				vtblAddr = toAddr(Integer.parseInt(classNameOrAddr, 16));
			}
			catch (Exception e) {
			}
			if (vtblAddr.getOffset() == 0) {
				println("Invalid class name or address");
				println("Note:  addresses must be hex -- with no '0x' prefix");
				return;
			}
		}

		// get vtbl offset of tgt function & compute tgt function address
		// function address = integer value stored at (vtblAddr +  vtblOffset)
		Address funcAddr = toAddr(mem.getInt(
			vtblAddr.add(Integer.parseInt(askString("Vtbl Offset", "Hex vtbl offset"), 16))));

		// get tgt function name
		String funcName = getSymbolAt(funcAddr).getName(true);

		// Provide feedback
		println("vtblAddr: 0x" + Long.toHexString(vtblAddr.getOffset()));
		println("function: " + funcName + " (0x" + Long.toHexString(funcAddr.getOffset()) + ")");

		// calculate displacement between instAddr and funcAddr
		Address instAddr = currentAddress;
		//long displacement = funcAddr.subtract(instAddr);

		// insert funcName as EOL comment and
		// add a mnemonic ref from instAddr to funcAddr
		listing.setComment(instAddr, CodeUnit.EOL_COMMENT, funcName);
		listing.getInstructionAt(instAddr).addMnemonicReference(funcAddr, RefType.COMPUTED_CALL,
			SourceType.USER_DEFINED);

		/*  old code that replaces the 'bctr' with a 'bl'
		int code = 0x48000001 | ((int)displacement & 0x3ffffff);
		mem.setInt(instAddr, code);
		clearListing(instAddr);    // clear/disassemble updates listing
		disassemble(instAddr);     // to display bl vice bctr
		println("New code word: 0x" + Long.toHexString(code) +
		        " -- displacement: 0x" + Long.toHexString(displacement));
		*/
	}
}
