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
//  
// Calculates the percentage of instructions which are not in functions.
//
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

public class MakeFuncsAtLabelsScript extends GhidraScript {

	int totalNumOfFunctions = 0;

	@Override
	public void run() throws Exception {

		// find all the sections of memory marked as executable
		Program prog = currentProgram;
		AddressSetView execMemSet = prog.getMemory().getExecuteSet();
		SymbolTable sm = currentProgram.getSymbolTable();
		SymbolIterator textLabels = sm.getPrimarySymbolIterator(execMemSet, true);
		Listing listing = prog.getListing();
		for (Symbol symbol : textLabels) {
			if (symbol.getSource() == SourceType.IMPORTED &&
				(symbol.getSymbolType() == SymbolType.LABEL)) {
				if (!this.isRunningHeadless()) {
					printf("%s %s", symbol.getAddress().toString(), symbol.toString());
				}
				Address labelAddress = symbol.getAddress();
				//don't declare to be functions if the symbol starts with .L or LAB
				if (symbol.toString().startsWith(".L") || symbol.toString().startsWith("LAB")) {
					continue;
				}
				if (listing.isUndefined(labelAddress, labelAddress)) {
					if (!this.isRunningHeadless()) {
						printf("Undefined: %s", labelAddress.toString());
					}
					boolean result = disassemble(labelAddress);
					if (result == false) {
						printf("Disassembly failure at %s", labelAddress.toString());
						continue; //must be data
					}
				}
				createFunction(labelAddress, symbol.toString());
			}
		}
	}

}
