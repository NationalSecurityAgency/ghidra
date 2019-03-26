/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//This script creates references on all scalars contained in operands in the
// current selection. There must be a selection for this script to run.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

public class CreateOperandReferencesInSelectionScript extends GhidraScript {

	Listing listing;
	Memory memory;
	SymbolTable symbolTable;
	
    @Override
    public void run() throws Exception {
 		listing = currentProgram.getListing();
 		memory = currentProgram.getMemory();
 		symbolTable = currentProgram.getSymbolTable();
 		if(currentSelection == null) {
 			monitor.setMessage("You must have a selection for this script to run.");
 			return;
 		}
 		monitor.setMessage("Creating operand references...");
 		AddressIterator addrIt = currentSelection.getAddresses(true);
 		while(addrIt.hasNext()){
 			Address addr = addrIt.next();
 			CodeUnit cu = listing.getCodeUnitContaining(addr);
 			int numOps = cu.getNumOperands();
 			for(int i=0;i<numOps;i++){
 				Scalar scalar = cu.getScalar(i);
 				if(scalar != null){
 					//check to see if scalar value is a valid address in program memory
 					long scalarValue = scalar.getUnsignedValue();
 					Address testAddr = addr.getNewAddress(scalarValue);
 					if(memory.contains(testAddr)){
 					//if so, create the memory reference on the scalar operand
 				  //TODO: not sure if the DATA type for the ref is correct
 				// RefTypeFactory.getDefaultMemoryRefType(instr, opIndex)
 					cu.addOperandReference(i, testAddr, RefType.DATA, SourceType.ANALYSIS);
 					}
 				}
 				
 			}
 		}
 		
 		
    }// end of run method
}
