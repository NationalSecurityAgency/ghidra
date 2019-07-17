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
//With a user-inputed base address, this script will add a reference on the current switch table entry to corresponding code
//Make sure your table entry is defined data (db,dw,etc).
//@category ARM

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.util.NumericUtilities;

public class AddSingleReferenceInSwitchTable extends GhidraScript {

    @Override
    public void run() throws Exception {
    	
    	Program program = currentProgram;
    	Listing listing = program.getListing(); 
    	
    	// Ask for base address 
    	//  (equals the pc when program hits the switch table, 
    	//   which equals the address of the "add pc, .." instruction + 4)
    	Address pc = askAddress("Address", "Enter switch base address (hex, don't use 0x)");

    	// Get current data value
    	Data data = listing.getDefinedDataAt(currentAddress);
    	long currVal = NumericUtilities.parseHexLong(data.getValue().toString().substring(2));
    	
		// Calculate referenced addr
		Address refAddr = pc.add(2 * currVal);
			
		// Add reference
		println("Adding ref " + refAddr.toString() + " to address " + data.getAddressString(false, true));
		data.addValueReference(refAddr, RefType.DATA);

    }

}
