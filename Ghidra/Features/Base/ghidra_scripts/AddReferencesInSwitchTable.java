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
//With cursor on switch's "add pc, .." command, this script will add references on the switch offset table to corresponding code.  
//Make sure your table consists of defined data (db,dw,etc).
//@category ARM

/*
 * This script has 2 preconditions:
 *  1.  Your switch table should already be defined data
 *  2.  Make sure your cursor is on the "add pc, .." command.    	
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

import ghidra.program.model.symbol.*;
import ghidra.util.NumericUtilities;


public class AddReferencesInSwitchTable extends GhidraScript {

    @Override
    public void run() throws Exception {
      	println("This script attempts to add references to a switch table to corresponding code.\n"
    			+ "BEFORE running this script, \n"
    			+ "     1.  Your switch table should already be defined data.\n"
    			+ "     2.  Make sure your cursor is on the \"add pc, ..\" command.\n"    			
    			+ "Note: Adding the same reference twice does not have any impact.\n");
    	
    	Program program = currentProgram;
    	Listing listing = program.getListing(); 
    	
    	Address startAddr = currentAddress;
    	Address pc = startAddr.add(4);
    	
    	Address prevAddr = null;
    	int diff = 0;
  	    	
    	// Get data iterator
    	DataIterator dataIter = listing.getDefinedData(startAddr, true);
    	
    	// Find and add reference to first table entry
    	Data data = dataIter.next();
    	CalcAndAddReference( data, pc );
		prevAddr = data.getMinAddress();
		
		// Determine address difference between each switch table entry
		DataType type = data.getDataType();
		String typeName = type.getName();
		//println( "type: " + typeName );			
		if ( typeName.equalsIgnoreCase("byte") )
			diff = 1;
		else if ( type.getName().equalsIgnoreCase("word") )
			diff = 2;
		else if ( type.getName().equalsIgnoreCase("dword") )
			diff = 4;
		else {
			popup( "Sorry, type " + typeName + " is not supported yet.  (Try adding it yourself.)");
			return;
		}		

		// Iterate through rest of table
		while (dataIter.hasNext() && !monitor.isCancelled()) {
			data = dataIter.next();
			Address currAddr = data.getMinAddress();
			monitor.setMessage(currAddr.toString());
			
			// Check if consecutive next entry in switch table
			if ( currAddr.subtract(prevAddr) == diff ) {
				// Save currAddr as prevAddr
				prevAddr = currAddr;

				// Add reference
				CalcAndAddReference( data, pc );						
			}
			else {
				// Passed end of switch table...Exit script
				break;			
			}
		}
  
	}   // end run()

	private void CalcAndAddReference(Data data, Address pc) {
		
		// Get current data value in switch table
		//println("value: " + data.getValue().toString().substring(2));
		long currVal = NumericUtilities.parseHexLong(data.getValue().toString().substring(2));
		
		// Calculate referenced addr
		// (using addWrap so that an exception is not thrown when past the switch table)
		Address refAddr = pc.addWrap(2 * currVal);
		
		// Add reference
		println("Adding ref " + refAddr.toString() + " to address " + data.getAddressString(false, true));
		data.addValueReference(refAddr, RefType.COMPUTED_JUMP);	
		
	}
    
}
