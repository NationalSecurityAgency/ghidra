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
//Test script to lay down known RTTI structures in a file with applied pdb symbols to test the 32 and 64 bit RTTI structures
//@author
//@category Test
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.datatype.microsoft.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

public class ApplyRTTITestScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		
		//Find RTTI0 using symbol names pdb put on - symbol contains text: Type_Descriptor
		SymbolIterator symbolIterator = symbolTable.getSymbolIterator("*Type_Descriptor*", true);
		RTTI0DataType dt0 = new RTTI0DataType();
		createRTTIDataType(symbolIterator, dt0);

		//Next find RTTI1 using symbol names pdb put on - symbol contains text: Base_Class_Descriptor
		symbolIterator = symbolTable.getSymbolIterator("*Base_Class_Descriptor*", true);
		RTTI1DataType dt1 = new RTTI1DataType();
		createRTTIDataType(symbolIterator, dt1);
		
		//Next find RTTI2 using symbol names pdb put on - symbol contains text: Base_Class_Array
		symbolIterator = symbolTable.getSymbolIterator("*Base_Class_Array*", true);
		RTTI2DataType dt2 = new RTTI2DataType();
		createRTTIDataType(symbolIterator, dt2);
		
		
		//Next find RTTI3 using symbol names pdb put on - symbol contains text: Class_Hierarchy_Descriptor
		symbolIterator = symbolTable.getSymbolIterator("*Class_Hierarchy_Descriptor*", true);
		RTTI3DataType dt3 = new RTTI3DataType();
		createRTTIDataType(symbolIterator, dt3);
		
		
		//Next find RTTI4 using symbol names pdb put on - symbol contains text: Complete_Object_Locator
		symbolIterator = symbolTable.getSymbolIterator("*Complete_Object_Locator*", true);
		RTTI4DataType dt4 = new RTTI4DataType();
		createRTTIDataType(symbolIterator, dt4);
		
		
		 return;
	}

	private void createRTTIDataType(SymbolIterator symbolIterator, DataType dt)
			throws CancelledException, Exception {

		while (symbolIterator.hasNext()) {
			monitor.checkCanceled();
			Symbol sym = symbolIterator.next();
			DataUtilities.createData(currentProgram, sym.getAddress(), dt, -1, false,
					ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			println("Created " + dt.getName() + " at " + sym.getAddress().toString());
		}
	}

}
