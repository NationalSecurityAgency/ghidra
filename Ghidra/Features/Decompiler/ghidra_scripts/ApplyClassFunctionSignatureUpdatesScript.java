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
// Script to apply any changes the user has made to recovered class virtual function signatures 
// edited in the listing. To run the script, put the cursor on a changed virtual function in 
// the listing then run the script. If the function signature in the given class differs from
// the associated function definition in the data type manager, the script will update the associated 
// function definition and any other related function signatures in the listing.
// Note: The script will not work if the vftable structures were not originally applied to 
// the vftables using the RecoverClassesFromRTTIScript.
// At some point, the Ghidra API will be updated to do this automatically instead of needing the 
// script to do so. For now, to make it a bit easier, you can use the below listed key binding
// or menupath if you have the "In Tool" checkbox checked for this script in the script manager.
//@category C++
//@menupath Scripts.ApplyClassFunctionSignatures
//@keybinding shift S

import java.util.List;

import classrecovery.RecoveredClassHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

public class ApplyClassFunctionSignatureUpdatesScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		RecoveredClassHelper classHelper = new RecoveredClassHelper(currentProgram, currentLocation,
			state.getTool(), this, false, false, false, monitor);
		
		if(currentAddress == null) {
			println("Cursor must be in a class function.");
			return;
		}
		Function function = getFunctionContaining(currentAddress);
		if(function == null) {
			println("Cursor must be in a class function.");
			return;
		}
		
		if(function.isThunk()) {
			println("User should not edit thunks as they are auto-updated from thunked function. " +
				"Please undo changes to thunk then edit thunked function and rerun script");
			return;
		}

		if (function.getName().contains("purecall")) {
			println("Function definitions are not affected by purecall changes.");
			return;
		}
	

		Namespace classNamespace = classHelper.getClassNamespace(currentAddress);
		if (classNamespace == null) {
			println("Cursor must be in a class function.");
			return;
		}
		
		// get a vftable that points to this function - doesn't matter which since it will
		// be used to get the underlying function definition which will then be used to update
		// all related function signatures
		List<Address> vftablesContainingFunction = classHelper.getVftablesContaining(function);

		// get all vftables that point to given function
		if (vftablesContainingFunction.isEmpty()) {
			println(
				"Function is not a virtual function so has no function definition or related " +
					"function signatures to update");
			return;
		}

		// get one that has a class vftableStructure applied there
		Address vftableWithAppliedStructure = null;
		for (Address vftableAddress : vftablesContainingFunction) {
			monitor.checkCancelled();

			Data dataAt = getDataAt(vftableAddress);
			if (dataAt == null) {
				continue;
			}

			DataType baseDataType = dataAt.getBaseDataType();

			if (baseDataType.getCategoryPath().getPath().contains("ClassDataTypes")) {
				vftableWithAppliedStructure = vftableAddress;
				break;
			}
		}
	
		if (vftableWithAppliedStructure == null) {
			println(
				"The vftable(s) containing this function do not have a valid vftable structure " +
					"applied. Please run the RecoverClassesFromRTTIScript.java on this program before " +
					"using this script to update virtual functions.");
			return;
		}
		List<Object> changedItems =
			classHelper.applyNewFunctionSignature(function, vftableWithAppliedStructure);

		if (changedItems.isEmpty()) {
			println("No differences found between function signature at " +
				function.getEntryPoint().toString() +
				" and its associated function definition in the data type manager.");
			return;
		}

		List<Structure> structuresOnList = classHelper.getStructuresOnList(changedItems);
		List<FunctionDefinition> functionDefinitionsOnList =
			classHelper.getFunctionDefinitionsOnList(changedItems);
		List<Function> functionsOnList = classHelper.getFunctionsOnList(changedItems);

		if (!structuresOnList.isEmpty()) {
			println();
			println("Updated structures:");
			for (Structure structure : structuresOnList) {
				monitor.checkCancelled();
				println(structure.getPathName());
			}
		}

		if (!functionDefinitionsOnList.isEmpty()) {
			println();
			println("Updated function definition:");
			for (FunctionDefinition functionDef : functionDefinitionsOnList) {
				monitor.checkCancelled();
				println(functionDef.getPathName());
			}
		}

		if (!functionsOnList.isEmpty()) {
			println();
			println("Updated functions:");
			for (Function functionOnList : functionsOnList) {
				monitor.checkCancelled();
				println(functionOnList.getEntryPoint().toString());
			}
		}

	}


}
