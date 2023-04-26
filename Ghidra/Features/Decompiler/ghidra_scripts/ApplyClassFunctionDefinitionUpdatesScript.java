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
// Script to apply any changes the user has made to recovered class virtual function definitions 
// edited in the data type manager. To run the script, put the cursor on any member of the 
// desired class in the listing then run the script. For each function definition in the given class 
// that differs from the associated function signature in the listing, the script will update the 
// listing function signatures of any related virtual functions belonging to parent and children 
// classes. 
// Note: The script will not work if the vftable structures were not originally applied to 
// the vftables using the RecoverClassesFromRTTIScript. 
// At some point, the Ghidra API will be updated to do this automatically instead of needing the 
// script to do so. For now, to make it a bit easier, you can use the below listed key binding
// or menupath if you have the "In Tool" checkbox checked for this script in the script manager.
//@category C++
//@menupath Scripts.ApplyClassFunctionDefinitions
//@keybinding shift D

import java.util.ArrayList;
import java.util.List;

import classrecovery.RecoveredClassHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;

public class ApplyClassFunctionDefinitionUpdatesScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		RecoveredClassHelper classHelper = new RecoveredClassHelper(currentProgram, currentLocation,
			state.getTool(), this, false, false, false, monitor);

		DataTypeManagerService dtms = state.getTool().getService(DataTypeManagerService.class);
		List<DataType> selectedDatatypes = dtms.getSelectedDatatypes();
		if (selectedDatatypes.size() == 0) {
			println("Please select the class function definition(s) you wish to apply.");
			return;
		}

		List<FunctionDefinition> classFunctionDefinitions = new ArrayList<FunctionDefinition>();
		for (DataType selectedDataType : selectedDatatypes) {
			monitor.checkCancelled();

			if (!(selectedDataType instanceof FunctionDefinition)) {
				continue;
			}

			FunctionDefinition functionDefinition = (FunctionDefinition) selectedDataType;
			String pathName = functionDefinition.getPathName();
			if (!pathName.contains("ClassDataTypes")) {
				continue;
			}
			classFunctionDefinitions.add(functionDefinition);
		}

		if (classFunctionDefinitions.isEmpty()) {
			println(
				"Selected function definition(s) must be in a subfolder of the ClassDataTypes folder in the DataTypeManager.");
			return;
		}

		List<Object> changedItems = new ArrayList<Object>();

		for (FunctionDefinition functionDef : classFunctionDefinitions) {
			monitor.checkCancelled();

			List<Object> newChangedItems = classHelper.applyNewFunctionDefinition(functionDef);

			changedItems = classHelper.updateList(changedItems, newChangedItems);

		}

		if (changedItems == null || changedItems.isEmpty()) {
			println(
				"There were no differences between the selected function definitions and the items that could be updated.");
			return;
		}

		List<Structure> structuresOnList = classHelper.getStructuresOnList(changedItems);
		List<Function> functionsOnList = classHelper.getFunctionsOnList(changedItems);

		if (!structuresOnList.isEmpty()) {
			println();
			println("Updated structures:");
			for (Structure structure : structuresOnList) {
				monitor.checkCancelled();
				println(structure.getPathName());
			}
		}

		if (!functionsOnList.isEmpty()) {
			println();
			println("Updated functions:");
			for (Function function : functionsOnList) {
				monitor.checkCancelled();
				println(function.getEntryPoint().toString());
			}
		}
	}

}
