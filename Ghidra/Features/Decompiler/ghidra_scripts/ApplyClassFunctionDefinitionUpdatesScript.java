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
// classes. It will also update related data types including function definitions and vftable structures.
// Note: The script will not work if the vftable structures were not originally applied to 
// the vftables using the RecoverClassesFromRTTIScript. 
// At some point, the Ghidra API will be updated to do this automatically instead of needing the 
// script to do so. 
//@category C++

import java.util.List;

import classrecovery.RecoveredClassUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

public class ApplyClassFunctionDefinitionUpdatesScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		RecoveredClassUtils classUtils = new RecoveredClassUtils(currentProgram, currentLocation,
			state.getTool(), this, false, false, false, monitor);

		Namespace classNamespace = classUtils.getClassNamespace(currentAddress);
		if (classNamespace == null) {
			println(
				"Either cannot retrieve class namespace or cursor is not in a member of a class namepace");
			return;
		}

		List<Symbol> classVftableSymbols = classUtils.getClassVftableSymbols(classNamespace);
		if (classVftableSymbols.isEmpty()) {
			println("There are no vftables in this class");
			return;
		}

		println(
			"Applying differing function definitions for class " + classNamespace.getName(true));

		List<Object> changedItems =
			classUtils.applyNewFunctionDefinitions(classNamespace, classVftableSymbols);

		if (changedItems.isEmpty()) {
			println("No differences found for class " + classNamespace.getName(true) +
				" between the vftable listing function signatures and their associated data type manager function definition data types");
			return;
		}

		List<Structure> structuresOnList = classUtils.getStructuresOnList(changedItems);
		List<FunctionDefinition> functionDefinitionsOnList =
			classUtils.getFunctionDefinitionsOnList(changedItems);
		List<Function> functionsOnList = classUtils.getFunctionsOnList(changedItems);

		println();
		println("Updated structures:");
		for (Structure structure : structuresOnList) {
			monitor.checkCanceled();
			println(structure.getPathName());
		}

		println();
		println("Updated function definitions:");
		for (FunctionDefinition functionDef : functionDefinitionsOnList) {
			monitor.checkCanceled();
			println(functionDef.getPathName());
		}

		println();
		println("Updated functions:");
		for (Function function : functionsOnList) {
			monitor.checkCanceled();
			println(function.getEntryPoint().toString());
		}

	}

}
