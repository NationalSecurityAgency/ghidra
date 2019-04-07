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
// List function names and entry point addresses to a file
//@category Functions

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

import java.io.*;

public class ExportFunctionInfoScript extends GhidraScript implements Ingredient {

	@Override
	public void run() throws Exception {
		IngredientDescription[] ingredients = getIngredientDescriptions();
		for (int i = 0; i < ingredients.length; i++) {
			state.addParameter(ingredients[i].getID(), ingredients[i].getLabel(),
				ingredients[i].getType(), ingredients[i].getDefaultValue());
		}
		if (!state.displayParameterGatherer("Script Options")) {
			return;
		}
		File outputNameFile = (File) state.getEnvironmentVar("FunctionNameOutputFile");
		PrintWriter pWriter = new PrintWriter(new FileOutputStream(outputNameFile));
		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			String fName = f.getName();
			Address entry = f.getEntryPoint();
			if (entry == null) {
				pWriter.println("/* FUNCTION_NAME_ " + fName + " FUNCTION_ADDR_ " +
					"NO_ENTRY_POINT" + " */");
				println("WARNING: no entry point for " + fName);
			}
			else {
				pWriter.println("/* FUNCTION_NAME_ " + fName + " FUNCTION_ADDR_ " + entry + " */");
			}
		}
		pWriter.close();
	}

	@Override
	public IngredientDescription[] getIngredientDescriptions() {
		IngredientDescription[] retVal =
			new IngredientDescription[] { new IngredientDescription("FunctionNameOutputFile",
				"Output Function Name File", GatherParamPanel.FILE, "") };
		return retVal;
	}

}
