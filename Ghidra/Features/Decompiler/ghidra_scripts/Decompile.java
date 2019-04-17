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
//Decompile an entire program

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;

public class Decompile extends GhidraScript implements Ingredient {

	@Override
	public void run() throws Exception {
		IngredientDescription[] ingredients = getIngredientDescriptions();
		for (IngredientDescription ingredient : ingredients) {
			state.addParameter(ingredient.getID(), ingredient.getLabel(), ingredient.getType(),
				ingredient.getDefaultValue());
		}
		if (!state.displayParameterGatherer("Script Options")) {
			return;
		}
		File outputFile = (File) state.getEnvironmentVar("COutputFile");
		CppExporter cppExporter = new CppExporter();
		List<Option> options = new ArrayList<Option>();
		options.add(new Option(CppExporter.CREATE_HEADER_FILE, new Boolean(false)));
		cppExporter.setOptions(options);
		cppExporter.setExporterServiceProvider(state.getTool());
		cppExporter.export(outputFile, currentProgram, null, monitor);
	}

	@Override
	public IngredientDescription[] getIngredientDescriptions() {
		IngredientDescription[] retVal = new IngredientDescription[] {
			new IngredientDescription("COutputFile", "Output C File", GatherParamPanel.FILE, "") };
		return retVal;
	}

}
