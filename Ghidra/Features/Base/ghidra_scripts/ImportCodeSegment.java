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
//Imports the code segment of a set of binaries

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;

import java.io.File;

public class ImportCodeSegment extends GhidraScript implements Ingredient {

	/**
	 * @see ghidra.app.script.GhidraScript#run()
	 */
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
		File file = (File) state.getEnvironmentVar("CodeSegmentBinary");
		LanguageID languageID = (LanguageID) state.getEnvironmentVar("LanguageID");
		CompilerSpecID compilerSpecID = (CompilerSpecID) state.getEnvironmentVar("CompilerSpecID");

		Program prog = null;
		Language lang = getLanguage(languageID);
		if (lang == null) {
			println("Unable to locate default language for " + languageID);
			throw new Exception("Unable to locate default language for " + languageID);
		}
		CompilerSpec compilerSpec = lang.getCompilerSpecByID(compilerSpecID);
		if (compilerSpec == null) {
			compilerSpec = lang.getDefaultCompilerSpec();
		}
		prog = importFileAsBinary(file, lang, compilerSpec);
		if (prog == null) {
			println("Unable to import program from file " + file.getName());
			throw new Exception("Unable to import program from file " + file.getName());
		}
		state.setCurrentProgram(prog);
		openProgram(prog);
	}

	@Override
	public IngredientDescription[] getIngredientDescriptions() {
		IngredientDescription[] retVal =
			new IngredientDescription[] {
				new IngredientDescription("CodeSegmentBinary",
					"File containing blk 0 code segment:", GatherParamPanel.FILE, ""),
				new IngredientDescription("LanguageID", "Language:", GatherParamPanel.LANGUAGE, "") };
		return retVal;
	}
}
