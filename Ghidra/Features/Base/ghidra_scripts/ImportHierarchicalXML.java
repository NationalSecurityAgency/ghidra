/* ###
 * IP: GHIDRA
 * NOTE: again, VERSIONTRACKING?
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
//Import XML Directory Hierarchy

import java.io.File;
import java.io.FilenameFilter;

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.*;
import ghidra.app.util.opinion.XmlLoader;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;

public class ImportHierarchicalXML extends GhidraScript implements Ingredient {

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
		File topLevel = (File) state.getEnvironmentVar("XMLTopLevelDir");
		if (!topLevel.exists()) {
			throw new Exception("Directory " + topLevel.toString() + " does not exist!");
		}
		if (!topLevel.isDirectory()) {
			throw new Exception(topLevel.toString() + " is not a directory!");
		}

		Project project = state.getProject();
		addObject(project.getProjectData().getRootFolder(), topLevel);
		project.releaseFiles(this);
	}

	@Override
	public IngredientDescription[] getIngredientDescriptions() {
		IngredientDescription[] retVal = new IngredientDescription[] {
			new IngredientDescription("XMLTopLevelDir", "Top Level Directory Containing XML Files:",
				GatherParamPanel.DIRECTORY, ""),
			new IngredientDescription("XMLImportLanguageID", "Language ID (you don't know this):",
				GatherParamPanel.STRING, ""),
			new IngredientDescription("XMLImportCompilerSpecID",
				"Compiler Spec ID (again, you don't know this):", GatherParamPanel.STRING, "") };
		return retVal;
	}

	private void addObject(DomainFolder parentFolder, File obj) throws Exception {
		if (monitor.isCancelled()) {
			return;
		}
		if (obj.isDirectory()) {
			DomainFolder df = parentFolder.createFolder(obj.getName());
			File[] files = obj.listFiles(new XMLFileFilter());
			for (File file : files) {
				if (monitor.isCancelled()) {
					return;
				}
				addObject(df, file);
			}
		}
		else {
			LanguageID languageID =
				new LanguageID((String) state.getEnvironmentVar("XMLImportLanguageID"));
			CompilerSpecID compilerSpecID =
				new CompilerSpecID((String) state.getEnvironmentVar("XMLImportCompilerSpecID"));
			Language language = DefaultLanguageService.getLanguageService().getLanguage(languageID);
			CompilerSpec compilerSpec = language.getCompilerSpecByID(compilerSpecID);
			println("Importing " + obj.toString());
			MessageLog messageLog = new MessageLog();
			try {
				String programNameOverride = null;
				AutoImporter.importFresh(obj, parentFolder, this, messageLog, monitor,
					new SingleLoaderFilter(XmlLoader.class),
					new LcsHintLoadSpecChooser(language, compilerSpec), programNameOverride,
					OptionChooser.DEFAULT_OPTIONS, MultipleProgramsStrategy.ALL_PROGRAMS);
			}
			catch (Exception e) {
				Msg.error(this, "Error importing " + obj + ": " + messageLog, e);
				return;
			}
		}
	}

	private class XMLFileFilter implements FilenameFilter {
		@Override
		public boolean accept(File dir, String name) {
			File newFile = new File(dir, name);
			if (newFile.isDirectory() && hasXML(newFile)) {
				return true;
			}
			if (name.endsWith(".xml")) {
				return true;
			}
			return false;
		}

		public boolean hasXML(File file) {
			File[] files = file.listFiles();
			for (File file2 : files) {
				if (file2.isDirectory() && hasXML(file2)) {
					return true;
				}
				if (file2.getName().endsWith(".xml")) {
					return true;
				}
			}
			return false;
		}
	}

}
