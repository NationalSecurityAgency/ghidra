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
//Imports all programs from a selected directory.
//@category Import

import java.io.File;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;

public class ImportAllProgramsFromADirectoryScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		File directory = askDirectory("Please specify the input directory:", "DIRECTORY");

		LanguageCompilerSpecPair language = askLanguage("Please select a language:", "LANGUAGE");

		DomainFolder folder = askProjectFolder("Please select a project folder:");

		MessageLog log = new MessageLog();

		File[] files = directory.listFiles();

		for (File file : files) {

			Thread.sleep(1000);

			if (monitor.isCancelled()) {
				break;
			}

			if (file.getName().startsWith(".")) {//skip private files... like ".svn"
				continue;
			}

			LoadResults<Program> loadResults = null;
			try {
				loadResults = AutoImporter.importByLookingForLcs(file, state.getProject(),
					folder.getPathname(), language.getLanguage(), language.getCompilerSpec(), this,
					log, monitor);
				loadResults.getPrimary().save(state.getProject(), log, monitor);
			}
			catch (IOException e) {
				println("Unable to import program from file " + file.getName());
			}
			finally {
				if (loadResults != null) {
					loadResults.release(this);
				}
			}

			println(log.toString());
			log.clear();
		}
	}
}
