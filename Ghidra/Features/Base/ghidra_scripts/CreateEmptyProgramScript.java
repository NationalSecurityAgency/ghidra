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
//Creates an empty program using
//the language selected by the user.
//@category Program

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class CreateEmptyProgramScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		LanguageCompilerSpecPair pair = askLanguage("New Program: Select Language", "Select");
		if (pair == null) {
			println("User cancelled operation.");
		}
		else {
			try {
				Language language = pair.getLanguage();
				CompilerSpec compilerSpec = pair.getCompilerSpec();

				String name = "Untitled-" + language.getLanguageID().toString().replace(':', '_') +
					"_" + compilerSpec.getCompilerSpecID();
				Program program = new ProgramDB(name, language, compilerSpec, this);

				ProgramManager programManager = state.getTool().getService(ProgramManager.class);
				programManager.openProgram(program);

				program.release(this);
			}
			catch (Exception e) {
				Msg.showInfo(getClass(), null, "Error Creating New Program", e.getMessage());
			}
		}
	}
}
