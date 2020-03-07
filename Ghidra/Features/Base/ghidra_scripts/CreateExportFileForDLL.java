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
// Causes a .exports file to be created for a .dll imported as a program.
//   There may be a corresponding .def file in the Ghidra\Features\Base\data\symbols\win directory
//   which helps give names to ordinal numbers.
//   The program does not need to be analyzed for the .exports file to be created.
//   Just import the program, and don't analyze, and run this script.
//
//   The name of the .exports file will be printed when the script finishes.
//
//@category Windows
//@keybinding 
//@menupath 
//@toolbar 

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.LibraryLookupTable;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class CreateExportFileForDLL extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			Msg.error(this, "Script requires active program");
		}

		// push this .dll into the location of the system .exports files.
		// must have write permissions.
		ResourceFile file = LibraryLookupTable.createFile(currentProgram, false,
			SystemUtilities.isInDevelopmentMode(), monitor);

		println("Created .exports file : " + file.getAbsolutePath());
	}

}
