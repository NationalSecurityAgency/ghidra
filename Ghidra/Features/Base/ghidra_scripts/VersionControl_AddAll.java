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
//Adds all files under a folder to version control.
//@category    Version Control
//@menupath    Tools.Version Control.Add All

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;

public class VersionControl_AddAll extends GhidraScript {

	public VersionControl_AddAll() {
	}

	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		DomainFolder rootFolder =
			askProjectFolder("Choose root folder to recursively 'add to version control'");
		String checkInComment =
			askString("Check-in comment", "Enter the comment that will be used", "Initial import");

		long start_ts = System.currentTimeMillis();
		monitor.initialize(0);
		monitor.setIndeterminate(true);

		int filesProcessed = 0;
		for (DomainFile file : ProjectDataUtils.descendantFiles(rootFolder)) {
			if (monitor.isCancelled()) {
				break;
			}

			if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(file.getContentType()) ||
				file.isVersioned()) {
				continue;// skip
			}
			filesProcessed++;
			monitor.setMessage("Adding file " + file.getName() + " (" + filesProcessed + ")");
			file.addToVersionControl(checkInComment, false, monitor);

		}
		long end_ts = System.currentTimeMillis();

		println("Finished adding all programs to version control for folder: " +
			rootFolder.getPathname());
		println("Total files: " + filesProcessed);
		println("Total time: " + (end_ts - start_ts));
	}

}
