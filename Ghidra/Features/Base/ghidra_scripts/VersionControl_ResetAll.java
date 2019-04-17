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
//Resets all files under a folder to their first revision.
//@category    Version Control
//@menupath    Tools.Version Control.Reset All
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;

public class VersionControl_ResetAll extends GhidraScript {

	public VersionControl_ResetAll() {
	}


	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		DomainFolder rootFolder =
			askProjectFolder("Choose root folder to recursively 'reset to base rev'");

		if (askYesNo("Confirm delete",
			"Are you sure you want to delete all revisions of files in " + rootFolder +
				"?") == false) {
			return;
		}

		long start_ts = System.currentTimeMillis();
		monitor.initialize(0);
		monitor.setIndeterminate(true);

		int filesProcessed = 0;
		for (DomainFile file : ProjectDataUtils.descendantFiles(rootFolder)) {
			if (monitor.isCancelled()) {
				break;
			}

			if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(file.getContentType()) ||
				!file.isVersioned() || file.getLatestVersion() < 2) {
				continue;// skip
			}
			monitor.setMessage("Resetting " + file.getName() + " (" + file.getLatestVersion() + "");
			try {
				for (int verNum = file.getLatestVersion(); verNum > 1; verNum--) {
					file.delete(verNum);
				}
				filesProcessed++;
			}
			catch (IOException ioe) {
				println("Failed to reset " + file.getPathname() + " version: " + ioe.getMessage());
			}

		}
		long end_ts = System.currentTimeMillis();

		println("Finished reseting to base rev for folder: " + rootFolder.getPathname());
		println("Total files: " + filesProcessed);
		println("Total time: " + (end_ts - start_ts));
	}

}
