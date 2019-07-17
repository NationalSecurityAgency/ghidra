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
//Recursively finds a folder that matches a string and renames it to a new name.
//@category Project
//@menupath

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectDataUtils;

public class BatchRename extends GhidraScript {

	public BatchRename() {
	}


	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		DomainFolder rootFolder = askProjectFolder("Choose root folder:");
		String findString = askString("Match String", "Enter foldername to find:");
		String replaceString = askString("Replace", "Enter replacement foldername:");

		long start_ts = System.currentTimeMillis();
		monitor.initialize(0);
		monitor.setIndeterminate(true);

		int foldersProcessed = 0;
		int foldersRenamed = 0;
		for (DomainFolder folder : ProjectDataUtils.descendantFolders(rootFolder)) {
			if (monitor.isCancelled()) {
				break;
			}

			if (folder.getName().equals(findString)) {
				println("Found " + folder.getPathname() + ", renaming...");
				folder.setName(replaceString);
				foldersRenamed++;
			}

			foldersProcessed++;

		}
		long end_ts = System.currentTimeMillis();

		println("Finished batch rename under folder: " + rootFolder);
		println("Total folders: " + foldersProcessed);
		println("Total folders renamed: " + foldersRenamed);
		println("Total time: " + (end_ts - start_ts));
	}

}
