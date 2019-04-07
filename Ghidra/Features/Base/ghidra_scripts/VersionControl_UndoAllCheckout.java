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
//Undoes all checkouts under a folder.
//@category    Version Control
//@menupath    Tools.Version Control.Undo All Checkouts

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;

public class VersionControl_UndoAllCheckout extends GhidraScript {

	public VersionControl_UndoAllCheckout() {
	}


	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		DomainFolder rootFolder =
			askProjectFolder("Choose root folder to recursively 'undo checkouts'");

		if (askYesNo("Confirm action", "Are you sure you want to undo all checkouts of files in " +
			rootFolder +
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
			if (file.isCheckedOut()) {
				filesProcessed++;
				monitor.setMessage(
					"Releasing file " + file.getName() + " (" + filesProcessed + ")");
				file.undoCheckout(false);
			}
		}
		long end_ts = System.currentTimeMillis();

		println("Finished releasing checkout of all files in folder: " + rootFolder.getPathname());
		println("Total files: " + filesProcessed);
		println("Total time: " + (end_ts - start_ts));
	}

}
