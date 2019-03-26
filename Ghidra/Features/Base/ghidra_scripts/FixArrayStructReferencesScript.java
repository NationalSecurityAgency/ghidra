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
//
// When an array of structures is created at a location, and the
// array type contains a pointer type, Ghidra will lay down valid
// references as long as the pointer is valid (points to something
// in memory).  However, at the first sign of invalidity, the
// CodeManager bails and stops laying down references.
//
// This script, when run at the location of the array of structures,
// will update each individual structure element, iterating through
// the whole array until the end.
//
//@category Data Types

import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.listing.Data;

public class FixArrayStructReferencesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Data data = getDataAt(currentAddress);
		if (data == null) {
			printerr("no data at " + currentAddress);
			return;
		}
		if (!data.isArray()) {
			printerr("data at " + currentAddress + " is not an array");
			return;
		}
		CodeManager codeManager = ((ProgramDB) currentProgram).getCodeManager();
		int numComponents = data.getNumComponents();
		monitor.setMessage("updating data references in array");
		monitor.initialize(numComponents);
		for (int ii = 0; ii < numComponents; ++ii) {
			if (monitor.isCancelled()) {
				printerr("cancelled");
				return;
			}
			monitor.incrementProgress(1);
			Data component = data.getComponent(ii);
			codeManager.updateDataReferences(component);
		}
	}
}
