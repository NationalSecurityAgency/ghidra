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
// Fixes up all composite datatypes within the current program to account for 
// any changes to primitive datatype sizes or alignment rules as defined
// by the associated data organization.
//
// This script requires exclusive access to the program to avoid the possibilty
// of excessive change conflicts.
//
// This script can be run multiple times without harm
//@category Data Types
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.*;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

public class FixupCompositeDataTypesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		PluginTool tool = state.getTool();
		if (tool == null) {
			print("This script does not support headless use");
		}

		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		if (service == null) {
			popup("This script requires the DataTypeManagerService");
			return;
		}
		
		ArrayList<DTMWrapper> dtms = new ArrayList<>();

		for (DataTypeManager dtm : service.getDataTypeManagers()) {
			if (dtm instanceof BuiltInDataTypeManager) {
				continue;
			}
			if (dtm instanceof ProgramDataTypeManager) {
				dtms.add(0, new DTMWrapper((ProgramDataTypeManager) dtm));
			}
			else if (dtm instanceof DataTypeManagerDB) {
				dtms.add(new DTMWrapper((DataTypeManagerDB) dtm));
			}
		}

		DataTypeManagerDB dtm =
			askChoice("Fixup All Composites", "Select Data Type Manager: ", dtms, dtms.get(0)).dtm;

		if (dtm instanceof ProgramDataTypeManager) {
			Program program = ((ProgramDataTypeManager) dtm).getProgram();
			if (!program.hasExclusiveAccess()) {
				popup("Shared program must have an exclusive checkout.");
				return;
			}
		}
		else if (dtm instanceof ProjectDataTypeManager) {
			DomainFile df = ((ProjectDataTypeManager) dtm).getDomainFile();
			if (df.isVersioned() && !df.isCheckedOutExclusive()) {
				popup("Shared project archive must have an exclusive checkout.");
				return;
			}
		}

		if (!dtm.isUpdatable()) {
			popup("Selected archive must be open for update.");
			return;
		}

		dtm.fixupComposites(monitor);
	}

	private class DTMWrapper {
		DataTypeManagerDB dtm;

		DTMWrapper(DataTypeManagerDB dtm) {
			this.dtm = dtm;
		}

		@Override
		public String toString() {
			return dtm.getName();
		}
	}

}
