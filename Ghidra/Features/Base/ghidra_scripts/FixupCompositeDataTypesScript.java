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
import ghidra.app.script.GhidraScript;
import ghidra.program.database.data.DataTypeManagerDB;

public class FixupCompositeDataTypesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (currentProgram == null) {
			return;
		}
		
		if (!currentProgram.hasExclusiveAccess()) {
			popup("This script requires an exclusive checkout of the program");
			return;
		}

		DataTypeManagerDB dtm = (DataTypeManagerDB) currentProgram.getDataTypeManager();
		dtm.fixupComposites(monitor);
	}

}
