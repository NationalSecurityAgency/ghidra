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
//Script that enables user to add an existing Version Tracking Session to version control. This
//is meant to to be used when project is a shared project and when running in headless mode 
//since it is simple add a VTSession to version control from the project manager when running in
//GUI mode.
//@category Version Tracking
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.model.DomainFile;
import ghidra.util.MessageType;

public class AddVTSessionToVersionControl extends GhidraScript {

	@Override
	public void run() throws Exception {

		GhidraValuesMap startupValues = new GhidraValuesMap();

		startupValues.defineProjectFile("Select Version Tracking Session", "/");
		startupValues.defineString("Enter commit message", "Commiting session to version control");

		startupValues.setValidator((valueMap, status) -> {

			if (!valueMap.hasValue("Select Version Tracking Session")) {
				status.setStatusText("Must select a Version Tracking Session!", MessageType.ERROR);
				return false;
			}

			if (!valueMap.hasValue("Enter commit message")) {
				status.setStatusText("Must enter a commit message!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		startupValues = askValues(
			"Enter Version Tracking Session info for adding to source control:", "", startupValues);

		DomainFile sessionDF = startupValues.getProjectFile("Select Version Tracking Session");
		String commitMsg = startupValues.getString("Enter commit message");

		if (sessionDF.isVersioned()) {
			println("Chosen session is already in version control");
			return;
		}

		// add session to version control and do not keep checkout out
		sessionDF.addToVersionControl(commitMsg, false, monitor);

		println(sessionDF.getName() + " was successfully added to version control.");

	}



}
