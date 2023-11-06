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
// Example script for showing how to use the "AskValues" script method for inputing multiple values
// @category Examples
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.model.listing.Program;
import ghidra.util.MessageType;

public class AskValuesExampleScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		GhidraValuesMap values = new GhidraValuesMap();

		values.defineString("Name");
		values.defineInt("Count");
		values.defineInt("Max Results", 100);
		values.defineChoice("Priority", "Low", "Low", "Medium", "High");
		values.defineProgram("Other Program");
		values.defineProjectFile("Project File");
		values.defineProjectFolder("Project Folder");

		// Optional validator that can be set to validate values before the dialog returns. It
		// is called when the "Ok" button is pushed and must return true before the dialog exits.
		// It also includes a statusListener where messages can be set on the dialog. In this
		// example, we are requiring that the name and program fields be populated

		values.setValidator((valueMap, status) -> {
			if (!valueMap.hasValue("Name")) {
				status.setStatusText("Name must be filled in!", MessageType.ERROR);
				return false;
			}
			if (!valueMap.hasValue("Other Program")) {
				status.setStatusText("Other Program must be filled it!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		// asks the script to show a dialog where the user can give values for all the items
		// in the ValuesMap.

		values = askValues("Enter Example Script Values", null, values);

		// if the user cancels the ask dialog, the script will exit as cancelled. Otherwise
		// the returned ValuesMap will contain the results of the user filling in values from the 
		//dialog. The values map returned may or may not be the same instance as the one passed in.

		String name = values.getString("Name");
		int age = values.getInt("Count");
		int max = values.getInt("Max Results");
		String priority = values.getChoice("Priority");

		// When asking for a program, you must supply a consumer that you will use
		// to release the program. Since programs share open instances, Ghidra uses
		// consumers to keep track of these uses. Scripts can just add themselves
		// as the consumer (The askProgram() method does this for you). It is
		// important to release it when you are done with it. Optionally, you can also
		// provide a tool in which case the program will also be opened in the tool (and the
		// tool would then also add itself as a consumer). Otherwise, the program will not 
		// show up in the tool and when you release the consumer, it will be closed.
		// NOTE: if you call getProgram() more than once, the consumer will be added multiple times
		// and you must release it multiple times
		Program program = values.getProgram("Other Program", this, state.getTool());

		println("Name = " + name);
		println("Count = " + age);
		println("Max Results = " + max);
		println("Priority = " + priority);
		println("Program = " + program);

		// VERY IMPORTANT!!! you must release any programs when you are done with them!
		// If you also opened in the tool, you can immediately release it because the tool will
		// then keep it open.
		program.release(this);

	}
}
