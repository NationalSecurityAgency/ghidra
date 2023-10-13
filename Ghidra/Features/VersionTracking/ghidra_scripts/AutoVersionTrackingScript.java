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
// An example of how to create Version Tracking session, run some correlators to find matching
// data and and then save the session.
//@category Examples.Version Tracking

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingTask;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskLauncher;

public class AutoVersionTrackingScript extends GhidraScript {

	private Program sourceProgram;
	private Program destinationProgram;

	@Override
	public void cleanup(boolean success) {
		if (sourceProgram != null && sourceProgram.isUsedBy(this)) {
			sourceProgram.release(this);
		}
		if (destinationProgram != null && destinationProgram.isUsedBy(this)) {
			destinationProgram.release(this);
		}
		super.cleanup(success);
	}

	@Override
	public void run() throws Exception {

		DomainFolder folder =
			askProjectFolder("Please choose a folder for your Version Tracking session.");
		String name = askString("Please enter a Version Tracking session name", "Session Name");

		boolean isCurrentProgramSourceProg = askYesNo("Current Program Source Program?",
			"Is the current program your source program?");

		if (isCurrentProgramSourceProg) {
			sourceProgram = currentProgram;
			destinationProgram = askProgram("Please select the destination (new) program");
		}
		else {
			destinationProgram = currentProgram;
			sourceProgram = askProgram("Please select the source (existing annotated) program");
		}

		if (sourceProgram == null || destinationProgram == null) {
			return;
		}

		boolean autoCreateImpliedMatches = askYesNo("Implied Matches?",
			"Would you like the script to figure out implied matches from any matches it creates?");

		// Need to end the script transaction or it interferes with vt things that need locks
		end(true);

		VTSession session =
			VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);

		folder.createFile(name, session, monitor);

		ToolOptions options = getOptions();

		boolean originalImpliedMatchSetting =
			options.getBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, false);

		options.setBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, autoCreateImpliedMatches);

		AutoVersionTrackingTask autoVtTask =
			new AutoVersionTrackingTask(session, options, 0.95, 10.0);


		TaskLauncher.launch(autoVtTask);


		// if not running headless user can decide whether to save or not
		// if running headless - must save here or nothing that was done in this script will be
		// accessible later.
		if (isRunningHeadless()) {
			session.save();
		}
		options.setBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, originalImpliedMatchSetting);

		println(autoVtTask.getStatusMsg());
	}


	private ToolOptions getOptions() {
		ToolOptions vtOptions = new VTOptions("Dummy");
		PluginTool tool = state.getTool();
		if (tool != null) {
			vtOptions = tool.getOptions(VTController.VERSION_TRACKING_OPTIONS_NAME);
		}
		return vtOptions;
	}

}
