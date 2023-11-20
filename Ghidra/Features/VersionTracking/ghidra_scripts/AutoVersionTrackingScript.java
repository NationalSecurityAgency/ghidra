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
// A script that runs Auto Version Tracking given the options set in one of the following ways:
// 1. If script is run from the CodeBrowser, the GUI options are set in a pop up dialog by user.
// 2. If script is run in headless mode either the defaults provided by the script are used or the 
//    user can specify a script to be run that sets the options. See example script 
//    SetAutoVersionTrackingOptionsScript that can be copied and updated to reflect the users 
//    desired options. 
//  
// NOTE: This is an example to show how run this script in headless mode
//   
//    <ghidra_install>/support/analyzeHeadless.bat/sh c:/MyGhidraProjectFolder 
//     MyProjectName/OptionalFolderContainingProgram -process Program1.exe -postScript 
//     MyOptionsSetupScript -postScript AutoVersionTrackingScript.java "/FolderContainingSession" 
//     "MySessionName" true "/OptionalFolderContainingProgram/Program2.exe"
//
// 
//     NOTE: The first program will be analyzed for you if it is not already analyzed (and if you 
//           do not include the -noanalysis option) as it is part of the typical analyzeHeadless run.
// 		     The second program must be analyzed prior to running the script as the headless analyzer
//           itself knows nothing about the file other than as a given option name. This is true in
//           both GUI and headless mode. 
//       
//     NOTE: The second to last parameter is to identify whether the first listed program
//           is the source program or not. True means first program is source program and second 
//           program is destination program. False means second program is source program and first
//           program is destination program. This is important if you want the correct markup to be 
//           applied from the source to destination program.
//
//     NOTE: The options setup script is optional. It is only necessary if users want to change the
//           default options. To use it make a copy of the example one and save to a new script. You
//           You may need to add the -scriptPath to the headless run so it will find your script.
//
//@category Version Tracking
import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingTask;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.MessageType;
import ghidra.util.exception.CancelledException;
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

		GhidraValuesMap startupValues = new GhidraValuesMap();

		startupValues.defineProjectFolder("Version Tracking Session Folder", "/");
		startupValues.defineString("Version Tracking Session Name");
		startupValues.defineBoolean("Check if current program is the Source Program", true);
		startupValues.defineProgram("Please select the other program");

		startupValues.setValidator((valueMap, status) -> {

			GhidraValuesMap map = (GhidraValuesMap) valueMap;

			if (!valueMap.hasValue("Version Tracking Session Name")) {
				status.setStatusText("Session Name must be filled in!", MessageType.ERROR);
				return false;
			}

			try {
				if (hasExistingSession(map.getString("Version Tracking Session Name"),
					map.getProjectFolder("Version Tracking Session Folder"))) {
					status.setStatusText("Session cannot be an existing session!",
						MessageType.ERROR);
					return false;
				}
			}
			catch (CancelledException e) {
				return false;
			}

			if (!valueMap.hasValue("Please select the other program")) {
				status.setStatusText("Must choose second program!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		startupValues = askValues("Enter Auto Version Tracking Information",
			"Changing these options will not change the corresponding tool options",
			startupValues);

		DomainFolder folder = startupValues.getProjectFolder("Version Tracking Session Folder");

		String name = startupValues.getString("Version Tracking Session Name");
		boolean isCurrentProgramSourceProg =
			startupValues.getBoolean("Check if current program is the Source Program");
		Program otherProgram =
			startupValues.getProgram("Please select the other program", this, state.getTool());


		if (isCurrentProgramSourceProg) {
			sourceProgram = currentProgram;
			destinationProgram = otherProgram;
		}
		else {
			destinationProgram = currentProgram;
			sourceProgram = otherProgram;
		}

		if (sourceProgram == null || destinationProgram == null) {
			return;
		}


		// Need to end the script transaction or it interferes with vt things that need locks
		end(true);


		VTSession session =
			VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);


		if (folder.getFile(name) == null) {
			folder.createFile(name, session, monitor);
		}

		// create a default options map in case cannot get user input
		GhidraValuesMap optionsMap = createDefaultOptions();

		// if running script in GUI get options from user and update the vtOptions with them
		if(!isRunningHeadless()) {
			optionsMap = getOptionsFromUser();

		}
		// else if running script in headless get possible options set by prescript that saves
		// optionsMap in script state variable and update the vtOptions with them
		else {
			// try to get options map from state if running headless
			// if user runs prescript to set up their own options map those options will be used
			// See SetAutoVersionTrackingOptionsScript.java as an example
			GhidraValuesMap stateOptionsMap =
				(GhidraValuesMap) state.getEnvironmentVar("autoVTOptionsMap");
			if (optionsMap != null) {
				optionsMap = stateOptionsMap;
			}

		}

		ToolOptions vtOptions = setToolOptionsFromOptionsMap(optionsMap);

		AutoVersionTrackingTask autoVtTask =
			new AutoVersionTrackingTask(session, vtOptions);

		TaskLauncher.launch(autoVtTask);


		// if not running headless user can decide whether to save or not
		// if running headless - must save here or nothing that was done in this script will be
		// accessible later.
		if (isRunningHeadless()) {
			otherProgram.save("Updated with Auto Version Tracking", monitor);
			session.save();
		}


		println(autoVtTask.getStatusMsg());
		otherProgram.release(this);
	}

	/**
	 * Method to determine if there is an existing VTSession in the given folder with the given name
	 * @param name the given name
	 * @param folder the given Ghidra project folder
	 * @return true if there is an existing VTSession with the given name in the given folder, false
	 *          otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean hasExistingSession(String name, DomainFolder folder) throws CancelledException {

		DomainFile[] files = folder.getFiles();

		for (DomainFile file : files) {
			monitor.checkCancelled();

			if (file.getName().equals(name)) {
				if (file.getContentType().equals("VersionTracking")) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Method to create the default GhidraValuesMap AutoVT options
	 * @return the default GhidraValuesMap AutoVT options
	 */
	private GhidraValuesMap createDefaultOptions() {
		GhidraValuesMap optionsValues = new GhidraValuesMap();

		optionsValues.defineBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION_TEXT, true);
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION_TEXT, true);
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION_TEXT, true);
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION_TEXT, true);
		optionsValues.defineBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION_TEXT, true);
		optionsValues.defineBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION_TEXT, true);
		optionsValues.defineBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION_TEXT, true);
		optionsValues.defineInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION_TEXT, 5);
		optionsValues.defineInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION_TEXT, 3);
		optionsValues.defineInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT, 10);
		optionsValues.defineInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT, 10);
		optionsValues.defineBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION_TEXT, true);
		optionsValues.defineInt(VTOptionDefines.MIN_VOTES_OPTION_TEXT, 2);
		optionsValues.defineInt(VTOptionDefines.MAX_CONFLICTS_OPTION_TEXT, 0);
		optionsValues.defineDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION_TEXT, 0.95);
		optionsValues.defineDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION_TEXT, 10.0);

		return optionsValues;
	}

	/**
	 * Method to ask the user for AutoVT options
	 * @return a GhidraValuesMap containing AutoVT options values
	 * @throws CancelledException if cancelled
	 */
	private GhidraValuesMap getOptionsFromUser() throws CancelledException {

		GhidraValuesMap optionsValues = createDefaultOptions();

		optionsValues = askValues("Enter Auto Version Tracking Options",
			"These options will not be saved to your current tool options.",
			optionsValues);

		return optionsValues;
	}

	/**
	 * Set the Auto Version Tracking options given a GhidraValuesMap containing the options values
	 * @param optionsValues the option values in a GhidraValuesMap
	 * @return ToolOptions containing the Auto Version Tracking options values
	 */
	private ToolOptions setToolOptionsFromOptionsMap(GhidraValuesMap optionsValues) {

		ToolOptions toolOptions = new VTOptions("Dummy");

		toolOptions.setBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION,
			optionsValues.getBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION_TEXT));
		toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION,
			optionsValues.getBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION_TEXT));
		toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION,
			optionsValues.getBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION_TEXT));
		toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION,
			optionsValues.getBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION_TEXT));
		toolOptions.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION,
			optionsValues.getBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION_TEXT));
		toolOptions.setBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION,
			optionsValues.getBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION_TEXT));
		toolOptions.setBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION,
			optionsValues.getBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION_TEXT));

		toolOptions.setInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION,
			optionsValues.getInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION_TEXT));
		toolOptions.setInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION,
			optionsValues.getInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION_TEXT));
		toolOptions.setInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION,
			optionsValues.getInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT));
		toolOptions.setInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION,
			optionsValues.getInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT));

		toolOptions.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION,
			optionsValues.getDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION_TEXT));
		toolOptions.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION,
			optionsValues.getDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION_TEXT));

		toolOptions.setBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION,
			optionsValues.getBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION_TEXT));

		toolOptions.setInt(VTOptionDefines.MIN_VOTES_OPTION,
			optionsValues.getInt(VTOptionDefines.MIN_VOTES_OPTION_TEXT));

		toolOptions.setInt(VTOptionDefines.MAX_CONFLICTS_OPTION,
			optionsValues.getInt(VTOptionDefines.MAX_CONFLICTS_OPTION_TEXT));

		return toolOptions;

	}

}
