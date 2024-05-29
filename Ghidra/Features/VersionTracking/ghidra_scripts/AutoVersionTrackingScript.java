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

// A script that runs Auto Version Tracking such that the current program in the tool is the 
// destination program and the user is prompted to choose the source program. The user must also
// choose a name for a new Version Tracking Session. The script cannot run using an existing session.
// There are many options that can be set in one of the following ways:
// 1. If script is run from the CodeBrowser, the GUI options are set in a pop up dialog by user.
// 2. If script is run in headless mode either the default options provided by the script are used  
//    or the user can specify a script to be run that sets the options. See example script 
//    SetAutoVersionTrackingOptionsScript that can be copied and updated to reflect the users 
//    desired options. 
//  
// HEADLESS MODE NON-SHARED PROJECT: 
//    
//    This is an example to show how run this script in headless mode against a local non-shared
//    project
//   
//    <ghidra_install>/support/analyzeHeadless.bat/sh c:/MyGhidraProjectFolder 
//     MyProjectName/OptionalFolderContainingDestProgram -process DestinationProgram.exe -postScript 
//     MyOptionsSetupScript -postScript AutoVersionTrackingScript.java "/FolderContainingSession" 
//     "MySessionName" "/OptionalFolderContainingSourceProgram/SourceProgram.exe"
//
//     NOTE: The destination program will be analyzed for you if it is not already analyzed (and if  
//           you do not include the -noanalysis option) as it is part of the typical analyzeHeadless 
// 		     run. The source program must be analyzed prior to running the script as the headless 
//           analyzer itself knows nothing about the file other than as a given option name. This is 
//           true in both GUI and headless mode. 
//
//     NOTE: The options setup script is optional. It is only necessary if users want to change the
//           other default options that are not settable on the headless command line. To use an 
//           options script, make a copy of the example one (SetAutoVersionTrackingOptionsScript) 
//           and save it with a new script file name. Then use the -postScript headless argument to
//           run the options script before the second -postScript argument to run the 
//           AutoVersionTrackingScript. Depending on where you save your script, you might also need 
//           to add the -scriptPath to the headless run so it will find your script.
//
// SHARED PROJECT MODE FROM GUI
//     
//     From the GUI, this script can run on local project files contained in the shared project or 
//     those that have been added to source control. If the destination program has been added to 
//     version control but is not checked out, the user will be prompted to checkout the file. 
//     If the file is not checked-out the script will not proceed. User is responsible for checking 
//     in changes to the destination file made by the script if they want the changes added. After 
//     the script is run, if user wants to add the session to version control they can. 
//     
// SHARED PROJECT MODE FROM HEADLESS MODE:
//
//     If running this script in headless mode on a shared project, both source and destination 
//     programs must have already been added to version control before running the script or the 
//     script will not be able to locate the programs because the only programs visible to it will 
//     be those in the shared repository project. 
//
//     The headless shared project run will be different from the non-shared project in terms of how 
//     to tell it where the project location is. Instead of specifying a project location and 
//     project name, the user must instead specify the Ghidra Server repository URL.
//            
//     Also, there are necessary extra arguments to the headless run in order to connect to the
//     server and commit the destination program changes to the server. 
//
//     This is an example command line for running this script in headless shared project mode:
//   
//    <ghidra_install>/support/analyzeHeadless.bat/sh 
//     ghidra://localhost:13100/MyProjectName/OptionalFolderContainingDestProgram -process 
//     DestinationProgram.exe -postScript MyOptionsSetupScript -postScript 
//     AutoVersionTrackingScript.java "/FolderContainingSession" 
//     "MySessionName" "/OptionalFolderContainingSourceProgram/SourceProgram.exe" 
//     optionalAddSessionToVersionControl -connect username -p -commit "my commit msg"
//
//	   NOTE: The Destination program being processed in the shared project headless run must not be
//     checked out by anyone prior to the run. The headless script expects the file to be in version 
//     control but not checked out. The headless script will check it out, run the given scripts 
//     against it then check in any changes with the given commit message.
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

	private static final int NUM_ARGS = 3;

	@Override
	public void run() throws Exception {
		
		if(currentProgram == null) {
			println("Please open the destination program.");
			return;
		}

		Program destinationProgram = currentProgram;

		if (!destinationProgram.canSave()) {
			println("VT Session destination program " + destinationProgram.getName() +
				" is read-only which prevents its use.");
			return;
		}

		GhidraValuesMap startupValues = new GhidraValuesMap();

		startupValues.defineProjectFolder("Version Tracking Session Folder", "/");
		startupValues.defineString("Version Tracking Session Name");
		startupValues.defineProjectFile("Please select the SOURCE program", "/");

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

			if (!valueMap.hasValue("Please select the SOURCE program")) {
				status.setStatusText("Must choose a SOURCE program!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		startupValues = askValues("Enter Auto Version Tracking Information",
			"The currently opened program is assumed to be the DESTINATION program.",
			startupValues);

		DomainFolder folder = startupValues.getProjectFolder("Version Tracking Session Folder");

		String name = startupValues.getString("Version Tracking Session Name");

		// setting auto upgrade to isHeadless, will cause headless uses to auto upgrade, but in
		// GUI mode, will prompt before upgrading.
		boolean autoUpgradeIfNeeded = isRunningHeadless();

		DomainFile sourceProgramDF =
			startupValues.getProjectFile("Please select the SOURCE program");
		if (!Program.class.isAssignableFrom(sourceProgramDF.getDomainObjectClass())) {
			println(sourceProgramDF.getContentType() + " file " + sourceProgramDF.getName() +
				" may not be specified as the SOURCE Program.");
			return;
		}

		Program sourceProgram = (Program) sourceProgramDF.getDomainObject(this, autoUpgradeIfNeeded,
			false, monitor);

		VTSession session = null;
		try {
			// Need to end the script transaction or it interferes with vt things that need locks
			end(true);

			session = new VTSessionDB(name, sourceProgram, destinationProgram, this);

			if (folder.getFile(name) == null) {
				folder.createFile(name, session, monitor);
			}

			// create a default options map in case cannot get user input
			GhidraValuesMap optionsMap = createDefaultOptions();

			// if running script in GUI get options from user and update the vtOptions with them
			if (!isRunningHeadless()) {
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
				if (stateOptionsMap != null) {
					optionsMap = stateOptionsMap;
				}

			}

			ToolOptions vtOptions = setToolOptionsFromOptionsMap(optionsMap);

			AutoVersionTrackingTask autoVtTask = new AutoVersionTrackingTask(session, vtOptions);

			TaskLauncher.launch(autoVtTask);

			// Save destination program and session changes
			destinationProgram.save("Updated with Auto Version Tracking", monitor);
			session.save();

			println(autoVtTask.getStatusMsg());
		}
		catch (CancelledException e) {
			// let finally clean up
			return;
		}
		finally {
			if (sourceProgram != null) {
				sourceProgram.release(this);
			}
			if (session != null) {
				session.release(this);

			}
		}

		// try adding to version control if it is a transient project (ie headless operating against
		// a shared project repository
		if (state.getProject().getProjectLocator().isTransient()) {

			session.getDomainFile()
					.addToVersionControl("Added new session + " + session.getName(), false,
						monitor);
			println("Added session " + session.getName() + " to version control.");
		}

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
			"These options will not be saved to your current tool options.", optionsValues);

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
