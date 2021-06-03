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
package ghidra.app.script;

import java.awt.Color;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.rmi.ConnectException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineMessageDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.*;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.dialog.AskAddrDialog;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.query.TableService;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.framework.Application;
import ghidra.framework.client.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.FileSystem;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowNamespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.table.AddressArrayTableModel;
import ghidra.util.table.AddressSetTableModel;
import ghidra.util.task.TaskMonitor;

/**
 * <h2>Ghidra Script Development.</h2>
 * In order to write a script:
 * <ol>
 * 	<li>Ghidra script must be written in Java.</li>
 * 	<li>Your script class must extend <code>ghidra.app.script.GhidraScript</code>.</li>
 * 	<li>You must implement the <code>run()</code> method. This is where you insert your
 * 			script-specific code.</li>
 * 	<li>You should create a description comment at the top of the file. Each description
 * 			line should start with &quot;//&quot;.</li>
 * </ol>
 * <br><br>
 * When you create a new script using the script manager,
 * you will automatically receive a source code stub (as shown below).
 * <pre>
 *  //TODO write a description for this script
 *
 * 	public class NewScript extends GhidraScript {
 *
 * 		public void run() throws Exception {
 * 			//TODO Add User Code Here
 * 		}
 * 	}
 * </pre>
 * <h3>Ghidra Script State</h3>
 * <blockquote>
 * 
 * <p>All scripts, when run, will be handed the current state in the form of class instance 
 * variable. These variables are:
 * <ol>
 *   <li><code>currentProgram</code>: the active program</li>
 *   <li><code>currentAddress</code>: the address of the current cursor location in the tool</li>
 *   <li><code>currentLocation</code>: the program location of the current cursor location
 *   			in the tool, or null if no program location exists</li>
 *   <li><code>currentSelection</code>: the current selection in the tool, or null
 *   			if no selection exists</li>
 *   <li><code>currentHighlight</code>: the current highlight in the tool, or null
 *   			if no highlight exists</li>
 * </ol>
 * </blockquote>
 *
 * <h3>Hello World Example</h3>
 * This example, when run, will simply print &quot;Hello World&quot; into the Ghidra console.
 * <pre>
 * 	public class HelloWorldScript extends GhidraScript {
 * 		public void run() throws Exception {
 * 			println(&quot;Hello World!&quot;);
 * 		}
 * 	}
 * </pre>
 * All scripts, when run, will be handed the current state and are automatically
 * run in a separate thread.
 * <br>
 * @see ghidra.app.script.GhidraState
 * @see ghidra.program.model.listing.Program
 */
public abstract class GhidraScript extends FlatProgramAPI {
	// Stores last-selected value for askXxx() methods, used to pre-populate askXxx()
	// GUI dialogs if they are run more than once
	private static Map<String, Map<Class<?>, Object>> askMap = new HashMap<>();

	protected ResourceFile sourceFile;
	protected GhidraState state;
	protected PrintWriter writer;
	protected Address currentAddress;
	protected ProgramLocation currentLocation;
	protected ProgramSelection currentSelection;
	protected ProgramSelection currentHighlight;

	// Stores any parameters in a .properties file sharing the same base name as this GhidraScript
	protected GhidraScriptProperties propertiesFileParams;
	protected List<ResourceFile> potentialPropertiesFileLocs = new ArrayList<>();
	private CodeUnitFormat cuFormat;

	// Stores any script-specific arguments
	private String[] scriptArgs = new String[0];
	private int askScriptArgIndex = 0;

	private Program originalProgram; // needed to properly consider analysis mode

	private static class DIRECTORY {
		//place holder class for directories
	}

	public enum AnalysisMode {
		/**
		 * ENABLED - Script will run normally with Auto-Analysis responding to changes
		 */
		ENABLED,
		/**
		 * DISABLED - Script will coordinate with AutoAnalysisManager to run with
		 * analysis disabled (change events will be ignored).  Script will wait for any
		 * pending analysis to complete.  Within headed environments an additional modal task dialog
		 * will be displayed while the script is active to prevent the user from initiating
		 * additional program changes.
		 */
		DISABLED,
		/**
		 * SUSPENDED - Script will coordinate with AutoAnalysisManager to run with
		 * analysis suspended (change events will be analyzed after script execution completes).
		 * Script will wait for any pending analysis to complete.
		 */
		SUSPENDED
	}

	/**
	 * The run method is where the script specific code is placed.
	 * @throws Exception if any exception occurs.
	 */
	protected abstract void run() throws Exception;

	/**
	 * Set the context for this script.
	 * 
	 * @param state state object
	 * @param monitor the monitor to use during run
	 * @param writer the target of script "print" statements
	 */
	public final void set(GhidraState state, TaskMonitor monitor, PrintWriter writer) {
		this.state = state;
		this.monitor = monitor;
		this.writer = writer;
		loadVariablesFromState();
	}

	/**
	 * Execute/run script and {@link #doCleanup} afterwards.
	 * 
	 * @param runState state object
	 * @param runMonitor the monitor to use during run
	 * @param runWriter the target of script "print" statements
	 * @throws Exception if the script excepts
	 */
	public final void execute(GhidraState runState, TaskMonitor runMonitor, PrintWriter runWriter)
			throws Exception {
		boolean success = false;
		try {
			doExecute(runState, runMonitor, runWriter);
			success = true;
		}
		finally {
			doCleanup(success);
		}
	}

	private void doExecute(GhidraState runState, TaskMonitor runMonitor, PrintWriter runWriter)
			throws Exception {
		this.state = runState;
		this.monitor = runMonitor;
		this.writer = runWriter;
		loadVariablesFromState();

		loadPropertiesFile();

		originalProgram = currentProgram;
		askScriptArgIndex = 0;

		AnalysisMode scriptAnalysisMode = getScriptAnalysisMode();
		if (originalProgram == null || scriptAnalysisMode == AnalysisMode.ENABLED) {
			executeNormal();
		}
		else {
			executeAsAnalysisWorker(scriptAnalysisMode == AnalysisMode.SUSPENDED, runMonitor);
		}
		updateStateFromVariables();
	}

	protected void loadPropertiesFile() throws IOException {
		// Only attempt to read .properties file if the properties variable has not
		// already been initialized
		if (propertiesFileParams == null || propertiesFileParams.isEmpty()) {

			// If user has specified a location, check that location first.
			// If not found, then default to searching in script directory.

			// Look for and load info from properties file
			propertiesFileParams = new GhidraScriptProperties();
			String basename = getScriptName();
			basename = basename.substring(0, basename.lastIndexOf('.'));

			if (potentialPropertiesFileLocs.size() > 0) {
				propertiesFileParams.loadGhidraScriptProperties(potentialPropertiesFileLocs,
					basename);
			}

			if (propertiesFileParams.isEmpty()) {
				if (sourceFile != null) {
					ResourceFile scriptLocation = sourceFile.getParentFile();

					if (scriptLocation != null) {
						propertiesFileParams.loadGhidraScriptProperties(scriptLocation, basename);
					}
					else {
						Msg.warn(this,
							"Unable to find a parent folder for this script (while searching for .properties file).");
					}
				}
			}
		}
	}

	private void doCleanup(boolean success) {
		cleanup(success);
	}

	/**
	 * A callback for scripts to perform any needed cleanup after the script is finished
	 * @param success true if the script was successful
	 */
	public void cleanup(boolean success) {
		// for users to override
	}

	/**
	 * Set potential locations of .properties files for scripts (including subscripts).
	 * This should be used when the .properties file is not located in the same directory
	 * as the script, and the user has supplied one or more potential locations for the
	 * .properties file(s).
	 *
	 * @param locations directories that contain .properties files
	 */
	public void setPotentialPropertiesFileLocations(List<ResourceFile> locations) {
		potentialPropertiesFileLocs = locations;
	}

	/**
	 * Explicitly set the .properties file location and basename for this script (used
	 * if a ResourceFile representing the GhidraScript is not available -- i.e., if
	 * running GhidraScript from a .class file or instantiating the actual GhidraScript
	 * object directly).
	 *
	 * @param dirLocation  String representation of the path to the .properties file
	 * @param basename     base name of the file
	 * @throws IOException if there is an exception loading the new properties file
	 */
	public void setPropertiesFileLocation(String dirLocation, String basename) throws IOException {
		File testIfDir = new File(dirLocation);

		propertiesFileParams = new GhidraScriptProperties();

		// Check if valid directory, then try to load .properties file
		if (testIfDir.isDirectory()) {
			propertiesFileParams.loadGhidraScriptProperties(new ResourceFile(dirLocation),
				basename);
		}
	}

	/**
	 * Explicitly set the .properties file (used if a ResourceFile representing the
	 * GhidraScript is not available -- i.e., if running GhidraScript from a .class file
	 * or instantiating the actual GhidraScript object directly).
	 *
	 * @param propertiesFile  the actual .properties file for this GhidraScript
	 * @throws IOException if there is an exception reading the properties
	 */
	public void setPropertiesFile(File propertiesFile) throws IOException {
		setPropertiesFile(new ResourceFile(propertiesFile));
	}

	private void setPropertiesFile(ResourceFile propertiesFile) throws IOException {
		propertiesFileParams = new GhidraScriptProperties();

		if (propertiesFile.isFile()) {
			propertiesFileParams.loadGhidraScriptProperties(propertiesFile);
		}
	}

	private void executeAsAnalysisWorker(boolean analyzeChanges, TaskMonitor runMonitor)
			throws Exception {

		AutoAnalysisManager analysisManager =
			AutoAnalysisManager.getAnalysisManager(currentProgram);

		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return getScriptName();
			}

			@Override
			public boolean analysisWorkerCallback(Program program, Object workerContext,
					TaskMonitor workerMonitor) throws Exception, CancelledException {
				monitor = workerMonitor;
				monitor.setProgress(0);
				monitor.setMessage("Executing " + getScriptName());
				executeNormal();
				return true;
			}
		};

		if (!analyzeChanges && !isRunningHeadless() && analysisManager.isAnalyzing()) {
			Msg.showWarn(this, null, worker.getWorkerName(),
				"This script may not be run while auto-analysis is already in-progress.\n" +
					"Please try again later.");
			return;
		}

		analysisManager.scheduleWorker(worker, null, analyzeChanges, runMonitor);
	}

	private void executeNormal() throws Exception {
		start();
		try {
			run();
			monitor.checkCanceled();
		}
		finally {
			end(true);
		}
	}

	@Override
	public DomainFolder getProjectRootFolder() {
		if (isRunningHeadless()) {
			Project project = state.getProject();
			ProjectData projectData = project.getProjectData();
			return projectData.getRootFolder();
		}
		return super.getProjectRootFolder();
	}

	protected boolean promptToKeepChangesOnException() {

		String message = "<html>Encountered exception running script \"" +
			HTMLUtilities.escapeHTML(sourceFile.getName()) +
			"\".<br><br>Keep the changes to the program?";
		//@formatter:off
			int choice =
					OptionDialog.showOptionNoCancelDialog(
					null,
					"Keep Changes?",
					message,
					"<html>No (<font color=\"red\">discard</font> changes)",
					"<html>Yes (<font color=\"green\">keep</font> changes)",
					OptionDialog.QUESTION_MESSAGE);
		//@formatter:on

		if (choice == OptionDialog.OPTION_TWO) { // Yes
			return true;
		}
		return false;
	}

	@Override
	public void analyzeAll(Program program) {
		if (program == null) {
			throw new IllegalArgumentException("Program may not be null");
		}
		if (getScriptAnalysisMode() == AnalysisMode.ENABLED || program != originalProgram) {
			super.analyzeAll(program);
		}
		else {
			// Will use analysis yield mechanism if running as analysis worker
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.setIgnoreChanges(false);
			try {
				super.analyzeAll(program);
			}
			finally {
				monitor.setProgress(0);
				monitor.setMessage("Executing " + getScriptName());
				mgr.setIgnoreChanges(getScriptAnalysisMode() == AnalysisMode.DISABLED);
			}
		}
	}

	@Override
	public void analyzeChanges(Program program) {
		if (program == null) {
			throw new IllegalArgumentException("Program may not be null");
		}
		if (getScriptAnalysisMode() == AnalysisMode.ENABLED || program != originalProgram) {
			super.analyzeChanges(program);
		}
		else {
			// Will use analysis yield mechanism if running as analysis worker
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.setIgnoreChanges(false);
			try {
				super.analyzeChanges(program);
			}
			finally {
				monitor.setProgress(0);
				monitor.setMessage("Executing " + getScriptName());
				mgr.setIgnoreChanges(getScriptAnalysisMode() == AnalysisMode.DISABLED);
			}
		}
	}

	protected final void updateStateFromVariables() {
		state.setCurrentProgram(currentProgram);

		// weirdness caused by separate local variables for address and location
		// if they diverge, give precedence to the address by calling setLocation first
		state.setCurrentLocation(currentLocation);
		state.setCurrentAddress(currentAddress);
		state.setCurrentAddress(currentAddress);
		state.setCurrentHighlight(currentHighlight);
		state.setCurrentSelection(currentSelection);
	}

	protected final void loadVariablesFromState() {
		this.currentProgram = state.getCurrentProgram();
		this.currentAddress = state.getCurrentAddress();
		this.currentLocation = state.getCurrentLocation();
		this.currentSelection = state.getCurrentSelection();
		this.currentHighlight = state.getCurrentHighlight();
	}

	/**
	 * Returns the state object for this script after first synchronizing its state with its
	 * corresponding convenience variables.
	 * @return the state object
	 */
	public final GhidraState getState() {
		updateStateFromVariables();
		return state;
	}

	/**
	 * Set the script {@link #currentAddress}, {@link #currentLocation}, and update state object.
	 * 
	 * @param address the new address
	 */
	public final void setCurrentLocation(Address address) {
		state.setCurrentAddress(address);
		this.currentAddress = address;
		this.currentLocation = state.getCurrentLocation();
	}

	/**
	 * Set associated source file
	 * @param sourceFile the source file
	 */
	public final void setSourceFile(ResourceFile sourceFile) {
		this.sourceFile = sourceFile;
	}

	/**
	 * Determines the behavior of Auto-Analysis while this script is executed and the manner
	 * in which this script is executed.  If a script overrides this method and returns DISABLED
	 * or SUSPENDED, this script will execute as an AnalysisWorker.  Note that this will only
	 * work reliably when the script is working with the currentProgram only and is not opening
	 * and changing other programs.  If multiple programs will be modified
	 * and auto-analysis should be disabled/suspended, the AutoAnalysisManager.scheduleWorker
	 * method should be used with the appropriate AutoAnalysisManager instance.
	 *
	 * @return the analysis mode associated with this script.
	 * @see AutoAnalysisManager#getAnalysisManager(Program)
	 * @see AutoAnalysisManager#scheduleWorker(AnalysisWorker, Object, boolean, TaskMonitor)
	 * @see AutoAnalysisManager#setIgnoreChanges(boolean)
	 */
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.ENABLED;
	}

	/**
	 * Establishes fixed login credentials for Ghidra Server access.
	 * <p>
	 * NOTE: Only used for Headless environment, other GUI environments should
	 * continue to prompt user for login credentials as needed.
	 *
	 * @param username login name or null if not applicable or to use default name
	 * @param password login password
	 * @return true if active project is either private or shared project is
	 * connected to its server repository.  False is returned if not active
	 * project or an active shared project failed to connect.
	 */
	public final boolean setServerCredentials(String username, String password) {
		if (isRunningHeadless()) {
			// only change client authenticator in headless mode
			ClientUtil.setClientAuthenticator(new PasswordClientAuthenticator(username, password));
		}
		return verifyRepositoryConnection();
	}

	/**
	 * Enable use of anonymous read-only user connection to Ghidra Server in place of
	 * fixed username/password credentials.
	 * <p>
	 * NOTE: Only used for Headless environment, other GUI environments should
	 * continue to prompt user for login credentials as needed.
	 *
	 * @return true if active project is either private or shared project is
	 * connected to its server repository.  False is returned if not active
	 * project or an active shared project failed to connect.
	 */
	public final boolean setAnonymousServerCredentials() {
		if (isRunningHeadless()) {
			// only change client authenticator in headless mode
			try {
				HeadlessClientAuthenticator
					.installHeadlessClientAuthenticator(ClientUtil.getUserName(), null, false);
			}
			catch (IOException e) {
				throw new RuntimeException("Unexpected Exception", e);
			}
		}
		return verifyRepositoryConnection();
	}

	private boolean verifyRepositoryConnection() {
		Project project = state.getProject();
		if (project != null) {
			RepositoryAdapter repository = project.getRepository();
			if (repository != null) {
				try {
					repository.connect();
				}
				catch (IOException e) {
					if ((e instanceof ConnectException) || (e instanceof NotConnectedException)) {
						return false;
					}

					if (isRunningHeadless()) {
						Msg.error(this,
							"Server Connect Error: Server repository connection failed: " +
								repository + ", Exception: " + e.toString());
					}
					else {
						PluginTool tool = state.getTool();
						Msg.showError(this, tool != null ? tool.getActiveWindow() : null,
							"Server Connect Error",
							"Server repository connection failed: " + repository, e);
					}
				}
				return repository.isConnected();
			}
			return true; // private project
		}
		return false; // no active project
	}

	/**
	 * Returns the category for this script.
	 * @return the category for this script
	 */
	public String getCategory() {
		return null;
	}

	/**
	 * Returns the username of the user running the script.
	 * @return the username of the user running the script
	 */
	public String getUserName() {
		return System.getProperty("user.name");
	}

	@Override
	public final String toString() {
		return getScriptName();
	}

	/**
	 * Returns name of script
	 * @return name of script
	 */
	public final String getScriptName() {
		if (sourceFile == null) {
			return getClass().getSimpleName() + ".class";
		}
		return sourceFile.getName();
	}

	/**
	 * Returns the script source file.
	 * @return the script source file
	 */
	public final ResourceFile getSourceFile() {
		return sourceFile;
	}

	/**
	 * Returns the script-specific arguments
	 *
	 * @return The script-specific arguments.  Could be an empty array, but won't be null.
	 */
	public String[] getScriptArgs() {
		return scriptArgs;
	}

	/**
	 * Sets script-specific arguments
	 *
	 * @param scriptArgs The script-specific arguments to use.  For no scripts, use null or an
	 *   empty array.
	 */
	public void setScriptArgs(String[] scriptArgs) {
		this.scriptArgs = scriptArgs != null ? scriptArgs : new String[0];
		this.askScriptArgIndex = 0;
	}

	/**
	 * Gets the next script argument from the script argument array to process.  Designed to be
	 * called by the "ask" methods.
	 *
	 * @return The next script argument from the script argument array.
	 * @throws IndexOutOfBoundsException If there are no more script arguments in the array.
	 */
	private String nextScriptArg() throws IndexOutOfBoundsException {
		if (askScriptArgIndex >= scriptArgs.length) {
			throw new IndexOutOfBoundsException("Script is looking for script argument #" +
				(askScriptArgIndex + 1) + ", but only " + scriptArgs.length + " were passed in.");
		}
		return scriptArgs[askScriptArgIndex++];
	}

	/**
	 * Returns the version of the Ghidra being run.
	 * @return the version of the Ghidra being run
	 */
	public String getGhidraVersion() {
		return Application.getApplicationVersion();
	}

	/**
	 * Returns whether this script is running in a headless (Non GUI) environment.
	 * <p>
	 * This method should not be using GUI type script calls like showAddress()
	 *
	 * @return true if the script is running without a GUI.
	 */
	public final boolean isRunningHeadless() {
		return SystemUtilities.isInHeadlessMode();
	}

	/**
	 * Runs a script by name (allows current state to be changed by script).
	 * <p>
	 * It attempts to locate the script in the directories
	 * defined in <code>GhidraScriptUtil.getScriptDirectories()</code>.
	 * <p>
	 * The script being run uses the same {@link GhidraState} (e.g., script variables) as
	 * this calling script.  Also, any changes to the state by the script being run will be
	 * reflected in this calling script's state.
	 *
	 * @param scriptName the name of the script to run
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws Exception if any exceptions occur while running the script
	 * @see #runScriptPreserveMyState(String)
	 * @see #runScript(String, GhidraState)
	 */
	public final void runScript(String scriptName) throws Exception {
		runScript(scriptName, state);
	}

	/**
	 * Runs a script by name with the provided arguments (allows current state to be changed by
	 * script).
	 * <p>
	 * It attempts to locate the script in the directories
	 * defined in <code>GhidraScriptUtil.getScriptDirectories()</code>.
	 * <p>
	 * The script being run uses the same {@link GhidraState} (e.g., script variables) as
	 * this calling script.  Also, any changes to the state by the script being run will be
	 * reflected in this calling script's state.
	 *
	 * @param scriptName the name of the script to run
	 * @param scriptArguments the arguments to pass to the script
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws Exception if any exceptions occur while running the script
	 * @see #runScriptPreserveMyState(String)
	 * @see #runScript(String, GhidraState)
	 */
	public final void runScript(String scriptName, String[] scriptArguments) throws Exception {
		runScript(scriptName, scriptArguments, state);
	}

	/**
	 * Runs a script by name (does not allow current state to change).
	 * <p>
	 * It attempts to locate the script in the directories
	 * defined in <code>GhidraScriptUtil.getScriptDirectories()</code>.
	 * <p>
	 * The script being run uses the same {@link GhidraState} (e.g., script variables) as
	 * this calling script.  However, any changes to the state by the script being run will NOT
	 * be reflected in this calling script's state.
	 *
	 * @param scriptName the name of the script to run
	 * @return a GhidraState object containing the final state of the run script.
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws Exception if any exceptions occur while running the script
	 * @see #runScript(String)
	 * @see #runScript(String, GhidraState)
	 */
	public final GhidraState runScriptPreserveMyState(String scriptName) throws Exception {
		updateStateFromVariables();
		GhidraState clonedState = new GhidraState(state);
		runScript(scriptName, clonedState);
		return clonedState;
	}

	/**
	 * Runs a script by name using the given state.
	 * <p>
	 * It attempts to locate the script in the directories
	 * defined in <code>GhidraScriptUtil.getScriptDirectories()</code>.
	 * <p>
	 * The script being run uses the given {@link GhidraState} (e.g., script variables)
	 * Any changes to the state by the script being run will be reflected in the given state
	 * object.  If the given object is the current state, the this scripts state may be changed
	 * by the called script.
	 *
	 * @param scriptName the name of the script to run
	 * @param scriptState the Ghidra state
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws Exception if any exceptions occur while running the script
	 * @see #runScriptPreserveMyState(String)
	 * @see #runScript(String)
	 */
	public void runScript(String scriptName, GhidraState scriptState) throws Exception {
		runScript(scriptName, null, scriptState);
	}

	/**
	 * Runs a script by name with the given arguments using the given state.
	 * <p>
	 * It attempts to locate the script in the directories
	 * defined in <code>GhidraScriptUtil.getScriptDirectories()</code>.
	 * <p>
	 * The script being run uses the given {@link GhidraState} (e.g., script variables)
	 * Any changes to the state by the script being run will be reflected in the given state
	 * object.  If the given object is the current state, the this scripts state may be changed
	 * by the called script.
	 *
	 * @param scriptName the name of the script to run
	 * @param scriptArguments the arguments to pass to the script
	 * @param scriptState the Ghidra state
	 * @throws IllegalArgumentException if the script does not exist
	 * @throws Exception if any exceptions occur while running the script
	 * @see #runScriptPreserveMyState(String)
	 * @see #runScript(String)
	 */
	public void runScript(String scriptName, String[] scriptArguments, GhidraState scriptState)
			throws Exception {
		ResourceFile scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
		if (scriptSource != null) {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSource);

			if (provider == null) {
				throw new IOException("Attempting to run subscript '" + scriptName +
					"': unable to run this script type.");
			}

			GhidraScript script = provider.getScriptInstance(scriptSource, writer);
			script.setScriptArgs(scriptArguments);

			if (potentialPropertiesFileLocs.size() > 0) {
				script.setPotentialPropertiesFileLocations(potentialPropertiesFileLocs);
			}

			if (scriptState == state) {
				updateStateFromVariables();
			}

			script.execute(scriptState, monitor, writer);

			if (scriptState == state) {
				loadVariablesFromState();
			}
			return;
		}

		boolean shouldContinue = false;

		if (!isRunningHeadless()) {
			shouldContinue = askYesNo("Script does not exist", //
				getScriptName() + " is attempting to run another script " + "[" + scriptName + "]" +
					" that does not exist or can not be found.\n \n" + // <-- spaces between \n's on purpose
					"You can silently ignore this error, which could lead to bad results (choose Yes)\n" +
					"or allow the calling script to receive the error (choose No).\n \n" + // <-- spaces between \n's on purpose
					"Do you wish to suppress this error?");
		}

		if (!shouldContinue) {
			throw new IllegalArgumentException("Script does not exist: " + scriptName);
		}
	}

	/**
	 * Runs the specified command using the current program.
	 * @param cmd the command to run
	 * @return true if the command successfully ran
	 */
	public final boolean runCommand(Command cmd) {
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Runs the specified background command using the current program.
	 * The command will be given the script task monitor.
	 *
	 * @param cmd the background command to run
	 * @return true if the background command successfully ran
	 */
	public final boolean runCommand(BackgroundCommand cmd) {
		return cmd.applyTo(currentProgram, monitor);
	}

	/**
	 * Returns the default language provider for the specified processor name.
	 *
	 * @param processor the processor
	 * @return the default language provider for the specified processor name
	 * @throws LanguageNotFoundException if no language provider exists for the processor
	 * @see ghidra.program.model.lang.Language
	 */
	public final Language getDefaultLanguage(Processor processor) throws LanguageNotFoundException {
		LanguageService service = DefaultLanguageService.getLanguageService();
		if (service != null) {
			return service.getDefaultLanguage(processor);
		}
		throw new IllegalStateException("LanguageService does not exist in tool!");
	}

	/**
	 * Returns the language provider for the specified language name.
	 *
	 * @param languageID the language name
	 * @return the language provider for the specified language name
	 * @throws LanguageNotFoundException if no language provider exists
	 * @see ghidra.program.model.lang.Language
	 */
	public final Language getLanguage(LanguageID languageID) throws LanguageNotFoundException {
		LanguageService service = DefaultLanguageService.getLanguageService();
		if (service != null) {
			Language language = service.getLanguage(languageID);
			if (language != null) {
				return language;
			}
		}
		throw new IllegalStateException("LanguageService does not exist in tool!");
	}

	/**
	 * Returns a demangled version of the mangled string.
	 *
	 * @param mangled the mangled string to demangled
	 * @return a demangled version of the mangled string
	 */
	public String getDemangled(String mangled) {
		DemangledObject demangledObj = DemanglerUtil.demangle(mangled);
		if (demangledObj != null) {
			return demangledObj.getSignature(false);
		}
		return null;
	}

	/**
	 * Prints a newline.
	 *
	 * @see #printf(String, Object...)
	 */
	public void println() {
		println("");
	}

	/**
	 * Prints the message to the console followed by a line feed.
	 *
	 * @param message the message to print
	 * @see #printf(String, Object...)
	 */
	public void println(String message) {
		String decoratedMessage = getScriptName() + "> " + message;

		// note: use a Message object to facilitate script message log filtering
		Msg.info(GhidraScript.class, new ScriptMessage(decoratedMessage));

		if (isRunningHeadless()) {
			return;
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		ConsoleService console = tool.getService(ConsoleService.class);
		if (console == null) {
			return;
		}

		try {
			console.addMessage(getScriptName(), message);
		}
		catch (Exception e) {
			Msg.error(this, "Script Message: " + message, e);
		}
	}

	/**
	 * A convenience method to print a formatted String using Java's <code>printf</code>
	 * feature, which is similar to that of the C programming language.
	 * For a full description on Java's
	 * <code>printf</code> usage, see {@link java.util.Formatter}.
	 * <p>
	 * For examples, see the included <code>FormatExampleScript</code>.
	 * <p>
	 * <b><u>Note:</u> This method will not:</b>
	 * <ul>
	 * 	<li><b>print out the name of the script, as does {@link #println(String)}</b></li>
	 *  <li><b>print a newline</b></li>
	 * </ul>
	 * If you would like the name of the script to precede you message, then you must add that
	 * yourself.  The {@link #println(String)} does this via the following code:
	 * <pre>
	 *     String messageWithSource = getScriptName() + "&gt; " + message;
	 * </pre>
	 *
	 * @param message the message to format
	 * @param args formatter arguments (see above)
	 *
	 * @see String#format(String, Object...)
	 * @see java.util.Formatter
	 * @see #print(String)
	 * @see #println(String)
	 */
	public void printf(String message, Object... args) {
		String formattedString = String.format(message, args);
		print(formattedString);
	}

	/**
	 * Prints the message to the console - no line feed
	 * <p>
	 * <b><u>Note:</u> This method will not print out the name of the script,
	 * as does {@link #println(String)}
	 * </b>
	 * <p>
	 * If you would like the name of the script to precede you message, then you must add that
	 * yourself.  The {@link #println(String)} does this via the following code:
	 * <pre>
	 *     String messageWithSource = getScriptName() + "&gt; " + message;
	 * </pre>
	 *
	 * @param message the message to print
	 * @see #printf(String, Object...)
	 */
	public void print(String message) {
		// clients using print may add their own newline, which interferes with our logging,
		// so, strip it off
		if (message.endsWith("\r\n")) {
			Msg.info(GhidraScript.class, message.substring(0, message.length() - 2));
		}
		else if (message.endsWith("\n")) {
			Msg.info(GhidraScript.class, message.substring(0, message.length() - 1));
		}
		else {
			Msg.info(GhidraScript.class, message);
		}

		if (isRunningHeadless()) {
			return;
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		ConsoleService console = tool.getService(ConsoleService.class);
		if (console == null) {
			return;
		}

		try {
			console.print(message);
		}
		catch (Exception e) {
			Msg.error(this, "Script Message: " + message, e);
		}
	}

	/**
	 * Prints the error message to the console followed by a line feed.
	 *
	 * @param message the error message to print
	 */
	public void printerr(String message) {
		String msgMessage = getScriptName() + "> " + message;
		Msg.error(GhidraScript.class, msgMessage);

		if (isRunningHeadless()) {
			return;
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		ConsoleService console = tool.getService(ConsoleService.class);
		if (console == null) {
			return;
		}

		try {
			console.addErrorMessage(getScriptName(), message);
		}
		catch (Exception e) {
			Msg.error(this, "Script Message: " + message, e);
		}
	}

	/**
	 * Returns the description of an analysis option name, as provided by the analyzer. This
	 * method returns an empty string if no description is available.
	 *
	 * @param program  the program to get the analysis option description from
	 * @param analysisOption  the analysis option to get the description for
	 * @return the analysis description, or empty String if none has been provided
	 */
	public String getAnalysisOptionDescription(Program program, String analysisOption) {

		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		String description = options.getDescription(analysisOption);

		if (description == null) {
			return "";
		}

		return description;
	}

	/**
	 * Returns descriptions mapping to the given list of analysis option names. This method
	 * returns an empty string for an analysis option if no description is available.
	 *
	 * @param program  the program to get the analysis option description from
	 * @param analysisOptions  the lists of analysis options to get the description for
	 * @return  mapping between each analysis options and its description (description is empty
	 * 			string if none has been provided).
	 */
	public Map<String, String> getAnalysisOptionDescriptions(Program program,
			List<String> analysisOptions) {

		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Map<String, String> optionsToDescriptions = new HashMap<>();

		String description;

		for (String singleOption : analysisOptions) {

			description = options.getDescription(singleOption);

			if (description == null) {
				description = "";
			}

			optionsToDescriptions.put(singleOption, description);
		}

		return optionsToDescriptions;
	}

	/**
	 * Reset all analysis options to their default values.
	 *
	 * @param program  the program for which all analysis options should be reset
	 */
	public void resetAllAnalysisOptions(Program program) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		for (String propertyName : options.getOptionNames()) {
			options.restoreDefaultValue(propertyName);
		}
	}

	/**
	 * Reset one analysis option to its default value.
	 *
	 * @param program  the program for which the specified analysis options should be reset
	 * @param analysisOption  the specified analysis option to reset (invalid options will be
	 * 		  	ignored)
	 */
	public void resetAnalysisOption(Program program, String analysisOption) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.restoreDefaultValue(analysisOption);
	}

	/**
	 * Resets a specified list of analysis options to their default values.
	 *
	 * @param program  the program for which the specific analysis options should be reset
	 * @param analysisOptions  the specified analysis options to reset (invalid options
	 * 			will be ignored)
	 */
	public void resetAnalysisOptions(Program program, List<String> analysisOptions) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		for (String analysisOption : analysisOptions) {
			options.restoreDefaultValue(analysisOption);
		}
	}

	/**
	 * Returns a boolean value representing whether the specified value for the specified
	 * analysis option is actually the default value for that option.
	 *
	 * @param program  the program for which we want to verify the analysis option value
	 * @param analysisOption  the analysis option whose value we want to verify
	 * @param analysisValue  the analysis value to be compared to the option's default value
	 * @return  whether the given value for the given option is default or not
	 */
	public boolean isAnalysisOptionDefaultValue(Program program, String analysisOption,
			String analysisValue) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		Object defaultValue = options.getDefaultValue(analysisOption);
		String defaultValueAsString = defaultValue == null ? null : defaultValue.toString();

		return analysisValue.equals(defaultValueAsString);
	}

	/**
	 * Returns the default value for the given analysis option.  Returns empty string if
	 * invalid option.
	 *
	 * @param program  the program for which we want to retrieve the default value for the
	 * 			given analysis option
	 * @param analysisOption  the analysis option for which we want to retrieve the default value
	 * @return  String representation of default value (returns empty string if analysis option
	 * 			is invalid).
	 */
	public String getAnalysisOptionDefaultValue(Program program, String analysisOption) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		Object defaultValue = options.getDefaultValue(analysisOption);
		String returnVal = defaultValue == null ? null : defaultValue.toString();

		if (returnVal == null) {
			return "";
		}

		return returnVal;
	}

	/**
	 * Returns a mapping of the given analysis options to their default values in String form.
	 * An individual option is mapped to the empty String if the option is invalid.
	 *
	 * @param program  the program for which to retrieve default values for the
	 * 					given analysis options
	 * @param analysisOptions  the analysis options for which to retrieve default values
	 * @return  mapping from analysis options to their default values.  An individual option
	 * 				will be mapped to an empty String if the option is invalid.
	 */
	public Map<String, String> getAnalysisOptionDefaultValues(Program program,
			List<String> analysisOptions) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		Map<String, String> optionsToDefaultValues = new HashMap<>();

		for (String singleOption : analysisOptions) {
			Object defaultValue = options.getDefaultValue(singleOption);
			String defaultValueString = defaultValue == null ? null : defaultValue.toString();

			if (defaultValueString == null) {
				defaultValueString = "";
			}

			optionsToDefaultValues.put(singleOption, defaultValueString);
		}

		return optionsToDefaultValues;
	}

	/**
	 * Gets the given program's ANALYSIS_PROPERTIES and returns a HashMap of the
	 * program's analysis options to current values (values represented as strings).
	 * <p>
	 * The string "(default)" is appended to the value if it represents the
	 * default value for the option it is assigned to.
	 *
	 * @param program  the program to get analysis options from
	 * @return  mapping of analysis options to current settings (represented as strings)
	 */
	public Map<String, String> getCurrentAnalysisOptionsAndValues(Program program) {

		Map<String, String> availableOptions = new HashMap<>();
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		for (String propertyName : options.getOptionNames()) {
			OptionType propertyType = options.getType(propertyName);
			Object propertyValue = null;

			switch (propertyType) {
				case INT_TYPE:
					propertyValue = Integer.valueOf(options.getInt(propertyName, -1));
					break;

				case LONG_TYPE:
					propertyValue = Long.valueOf(options.getLong(propertyName, -1l));
					break;

				case STRING_TYPE:
					propertyValue = options.getString(propertyName, "");
					break;

				case DOUBLE_TYPE:
					propertyValue = Double.valueOf(options.getDouble(propertyName, -1.0d));
					break;

				case BOOLEAN_TYPE:
					propertyValue = Boolean.valueOf(options.getBoolean(propertyName, false));
					break;
				case FLOAT_TYPE:
					propertyValue = Float.valueOf(options.getFloat(propertyName, 0f));
					break;

				case DATE_TYPE:
				case BYTE_ARRAY_TYPE:
				case COLOR_TYPE:
				case CUSTOM_TYPE:
				case FILE_TYPE:
				case FONT_TYPE:
				case KEYSTROKE_TYPE:
					// do nothing; don't allow user to set these options (doesn't make any sense)
					break;

				case NO_TYPE:
					break;
				case ENUM_TYPE:
					propertyValue = options.getObject(propertyName, null);
					break;
				default:
					// Do nothing
			}

			if (propertyValue != null) {
				availableOptions.put(propertyName, propertyValue.toString());
			}
		}

		return availableOptions;
	}

	/**
	 * Allows user to set analysis options by passing a mapping of analysis option to
	 * desired value.  This method does the work of converting the option value to its
	 * actual object type (if needed).
	 *
	 * @param program	the program for which analysis options should be set
	 * @param analysisSettings	a mapping from analysis options to desired new settings
	 */
	public void setAnalysisOptions(Program program, Map<String, String> analysisSettings) {

		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		StringBuffer errorBuffer = new StringBuffer();
		for (String analysisOptionName : analysisSettings.keySet()) {
			String returnString = setAnalysisOption(options, analysisOptionName,
				analysisSettings.get(analysisOptionName));

			if (returnString.length() > 0) {
				errorBuffer.append(returnString);
				errorBuffer.append("\n");
			}
		}

		if (errorBuffer.length() > 0) {
			if (isRunningHeadless()) {
				Msg.error(this, errorBuffer.toString());
			}
			else {
				MultiLineMessageDialog dialog = new MultiLineMessageDialog("Analysis Options",
					"Ghidra encountered error(s) when attempting to set analysis options.",
					errorBuffer.toString(), MultiLineMessageDialog.WARNING_MESSAGE, false);
				DockingWindowManager.showDialog(null, dialog);
			}
		}
	}

	/**
	 * Allows user to set one analysis option by passing in the analysis option to
	 * be changed and the new value of that option. This method does the work of
	 * converting the option value to its actual object type (if needed).
	 *
	 * @param program  the program for which analysis options should be set
	 * @param optionName  the name of the option to be set
	 * @param optionValue  the new value of the option
	 */
	public void setAnalysisOption(Program program, String optionName, String optionValue) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		String errorMsg = setAnalysisOption(options, optionName, optionValue);

		if (errorMsg.length() > 0) {
			if (isRunningHeadless()) {
				Msg.error(this, errorMsg);
			}
			else {
				MultiLineMessageDialog dialog = new MultiLineMessageDialog("Analysis Options",
					"Ghidra encountered error(s) when attempting to set analysis options.",
					errorMsg, MultiLineMessageDialog.WARNING_MESSAGE, false);
				DockingWindowManager.showDialog(null, dialog);
			}
		}
	}

	/**
	 * Private method, returns any error message that may have resulted from attempting to set
	 * the given analysis option to the given analysis value.
	 *
	 * @param options  the options for which analysisOption should be set to
	 * 			analysisOptionValue
	 * @param analysisOption	the option to be changed
	 * @param analysisOptionValue	the value to be set for the option
	 * @return  a String description of any errors that occurred during setting of options; if
	 * 		empty String is returned, no problems occurred.
	 */
	private String setAnalysisOption(Options options, String analysisOption,
			String analysisOptionValue) {

		String changeFailedMessage = "";
		if (analysisOptionValue == null) {
			return changeFailedMessage + " " + analysisOption +
				" Can not set an analyzer option to null value.";
		}

		if (!options.contains(analysisOption)) {
			return changeFailedMessage + analysisOption + " could not be found for this program.";
		}

		OptionType optionType = options.getType(analysisOption);
		try {
			switch (optionType) {

				case INT_TYPE:
					options.setInt(analysisOption, Integer.valueOf(analysisOptionValue));
					break;

				case LONG_TYPE:
					options.setLong(analysisOption, Long.valueOf(analysisOptionValue));
					break;

				case STRING_TYPE:
					options.setString(analysisOption, analysisOptionValue);
					break;

				case DOUBLE_TYPE:

					options.setDouble(analysisOption, Double.valueOf(analysisOptionValue));
					break;
				case FLOAT_TYPE:
					options.setFloat(analysisOption, Float.valueOf(analysisOptionValue));
					break;

				case BOOLEAN_TYPE:
					// Tests if text actually equals "true" or "false
					String tempBool = analysisOptionValue.toLowerCase();

					if ("true".equals(tempBool) || "false".equals(tempBool)) {
						options.setBoolean(analysisOption, Boolean.valueOf(tempBool));
					}

					break;
				case ENUM_TYPE:
					setEnum(options, analysisOption, analysisOptionValue);
					break;
				case KEYSTROKE_TYPE:
				case FONT_TYPE:
				case DATE_TYPE:
				case BYTE_ARRAY_TYPE:
				case COLOR_TYPE:
				case CUSTOM_TYPE:
				case FILE_TYPE:
					changeFailedMessage +=
						"Not allowed to change settings usings strings for type: " + optionType;

				case NO_TYPE:
				default:
					changeFailedMessage += "The option could not be found for this program.";
			}

		}
		catch (NumberFormatException numFormatExc) {
			changeFailedMessage += "Could not convert '" + analysisOptionValue +
				"' to a number of type " + optionType + ".";
		}
		catch (IllegalArgumentException e) {
			changeFailedMessage = "Error changing setting for option '" + analysisOption + "'. ";
		}

		return changeFailedMessage;
	}

	@SuppressWarnings("unchecked")
	private void setEnum(Options options, String analysisOption, String analysisOptionValue) {

		@SuppressWarnings("rawtypes")
		Enum enumm = options.getEnum(analysisOption, null);
		if (enumm == null) {
			throw new IllegalStateException(
				"Attempted to set an Enum option without an " + "existing enum value alreday set.");
		}

		@SuppressWarnings({ "rawtypes" })
		Enum newEnumm = Enum.valueOf(enumm.getClass(), analysisOptionValue);
		if (newEnumm != null) {
			options.setEnum(analysisOption, newEnumm);
		}
	}

	/**
	 * Sets the selection state to the given address set.
	 * <p>
	 * The actual behavior of the method depends on your environment, which can be GUI or
	 * headless:
	 * <ol>
	 * 		<li>In the GUI environment this method will set the {@link #currentSelection}
	 * 			variable to the given value, update the {@link GhidraState}'s selection
	 * 			variable, <b>and</b> will set the Tool's selection to the given value.</li>
	 * 		<li>In the headless environment this method will set the {@link #currentSelection}
	 * 			variable to the given value and update the GhidraState's selection variable.</li>
	 * </ol>
	 * <p>
	 *
	 * @param addressSet the set of addresses to include in the selection.  If this value is null,
	 * the current selection will be cleared and the variables set to null.
	 */
	public void setCurrentSelection(AddressSetView addressSet) {
		if (addressSet == null || addressSet.isEmpty()) {
			this.currentSelection = null;
		}
		else {
			this.currentSelection = new ProgramSelection(addressSet);
		}
		state.setCurrentSelection(currentSelection);
	}

	/**
	 * Calling this method is equivalent to calling {@link #setCurrentSelection(AddressSetView)}.
	 * @param set the addresses
	 */
	public void createSelection(AddressSetView set) {
		setCurrentSelection(set);
	}

	/**
	 * Clears the current selection.  Calling this method is equivalent to calling
	 * {@link #setCurrentSelection(AddressSetView)} with a null or empty AddressSet.
	 */
	public void removeSelection() {
		setCurrentSelection(null);
	}

	/**
	 * Sets the highlight state to the given address set.
	 * <p>
	 * The actual behavior of the method depends on your environment, which can be GUI or
	 * headless:
	 * <ol>
	 * 		<li>In the GUI environment this method will set the {@link #currentHighlight}
	 * 			variable to the given value, update the {@link GhidraState}'s highlight variable,
	 * 			<b>and</b> will set the Tool's highlight to the given value.</li>
	 * 		<li>In the headless environment this method will set the {@link #currentHighlight}
	 * 			variable to	the given value and update the GhidraState's highlight variable.</li>
	 * </ol>
	 * <p>
	 *
	 * @param addressSet the set of addresses to include in the highlight.  If this value is null,
	 * the current highlight will be cleared and the variables set to null.
	 */
	public void setCurrentHighlight(AddressSetView addressSet) {
		if (addressSet == null || addressSet.isEmpty()) {
			this.currentHighlight = null;
		}
		else {
			this.currentHighlight = new ProgramSelection(addressSet);
		}
		state.setCurrentHighlight(currentHighlight);
	}

	/**
	 * Sets this script's highlight state (both the local variable
	 * <code>currentHighlight</code> and the
	 * <code>GhidraState</code>'s currentHighlight) to the given address set.  Also sets the tool's highlight
	 * if the tool exists. (Same as calling setCurrentHightlight(set);
	 * @param set the set of addresses to include in the highlight.  May be null.
	 */
	public void createHighlight(AddressSetView set) {
		setCurrentHighlight(set);
	}

	/**
	 * Clears the current highlight. Sets this script's highlight state (both the local variable
	 * currentHighlight and the ghidraState's currentHighlight) to null.  Also clears the tool's
	 * highlight if the tool exists.
	 */
	public void removeHighlight() {
		createHighlight(createAddressSet());
	}

	/**
	 * Sets the background of the Listing at the given address to the given color.  See the
	 * Listing help page in Ghidra help for more information.
	 * <p>
	 * This method is unavailable in headless mode.
	 * <p>
	 * Note: you can use the {@link ColorizingService} directly to access more color changing
	 * functionality.  See the source code of this method to learn how to access services from
	 * a script.
	 *
	 * @param address The address at which to set the color
	 * @param color The color to set
	 * @see #setBackgroundColor(AddressSetView, Color)
	 * @see #clearBackgroundColor(Address)
	 * @see ColorizingService
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void setBackgroundColor(Address address, Color color) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The setBackgroundColor() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			printerr("Cannot set background colors without the " +
				ColorizingService.class.getSimpleName() + " installed");
			return;
		}

		service.setBackgroundColor(address, address, color);
	}

	/**
	 * Sets the background of the Listing at the given addresses to the given color.  See the
	 * Listing help page in Ghidra help for more information.
	 * <p>
	 * This method is unavailable in headless mode.
	 * <p>
	 * Note: you can use the {@link ColorizingService} directly to access more color changing
	 * functionality.  See the source code of this method to learn how to access services from
	 * a script.
	 *
	 * @param addresses The addresses at which to set the color
	 * @param color The color to set
	 * @see #setBackgroundColor(Address, Color)
	 * @see #clearBackgroundColor(AddressSetView)
	 * @see ColorizingService
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void setBackgroundColor(AddressSetView addresses, Color color)
			throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The setBackgroundColor() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			printerr("Cannot set background colors without the " +
				ColorizingService.class.getSimpleName() + " installed");
			return;
		}

		service.setBackgroundColor(addresses, color);
	}

	/**
	 * Clears the background of the Listing at the given address to the given color.  See the
	 * Listing help page in Ghidra help for more information.
	 * <p>
	 * This method is unavailable in headless mode.
	 * <p>
	 * Note: you can use the {@link ColorizingService} directly to access more color changing
	 * functionality.  See the source code of this method to learn how to access services from
	 * a script.
	 *
	 * @param address The address at which to clear the color
	 * @see #setBackgroundColor(AddressSetView, Color)
	 * @see #clearBackgroundColor(AddressSetView)
	 * @see ColorizingService
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void clearBackgroundColor(Address address) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The clearBackgroundColor() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			printerr("Cannot clear background colors without the " +
				ColorizingService.class.getSimpleName() + " installed");
			return;
		}

		service.clearBackgroundColor(address, address);
	}

	/**
	 * Clears the background of the Listing at the given addresses to the given color.  See the
	 * Listing help page in Ghidra help for more information.
	 * <p>
	 * This method is unavailable in headless mode.
	 * <p>
	 * Note: you can use the {@link ColorizingService} directly to access more color changing
	 * functionality.  See the source code of this method to learn how to access services from
	 * a script.
	 *
	 * @param addresses The address at which to clear the color
	 * @see #setBackgroundColor(AddressSetView, Color)
	 * @see #clearBackgroundColor(AddressSetView)
	 * @see ColorizingService
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void clearBackgroundColor(AddressSetView addresses) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The clearBackgroundColor() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			printerr("Cannot clear background colors without the " +
				ColorizingService.class.getSimpleName() + " installed");
			return;
		}

		service.clearBackgroundColor(addresses);
	}

	/**
	 * Creates a TableChooserDialog that allows the script to display a list of addresses (and
	 * associated column data) in a table and also provides the capability to execute an
	 * action from a selection in the table.
	 * <p>
	 * This method is unavailable in headless mode.
	 * 
	 * @param title the title of the dialog
	 * @param executor the TableChooserExecuter to be used to apply operations on table entries.
	 * @return a new TableChooserDialog.
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public TableChooserDialog createTableChooserDialog(String title, TableChooserExecutor executor)
			throws ImproperUseException {

		return createTableChooserDialog(title, executor, false);
	}

	/**
	 * Creates a TableChooserDialog that allows the script to display a list of addresses (and
	 * associated column data) in a table and also provides the capability to execute an
	 * action from a selection in the table.
	 * <p>
	 * This method is unavailable in headless mode.
	 * 
	 * @param title of the dialog
	 * @param executor the TableChooserExecuter to be used to apply operations on table entries.
	 * @param isModal indicates whether the dialog should be modal or not
	 * @return a new TableChooserDialog.
	 *
	 * @throws ImproperUseException if this method is run in headless mode; if this script is
	 *                              run directly via Java or another script where the state does
	 *                              not include a tool.
	 */
	public TableChooserDialog createTableChooserDialog(String title, TableChooserExecutor executor,
			boolean isModal) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The createTableChooserDialog() method can only be run within a headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			throw new ImproperUseException(
				"The createTableChooserDialog() method can only be run within a headed Ghidra.");
		}

		Program program = state.getCurrentProgram();
		TableService service = tool.getService(TableService.class);
		return service.createTableChooserDialog(executor, program, title, null, isModal);
	}

	/**
	 * Returns the code unit format established for the code browser listing
	 * or a default format if no tool (e.g., headless).
	 * <p>
	 * This format object may be used to format any code unit (instruction/data) using
	 * the same option settings.
	 *
	 *  @return code unit format when in GUI mode, default format in headless
	 */
	public CodeUnitFormat getCodeUnitFormat() {
		PluginTool tool = state.getTool();
		if (cuFormat == null) {
			if (tool != null) {
				cuFormat = new BrowserCodeUnitFormat(state.getTool());
			}
			else {
				cuFormat = new CodeUnitFormat(ShowBlockName.NEVER, ShowNamespace.NON_LOCAL);
			}
		}
		return cuFormat;
	}

	/**
	 * Displays a popup dialog with the specified message. The dialog title
	 * will be the name of this script.
	 * <p>
	 * In headless mode, the message is displayed in the log output.
	 *
	 * @param message the message to display in the dialog
	 */
	public void popup(final String message) {

		if (isRunningHeadless()) {
			Msg.info(this, message);
		}
		else {

			final String name = getClass().getName();
			if (SwingUtilities.isEventDispatchThread()) {
				Msg.showInfo(getClass(), null, name, message);
			}
			else {
				try {
					SwingUtilities
						.invokeAndWait(() -> Msg.showInfo(getClass(), null, name, message));
				}
				catch (InterruptedException e) {
					// shouldn't happen
				}
				catch (InvocationTargetException e) {
					// shouldn't happen
				}
			}
		}
	}

	/**
	 * Returns a concatenation of the input strings.
	 * <p>
	 * This is helper code for the askXxx() methods -- it concatenates string
	 * parameters together, separated by spaces, to form the string that is
	 * used to look up variables in .properties files.
	 *
	 * @param input  one or more Strings to be concatenated
	 * @return  a String representing the space-separated, concatenated input strings
	 */
	private String join(String... input) {

		char separator = ' ';
		StringBuilder buffy = new StringBuilder("");
		for (String s : input) {
			if (s == null) {
				continue;
			}
			buffy.append(s.trim()).append(separator);
		}

		String newString = buffy.toString();
		return newString.trim();
	}

	/**
	 * Helper code for the askXxx() methods. Takes a string and attempts to separate it into multiple
	 * strings (only if the string is surrounded by double quotes with values separated by ';').
	 *
	 * @param s  input string
	 * @return  array of output strings
	 */
	private List<String> getValues(String s) {
		if (s.charAt(0) == '\"' && s.charAt(s.length() - 1) == '\"') {
			String unquoted = s.substring(1, s.length() - 1);
			return Arrays.asList(unquoted.split(";"));
		}
		return Arrays.asList(s);
	}

	/**
	 * Parses a file from a string.
	 *
	 * @param s The string to parse.
	 * @return The file that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid file.
	 */
	public File parseFile(String s) {
		File f = new File(s);
		if (!f.isFile()) {
			throw new IllegalArgumentException("Invalid file: " + f);
		}
		return f;
	}

	/**
	 * Attempts to locate a value from script arguments
	 *  or a script properties file using
	 * the given <code>keys</code> as the lookup key for the latter.  The given <code>parser</code> will
	 * be called to turn the String into a <code>T</code>.
	 *
	 * @param transformer the function to turn a String into a T
	 * @param key the values used to create a key for lookup in the script properties file
	 * @return null if no value was found in the aforementioned sources
	 */
	private <T> T loadAskValue(StringTransformer<T> transformer, String key) {
		T value = loadAskValue(null, transformer, key);
		return value;
	}

	/**
	 * This version of {@link #loadAskValue(StringTransformer, String)} will use
	 * the given default, if not null and not empty, instead of failing when a value is not
	 * provided by the client when in headless.
	 *
	 * @param defaultValue an optional default value that will be used if no suitable
	 *                     value can be found in script args or a properties file
	 * @param transformer the function to turn a String into a T
	 * @param key the values used to create a key for lookup in the script properties file
	 * @return null if no value was found in the aforementioned sources
	 *
	 * @throws IllegalArgumentException if the loaded String value cannot be parsed into a
	 *                                  <code>T</code>.
	 */
	private <T> T loadAskValue(T defaultValue, StringTransformer<T> transformer, String key) {

		boolean isHeadless = isRunningHeadless();
		if (isHeadless && scriptArgs.length > 0) {
			// this will throw IllegalArgumenrException if the args cannot be parsed
			return transformer.apply(nextScriptArg());
		}

		boolean hasDefault = !isBlank(defaultValue);

		String propertyKey = key;
		if (propertiesFileParams == null) {

			if (isHeadless && !hasDefault) { // require either a props file or a default value
				throw new IllegalArgumentException("Error processing variable '" + propertyKey +
					"' in headless mode -- it was not found in a .properties file.");
			}
			return defaultValue; // may be null
		}

		String storedValue = propertiesFileParams.getValue(propertyKey);
		if (storedValue.isEmpty()) {

			if (isHeadless && !hasDefault) { // require either a props file or a default value
				throw new IllegalArgumentException("Error processing variable '" + propertyKey +
					"' in headless mode -- it was not found in a .properties file.");
			}
			return defaultValue;
		}

		try {
			T t = transformer.apply(storedValue);
			return t;
		}
		catch (IllegalArgumentException e) {
			// handled below
		}

		if (isHeadless) {
			throw new IllegalArgumentException("Error processing variable '" + propertyKey +
				"' in headless mode -- its value '" + storedValue + "' is not a valid value.");
		}

		Msg.warn(this, "Failed to parse script properties value '" + key + "' from file " +
			propertiesFileParams.getFilename());
		return null;
	}

	/**
	 * A generic method to execute user prompting for a value.  This method handles:
	 * <ol>
	 * 	<li>Checking for a previously chosen value; using the optional <code>defaultValue</code> as a fallback</li>
	 * 	<li>Calling the provided function to execute the client-specific ask UI</li>
	 * 	<li>Storing the chosen result after the dialog is closed</li>
	 * </ol>
	 *
	 * @param clazz the type of the object for which the client is asking
	 * @param key1 - the first key used to store/lookup chosen values (aka, 'title')
	 * @param key2 - the second key used to store/lookup chosen values (aka, 'message'/'approveButtonText')
	 * @param defaultValue - an optional value to be used as the pre-seed value in the 'asker'
	 *                       callback.  This value will be passed if no previous value is found
	 * @param asker - a function that will be called with the seed value derived from a previous
	 *                choice and the given default value.
	 *                This function is one in which you can throw a {@link CancelledException}
	 * @return the user's choice
	 *
	 * @throws CancelledException if the user cancels the ask operation
	 */
	@SuppressWarnings("unchecked")
	private <T> T doAsk(Class<?> clazz, String key1, String key2, T defaultValue,
			CancellableFunction<T, T> asker) throws CancelledException {

		Map<Class<?>, Object> map = getScriptMap(key1, key2);

		T mappedValue = null;
		if (clazz != null) {
			mappedValue = (T) map.get(clazz);
		}

		T lastValue = (mappedValue != null) ? mappedValue : defaultValue;

		T newValue = asker.apply(lastValue); // may be cancelled

		map.put(clazz, newValue);
		return newValue;
	}

	private interface CancellableFunction<T, R> {
		R apply(T t) throws CancelledException;
	}

	/**
	 * Returns a File object, using the String parameters for guidance.  The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + approveButtonText).
	 * If that property name exists and its value represents a valid <b>absolute path</b> of a valid
	 * File, then the .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a file chooser dialog that allows the
	 * 			user to select a file. If the file chooser dialog has been run before in the same
	 * 			session, the File selection will be pre-populated with the last-selected file. If
	 * 			not, the File selection will be pre-populated with the .properties value (if it
	 * 			exists).
	 * 		</li>
	 *		<li>In the headless environment, this method returns a File object representing	the
	 *			.properties	String value (if it exists), or throws an Exception if there is an
	 *			invalid or missing .properties value.
	 *		</li>
	 * </ol>
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using using .properties file)
	 * @param approveButtonText the approve button text (in GUI mode - typically, this would
	 * 		  	be "Open" or "Save") or the second part of the variable name (in headless mode
	 * 			or when using .properties file)
	 * @return the selected file or null if no tool was available
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid file
	 * 			name specified in the .properties file
	 */
	public File askFile(final String title, final String approveButtonText)
			throws CancelledException {

		String key = join(title, approveButtonText);
		File existingValue = loadAskValue(this::parseFile, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		File choice = doAsk(File.class, title, approveButtonText, existingValue, lastValue -> {

			GhidraFileChooser chooser = new GhidraFileChooser(null);
			AtomicReference<File> ref = new AtomicReference<>();

			Runnable r = () -> {
				chooser.setSelectedFile(lastValue);
				chooser.setTitle(title);
				chooser.setApproveButtonText(approveButtonText);
				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				ref.set(chooser.getSelectedFile());
			};
			Swing.runNow(r);

			if (chooser.wasCancelled()) {
				throw new CancelledException();
			}

			return ref.get();
		});

		return choice;
	}

	/**
	 * Parses a directory from a string.
	 *
	 * @param val The string to parse.
	 * @return The directory that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid directory.
	 */
	public File parseDirectory(String val) {
		File dir = new File(val);
		if (!dir.isDirectory()) {
			throw new IllegalArgumentException("Invalid directory: " + dir);
		}
		return dir;
	}

	/**
	 * Returns a directory File object, using the String parameters for guidance. The actual
	 * behavior of the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + approveButtonText).
	 * If that property name exists and its value represents a valid <b>absolute path</b> of a valid
	 * directory File, then the .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a file chooser dialog that allows the
	 * 			user to select a directory. If the file chooser dialog has been run before in the
	 * 			same session, the directory selection will be pre-populated with the last-selected
	 * 			directory. If not, the directory selection will be pre-populated with the
	 * 			.properties	value (if it exists).</li>
	 *		<li>In the headless environment, this method returns a directory File representing
	 *			the .properties value (if it exists), or throws an Exception if there is an invalid
	 *			or missing .properties value.</li>
	 * </ol>
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param approveButtonText the approve button text (in GUI mode - typically, this would be
	 * 			"Open" or "Save") or the second part of the variable name (in headless mode or
	 * 			when using .properties file)
	 * @return the selected directory or null if no tool was available
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid
	 * 				directory name specified in the .properties file
	 */
	public File askDirectory(final String title, final String approveButtonText)
			throws CancelledException {

		String key = join(title, approveButtonText);
		File existingValue = loadAskValue(this::parseDirectory, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		File choice = doAsk(DIRECTORY.class, title, approveButtonText, existingValue, lastValue -> {

			GhidraFileChooser chooser = new GhidraFileChooser(null);
			AtomicReference<File> ref = new AtomicReference<>();

			Runnable r = () -> {
				chooser.setSelectedFile(lastValue);
				chooser.setTitle(title);
				chooser.setApproveButtonText(approveButtonText);
				chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
				ref.set(chooser.getSelectedFile());
			};
			Swing.runNow(r);

			if (chooser.wasCancelled()) {
				throw new CancelledException();
			}

			return ref.get();
		});

		return choice;
	}

	/**
	 * Parses a LanguageCompilerSpecPair from a string.
	 *
	 * @param val The string to parse.
	 * @return The directory that was parsed from the LanguageCompilerSpecPair.
	 * @throws IllegalArgumentException if the parsed value is not a valid LanguageCompilerSpecPair.
	 */
	public LanguageCompilerSpecPair parseLanguageCompileSpecPair(String val) {

		if (val.isEmpty()) {
			throw new IllegalArgumentException("No LanguageCompilerSpecPair specified");
		}

		Set<LanguageCompilerSpecPair> allPairs = new HashSet<>();
		List<LanguageDescription> languageDescriptions =
			DefaultLanguageService.getLanguageService().getLanguageDescriptions(false);
		if (languageDescriptions != null) {
			for (LanguageDescription description : languageDescriptions) {
				Collection<CompilerSpecDescription> csDescriptions =
					description.getCompatibleCompilerSpecDescriptions();
				if (csDescriptions != null) {
					for (CompilerSpecDescription csDescription : csDescriptions) {
						allPairs.add(new LanguageCompilerSpecPair(description.getLanguageID(),
							csDescription.getCompilerSpecID()));
					}
				}
			}
		}

		// Split on last colon to get separated languageID and compilerSpecID
		int lastColon = val.lastIndexOf(':');
		String storedLangID = val.substring(0, lastColon);
		String storedCompilerSpecID = val.substring(lastColon + 1);
		LanguageCompilerSpecPair storedLCS =
			new LanguageCompilerSpecPair(storedLangID, storedCompilerSpecID);
		if (allPairs.contains(storedLCS)) {
			return storedLCS;
		}
		throw new IllegalArgumentException("Invalid LanguageCompilerSpecPair: " + val);
	}

	/**
	 * Returns a LanguageCompilerSpecPair, using the String parameters for guidance. The actual
	 * behavior of the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid LanguageCompilerSpecPair value,
	 * then the .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a language table dialog and returns
	 * 			the selected language. If the same popup has been run before in the same session,
	 * 			the last-used language will be pre-selected. If not, the language specified in the
	 * 			.properties file will be pre-selected (if it exists).</li>
	 *		<li>In the headless environment, this method returns a LanguageCompilerSpecPair
	 *			representing the .properties value (if it exists), or throws an Exception if there
	 *			is an invalid or missing .properties value.</li>
	 * </ol>
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param approveButtonText the approve button text (in GUI mode - typically, this would be
	 * 			"Open" or "Save") or the second part of the variable name (in headless mode or
	 * 			when using .properties file)
	 * @return the selected LanguageCompilerSpecPair
	 * @throws CancelledException if the user hit the 'cancel' button
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	language
	 * 			specified in the .properties file
	 */
	public LanguageCompilerSpecPair askLanguage(String title, String approveButtonText)
			throws CancelledException {

		String key = join(title, approveButtonText);
		LanguageCompilerSpecPair existingValue =
			loadAskValue(this::parseLanguageCompileSpecPair, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Class<LanguageCompilerSpecPair> clazz = LanguageCompilerSpecPair.class;
		LanguageCompilerSpecPair choice =
			doAsk(clazz, title, approveButtonText, existingValue, lastValue -> {

				SelectLanguageDialog dialog = new SelectLanguageDialog(title, approveButtonText);
				AtomicReference<LanguageCompilerSpecPair> ref = new AtomicReference<>();

				Runnable r = () -> {
					dialog.setSelectedLanguage(lastValue);
					ref.set(dialog.getSelectedLanguage());
				};
				Swing.runNow(r);

				if (dialog.wasCancelled()) {
					throw new CancelledException();
				}

				return ref.get();
			});

		return choice;
	}

	/**
	 * Parses a ProjectFolder from a string.
	 *
	 * @param val The string to parse.
	 * @return The ProjectFolder that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid ProjectFolder.
	 */
	public DomainFolder parseProjectFolder(String val) {
		// Add the slash to make it an absolute path
		if (!val.isEmpty() && val.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			val = FileSystem.SEPARATOR_CHAR + val;
		}

		DomainFolder df = state.getProject().getProjectData().getFolder(val);
		if (df != null) {
			return df;
		}
		throw new IllegalArgumentException("Invalid DomainFolder: " + val);
	}

	/**
	 * Returns a DomainFolder object, using the supplied title string for guidance.  The actual
	 * behavior of the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is the
	 * title String parameter.  If that property name exists and its value represents a valid
	 * project folder, then the .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a file chooser dialog that allows the
	 * 			user to select a project folder. The selected folder will be returned.</li>
	 *		<li>In the headless environment, if a .properties file sharing the same base name as the
	 *			Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
	 *			looks there for the name of the project folder to return. The method will look in
	 *			the .properties	file by searching for a property name equal to the 'title' parameter.
	 *			If that property name exists and its value represents a valid DomainFolder in the
	 *			project, then that value is returned. Otherwise, an Exception is thrown if there is
	 *			an invalid or missing .properties value.</li>
	 * </ol>
	 *
	 * @param title the title of the dialog (GUI) or the variable name	(headless or when
	 * 			using .properties file)
	 * @return the selected project folder or null if there was an invalid .properties value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	project
	 * 			folder specified in the .properties file
	 */
	public DomainFolder askProjectFolder(final String title) throws CancelledException {

		DomainFolder existingValue = loadAskValue(this::parseProjectFolder, title);
		if (isRunningHeadless()) {
			return existingValue;
		}

		DomainFolder choice = doAsk(Program.class, title, "", existingValue, lastValue -> {

			DataTreeDialog dtd = new DataTreeDialog(null, title, DataTreeDialog.CHOOSE_FOLDER);
			AtomicReference<DomainFolder> ref = new AtomicReference<>();

			dtd.addOkActionListener(e -> {
				ref.set(dtd.getDomainFolder());
				dtd.close();
			});

			Runnable r = () -> dtd.showComponent();
			Swing.runNow(r);

			if (dtd.wasCancelled()) {
				throw new CancelledException();
			}

			return ref.get();
		});

		return choice;
	}

	/**
	 * Parses an integer from a string.
	 *
	 * @param val The string to parse.
	 * @return The integer that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid integer.
	 */
	public int parseInt(String val) {
		try {
			return Integer.decode(val);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid integer: " + val);
		}
	}

	/**
	 * Returns an int, using the String parameters for guidance.  The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid int value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			for an int value. If the same popup has been run before in the same session, the int
	 * 			input field will be pre-populated with the last-used int. If not, the int input
	 * 			field will be pre-populated with the .properties value (if it exists).
	 *  	</li>
	 *		<li>In the headless environment, this method returns an int value representing the
	 *			.properties value (if it exists), or throws an Exception if there is an invalid
	 *			or missing .properties value.
	 *		</li>
	 * </ol>
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @return the user-specified int value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid int
	 * 			specified in the .properties file
	 */
	public int askInt(String title, String message) throws CancelledException {

		String key = join(title, message);
		Integer existingValue = loadAskValue(this::parseInt, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Integer choice = doAsk(Integer.class, title, message, existingValue, lastValue -> {

			AskDialog<Integer> dialog = new AskDialog<>(title, message, AskDialog.INT, lastValue);
			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			Integer newValue = dialog.getValueAsInt();
			return newValue;
		});

		if (choice == null) {
			return 0; // prevent autoboxing NullPointerException
		}
		return choice;
	}

	/**
	 * Parses a long from a string.
	 *
	 * @param val The string to parse.
	 * @return The long that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid long.
	 */
	public long parseLong(String val) {
		try {
			return Long.decode(val);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid long: " + val);
		}
	}

	/** A simple placeholder function that returns the string passed to it. */
	private String stringIdentity(String s) {
		return s;
	}

	/**
	 * Returns a long, using the String parameters for guidance.  The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid long value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			for a long value. If the same popup has been run before in the same session, the
	 * 			long input field will be pre-populated with the last-used long. If not, the long
	 * 			input field will be pre-populated with the .properties value (if it exists).
	 * 		</li>
	 *		<li>In the headless environment, this method returns a long value representing the
	 *			.properties value (if it exists), or throws an Exception if there is an invalid or
	 *			missing .properties	value.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the second
	 * 			part of the	variable name (in headless mode or when using .properties file)
	 * @return the user-specified long value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	long
	 * 			specified in the .properties file
	 */
	public long askLong(String title, String message) throws CancelledException {

		String key = join(title, message);
		Long existingValue = loadAskValue(this::parseLong, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Long choice = doAsk(Long.class, title, message, existingValue, lastValue -> {

			AskDialog<Long> dialog = new AskDialog<>(title, message, AskDialog.LONG, lastValue);
			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			return dialog.getValueAsLong();
		});

		if (choice == null) {
			return 0; // prevent auto-boxing NullPointerException
		}
		return choice;
	}

	/**
	 * Parses an address from a string.
	 *
	 * @param val The string to parse.
	 * @return The address that was parsed from the string.
	 * @throws IllegalArgumentException if there was a problem parsing an address from the string.
	 */
	public Address parseAddress(String val) {
		Address addr = currentProgram.getAddressFactory().getAddress(val);
		if (addr == null) {
			throw new IllegalArgumentException("Invalid address " + val);
		}
		return addr;
	}

	/**
	 * Returns an Address, using the String parameters for guidance.  The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid Address value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			for an address value. If the same popup has been run before in the same session,
	 * 			the address input field will be pre-populated with the last-used address. If not,
	 * 			the	address input field will be pre-populated with the .properties value (if it
	 * 			exists).</li>
	 *		<li>In the headless environment, this method returns an Address representing the
	 *			.properties value (if it exists), or throws an Exception if there is an invalid or
	 *			missing .properties value.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the
	 * 			second part of the variable name (in headless mode or when using .properties file)
	 * @return the user-specified Address value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or	invalid Address
	 * 			specified in the .properties file
	 */
	public Address askAddress(String title, String message) throws CancelledException {

		String key = join(title, message);
		Address existingValue = loadAskValue(this::parseAddress, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Address choice = doAsk(Integer.class, title, message, existingValue, lastValue -> {

			AskAddrDialog dialog =
				new AskAddrDialog(title, message, currentProgram.getAddressFactory(), lastValue);
			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			Address addr = dialog.getValueAsAddress();
			return addr;
		});

		return choice;
	}

	/**
	 * Parses bytes from a string.
	 *
	 * @param val The string to parse.
	 * @return The bytes that were parsed from the string.
	 * @throws IllegalArgumentException if there was a problem parsing bytes from the string.
	 */
	public byte[] parseBytes(String val) {

		try {
			return NumericUtilities.convertStringToBytes(val);
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Invalid bytes: " + val);
		}
	}

	/**
	 * Returns a byte array, using the String parameters for guidance. The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents valid bytes, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the
	 * 			user for a byte pattern. If the same popup has been run before in the same session,
	 * 			the byte pattern input field will be pre-populated with	the last-used bytes string.
	 * 			If not, the byte pattern input field will be pre-populated with the .properties
	 * 			value (if it exists).</li>
	 *		<li>In the headless environment, this method returns a byte array representing the
	 *			.properties byte pattern value (if it exists), or throws an Exception if there is
	 *			an invalid or missing .properties value.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable
	 * 			name (in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the
	 * 			second part of the variable name (in headless mode or when using .properties file)
	 * @return the user-specified byte array
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid bytes
	 * 			string specified in the .properties file
	 */
	public byte[] askBytes(String title, String message) throws CancelledException {

		String key = join(title, message);
		byte[] existingValue = loadAskValue(this::parseBytes, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		byte[] choice = doAsk(byte[].class, title, message, existingValue, lastValue -> {

			String lastByteString = NumericUtilities.convertBytesToString(lastValue, " ");
			AskDialog<Byte> dialog =
				new AskDialog<>(title, message, AskDialog.BYTES, lastByteString);
			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			String bytesString = dialog.getValueAsString();
			byte[] bytes = NumericUtilities.convertStringToBytes(bytesString);
			return bytes;
		});

		return choice;
	}

	/**
	 * Returns a Program, using the title parameter for guidance. The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <br>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is the
	 * title String parameter.  If that property name exists and its value represents a valid
	 * program, then the .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			to select a program.</li>
	 *		<li>In the headless environment, if a .properties file sharing the same base name as the
	 *			Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
	 *			looks there for the name of the program to return. The method will look in the
	 *			.properties file by searching for a property name equal to the 'title' parameter. If
	 *			that property name exists and its value represents a valid Program in the project,
	 *			then that value	is returned. Otherwise, an Exception is thrown if there is an
	 *			invalid or missing .properties value.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the pop-up dialog (in GUI mode) or the variable name (in
	 * 			headless mode)
	 * @return the user-specified Program
	 * @throws VersionException if the Program is out-of-date from the version of GHIDRA
	 * @throws IOException if there is an error accessing the Program's DomainObject
	 * @throws CancelledException if the operation is cancelled
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	program
	 * 			specified in the .properties file
	 */
	public Program askProgram(String title)
			throws VersionException, IOException, CancelledException {

		DomainFile existingValue = loadAskValue(this::parseDomainFile, title);
		if (isRunningHeadless()) {
			return (Program) existingValue.getDomainObject(this, false, false, monitor);
		}

		DomainFile choice = doAsk(Program.class, title, "", existingValue, lastValue -> {

			DataTreeDialog dtd = new DataTreeDialog(null, title, DataTreeDialog.OPEN);
			AtomicReference<DomainFile> ref = new AtomicReference<>();

			dtd.addOkActionListener(e -> {
				ref.set(dtd.getDomainFile());
				dtd.close();
			});

			Runnable r = () -> dtd.showComponent();
			Swing.runNow(r);

			if (dtd.wasCancelled()) {
				throw new CancelledException();
			}

			return ref.get();
		});

		if (choice == null) {
			return null;
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			return (Program) choice.getDomainObject(this, false, false, monitor);
		}

		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm.openProgram(choice);
	}

	/**
	 * Parses a DomainFile from a string.
	 *
	 * @param val The string to parse.
	 * @return The DomainFile that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid DomainFile.
	 */
	public DomainFile parseDomainFile(String val) {
		// Add the slash to make it an absolute path
		if (!val.isEmpty() && val.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			val = FileSystem.SEPARATOR_CHAR + val;
		}

		DomainFile df = state.getProject().getProjectData().getFile(val);
		if (df != null) {
			return df;
		}
		throw new IllegalArgumentException("Invalid DomainFile: " + val);
	}

	/**
	 * Returns a DomainFile, using the title parameter for guidance.  The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is the
	 * title String parameter.  If that property name exists and its value represents a valid
	 * domain file, then the .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog listing all domain files
	 * 			in the current project, allowing the user to select one.</li>
	 *		<li>In the headless environment, if a .properties file sharing the same base name as the
	 *			Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
	 *			looks there for the name of the DomainFile to return. The method will look in the
	 *			.properties file by searching for a property name equal to the 'title' parameter. If
	 *			that property name exists and its value represents a valid DomainFile in the project,
	 *			then that value is returned. Otherwise, an Exception is thrown if there is an invalid
	 *			or missing .properties value.</li>
	 * </ol>
	 * 
	 * @param title the title of the pop-up dialog (in GUI mode) or the variable name (in headless
	 * 		mode or when using .properties file)
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	domain
	 * 			file specified in the .properties file
	 * @return the user-selected domain file
	 * @throws CancelledException if the operation is cancelled
	 */
	public DomainFile askDomainFile(String title) throws CancelledException {

		DomainFile existingValue = loadAskValue(this::parseDomainFile, title);
		if (isRunningHeadless()) {
			return existingValue;
		}

		String message = "";
		DomainFile choice = doAsk(DomainFile.class, title, message, existingValue, lastValue -> {

			DataTreeDialog dtd = new DataTreeDialog(null, title, DataTreeDialog.OPEN);
			AtomicReference<DomainFile> ref = new AtomicReference<>();

			dtd.addOkActionListener(e -> {
				ref.set(dtd.getDomainFile());
				dtd.close();
			});

			Runnable r = () -> dtd.showComponent();
			Swing.runNow(r);

			if (dtd.wasCancelled()) {
				throw new CancelledException();
			}

			return ref.get();
		});

		return choice;
	}

	/**
	 * Parses a double from a string.
	 *
	 * @param val The string to parse.
	 * @return The double that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid double.
	 */
	public double parseDouble(String val) {
		if ("pi".equalsIgnoreCase(val)) {
			return Math.PI;
		}
		if ("e".equalsIgnoreCase(val)) {
			return Math.E;
		}
		try {
			return Double.valueOf(val);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid double: " + val);
		}
	}

	/**
	 * Returns a double, using the String parameters for guidance. The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid double value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			for a double value. If the same popup has been run before in the same session, the
	 * 			double input field will be pre-populated with the last-used double. If not, the
	 * 			double input field will be pre-populated with the .properties value (if it exists).
	 * 		</li>
	 *		<li>In the headless environment, this method returns a double value representing the
	 *			.properties value (if it exists), or throws an Exception if there is an	invalid or
	 *			missing .properties value.</li>
	 * </ol>
	 * <p>
	 * Note that in both headless and GUI modes, you may specify "PI" or "E" and get the
	 * corresponding floating point value to 15 decimal places.
	 * <p>
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @return the user-specified double value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or	invalid double
	 * 			specified in the .properties file
	 */
	public double askDouble(String title, String message) throws CancelledException {

		String key = join(title, message);
		Double existingValue = loadAskValue(this::parseDouble, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Double choice = doAsk(Double.class, title, message, existingValue, lastValue -> {

			AskDialog<Double> dialog = new AskDialog<>(title, message, AskDialog.DOUBLE, lastValue);
			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			return dialog.getValueAsDouble();
		});

		if (choice == null) {
			return 0D; // prevent autoboxing NullPointerException
		}

		return choice;
	}

	/**
	 * Returns a String, using the String input parameters for guidance. The actual behavior of
	 * the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid String value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			for a String value. If the same popup has been run before in the same session, the
	 * 			String input field will be pre-populated with the last-used String. If not, the
	 * 			String input field will be pre-populated with the .properties value (if it exists).
	 * 		</li>
	 *		<li>In the headless environment, this method returns a String value	representing the
	 *			.properties value (if it exists), or throws an Exception if there is an invalid or
	 *			missing .properties value.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable	name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @return the user-specified String value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IndexOutOfBoundsException if in headless mode and arguments are being used, but not
	 *          enough arguments were passed in to accommodate the request.
	 * @throws IllegalArgumentException if in headless mode, there was an invalid String
	 * 			specified in the arguments, or an invalid or missing String specified in the
	 *          .properties file
	 */
	public String askString(String title, String message) throws CancelledException {
		return askString(title, message, "");
	}

	/**
	 * Returns a String, using the String input parameters for guidance. The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid String value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			for a String value. The pre-populated value for the String input field will be the
	 * 			last-used String (if the dialog has been run before). If that does not exist, the
	 * 			pre-populated value is the .properties value. If that does	not exist or is invalid,
	 * 			then the 'defaultValue' parameter is used (as long as it is not	null or the empty
	 * 			String).</li>
	 *		<li>In the headless environment, this method returns a String value representing the
	 *			.properties value (if it exists). Otherwise, if the 'defaultValue' parameter is
	 *			not null or an empty String, it is returned. In all other cases, an exception
	 *			is thrown.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @param defaultValue the optional default value
	 * @return the user-specified String value
	 * @throws CancelledException if the user hit the 'cancel' button in GUI mode
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid String
	 * 			specified in the .properties file
	 */
	public String askString(String title, String message, String defaultValue)
			throws CancelledException {

		String key = join(title, message);
		String existingValue = loadAskValue(defaultValue, this::stringIdentity, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		String choice = doAsk(String.class, title, message, existingValue, lastValue -> {
			AskDialog<String> dialog = new AskDialog<>(title, message, AskDialog.STRING, lastValue);

			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			return dialog.getValueAsString();
		});

		return choice;
	}

	/**
	 * Parses a choice from a string.
	 *
	 * @param val The string to parse.
	 * @param validChoices An array of valid choices.
	 * @return The choice
	 * @throws IllegalArgumentException if the parsed string was not a valid choice.
	 */
	public <T> T parseChoice(String val, List<T> validChoices) {
		for (T choice : validChoices) {
			if (choice.toString().equals(val)) {
				return choice;
			}
		}
		throw new IllegalArgumentException("Invalid choice: " + val);
	}

	/**
	 * Returns an object that represents one of the choices in the given list. The actual behavior
	 * of the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents a valid choice, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			to choose from the given list of objects. The pre-chosen choice will be the last
	 * 			user-chosen value (if the dialog has been run before). If that does not exist, the
	 * 			pre-chosen value is the .properties value. If that does not exist or is invalid,
	 * 			then the 'defaultValue' parameter is used (as long as it is not null).</li>
	 *		<li>In the headless environment, this method returns an object representing the
	 *			.properties value (if it exists and is a valid choice), or throws an Exception if
	 *			there is an invalid or missing .properties value.</li>
	 * </ol>
	 * 
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display next to the input field (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @param choices set of choices (toString() value of each object will be displayed in the dialog)
	 * @param defaultValue the default value to display in the input field; may be
	 *                     null, but must be a valid choice if non-null.
	 * @return the user-selected value
	 * @throws CancelledException if the user hit the 'cancel' button
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	choice
	 * 			specified in the .properties file
	 */
	public <T> T askChoice(String title, String message, List<T> choices, T defaultValue)
			throws CancelledException {

		// The value parser function is only a two parameter list (String,T).  We have another
		// parameter for this method's parse function.  So, curry it.
		StringTransformer<T> curry = s -> parseChoice(s, choices);

		String key = join(title, message);
		T existingValue = loadAskValue(defaultValue, curry, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Class<?> clazz = choices.get(0).getClass();
		T choice = doAsk(clazz, title, message, existingValue, lastValue -> {

			AskDialog<T> dialog =
				new AskDialog<>(null, title, message, AskDialog.STRING, choices, lastValue);
			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			T value = dialog.getChoiceValue();
			return value;
		});

		return choice;
	}

	private boolean isBlank(Object o) {
		if (o == null) {
			return true;
		}

		return o.toString().trim().isEmpty();
	}

	/**
	 * Parses choices from a string.  The string must be surrounded by quotes, with a ';' as the
	 * separator.
	 *
	 * @param s The string to parse.
	 * @param validChoices An array of valid choices.
	 * @return The choices, if they found in the array of choices.
	 * @throws IllegalArgumentException if the parsed string did not contain any valid choices.
	 */
	public <T> List<T> parseChoices(String s, List<T> validChoices) {
		Set<String> choiceStringSet = new HashSet<>(getValues(s));
		List<T> ret = new LinkedList<>();
		for (T choice : validChoices) {
			if (choiceStringSet.contains(choice.toString())) {
				ret.add(choice);
			}
		}

		if (!ret.isEmpty()) {
			return ret;
		}

		throw new IllegalArgumentException("Invalid choices: " + s);
	}

	/**
	 * Parses choices from a string.
	 *
	 * @param val The string to parse.
	 * @param validChoices A list of valid choices.
	 * @param stringRepresentationOfValidChoices An corresponding array of valid choice string
	 *          representations.
	 * @return The choices
	 * @throws IllegalArgumentException if the parsed string did not contain any valid choices.
	 */
	public <T> List<T> parseChoices(String val, List<T> validChoices,
			List<String> stringRepresentationOfValidChoices) {

		Set<String> choiceStringSet = new HashSet<>(getValues(val));
		List<T> ret = new LinkedList<>();
		for (int i = 0; i < stringRepresentationOfValidChoices.size(); i++) {
			if (choiceStringSet.contains(stringRepresentationOfValidChoices.get(i))) {
				ret.add(validChoices.get(i));
			}
		}

		if (!ret.isEmpty()) {
			return ret;
		}

		throw new IllegalArgumentException("Invalid choices: " + val);
	}

	/**
	 * Returns an array of Objects representing one or more choices from the given list. The actual
	 * behavior of the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents valid choices, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a pop-up dialog that presents the user
	 * 		    with checkbox choices (to allow a more flexible option where the user can pick
	 * 			some, all, or none).</li>
	 * 		<li>In the headless environment, if a .properties file sharing the same base name as the
	 * 			Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
	 * 			looks there for the choices to return. The method will look in the .properties file
	 * 			by searching for a property name equal to a space-separated concatenation of the
	 * 			String parameters (title + " " + message). If that property name exists and
	 * 			represents a list (one or more) of valid choice(s) in the form
	 * 			"choice1;choice2;choice3;..." (&lt;-- note the quotes surrounding the choices), then
	 * 			an Object array of those choices is returned. Otherwise, an Exception is thrown if
	 * 			there is an invalid or missing .properties value.</li>
	 *</ol>
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display with the choices (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @param choices set of choices (toString() value of each object will be displayed in the dialog)
	 * @return the user-selected value(s); an empty list if no selection was made
	 *
	 * @throws CancelledException if the user hits the 'cancel' button
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid	set of
	 * 			choices specified in the .properties file 
	 */
	public <T> List<T> askChoices(String title, String message, List<T> choices)
			throws CancelledException {

		// The value parser function is only a two parameter list (String,List<T>).  We have another
		// parameter for this method's parse function.  So, curry it.
		StringTransformer<List<T>> curry = s -> parseChoices(s, choices);

		String key = join(title, message);
		List<T> existingValue = loadAskValue(curry, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Class<?> clazz = choices.get(0).getClass();
		List<T> choice = doAsk(clazz, title, message, existingValue, lastValue -> {

			AtomicReference<List<T>> reference = new AtomicReference<>();
			MultipleOptionsDialog<T> dialog =
				new MultipleOptionsDialog<>(title, message, choices, true);

			Runnable r = () -> reference.set(dialog.getUserChoices());
			Swing.runNow(r);

			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			return reference.get();
		});

		return choice;
	}

	/**
	 * Returns an array of Objects representing one or more choices from the given list. The user
	 * specifies the choices as Objects, also passing along a corresponding array of String
	 * representations for each choice (used as the checkbox label). The actual behavior of the
	 * method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + message).
	 * If that property name exists and its value represents valid choices, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a pop-up dialog that presents the user
	 * 		    with checkbox choices (to allow a more flexible option where the user can pick
	 * 			some, all, or none).</li>
	 * 		<li>In the headless environment, if a .properties file sharing the same base name as the
	 * 			Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
	 * 			looks there for the choices to return. The method will look in the .properties file
	 * 			by searching for a property name equal to a space-separated concatenation of the
	 * 			String parameters (title + " " + message). If that property name exists and
	 * 			represents a list (one or more) of valid choice(s) in the form
	 * 			"choice1;choice2;choice3;..." (&lt;-- note the quotes surrounding the choices), then
	 * 			an Object array of those choices is returned. Otherwise, an Exception is thrown if
	 * 			there is an invalid or missing .properties value. NOTE: the choice names for
	 * 			this method must match those in the stringRepresentationOfChoices array.</li>
	 *</ol>
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode or when using .properties file)
	 * @param message the message to display with the choices (in GUI mode) or the second
	 * 			part of the variable name (in headless mode or when using .properties file)
	 * @param choices set of choices
	 * @param choiceLabels the String representation for each choice, used for
	 * 			checkbox labels
	 * @return the user-selected value(s); null if no selection was made
	 *
	 * @throws CancelledException if the user hits the 'cancel' button
	 * @throws IllegalArgumentException if choices is empty; if in headless mode, 
	 *         there was a missing or invalid set of choices	specified in the .properties file 
	 */
	public <T> List<T> askChoices(String title, String message, List<T> choices,
			List<String> choiceLabels) throws CancelledException {

		// The value parser function is only a two parameter list (String,T[]).  We have another
		// parameter for this method's parse function.  So, curry it.
		StringTransformer<List<T>> curry = s -> parseChoices(s, choices, choiceLabels);

		String key = join(title, message);
		List<T> existingValue = loadAskValue(curry, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		Class<?> clazz = choices.get(0).getClass();
		List<T> choice = doAsk(clazz, title, message, existingValue, lastValue -> {

			AtomicReference<List<T>> reference = new AtomicReference<>();
			MultipleOptionsDialog<T> dialog =
				new MultipleOptionsDialog<>(title, message, choices, choiceLabels, true);

			Runnable r = () -> reference.set(dialog.getUserChoices());
			Swing.runNow(r);

			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			return reference.get();
		});

		return choice;
	}

	/**
	 * Parses a boolean from a string.
	 *
	 * @param val The string to parse.
	 * @return The boolean that was parsed from the string.
	 * @throws IllegalArgumentException if the parsed value is not a valid boolean.
	 */
	public Boolean parseBoolean(String val) {
		if ("true".equalsIgnoreCase(val) || "false".equalsIgnoreCase(val)) {
			return Boolean.parseBoolean(val);
		}
		throw new IllegalArgumentException("Invalid boolean: " + val);
	}

	/**
	 * Returns a boolean value, using the String parameters for guidance. The actual behavior of
	 * the method depends on your environment, which can be GUI or headless.
	 * <p>
	 * Regardless of environment -- if script arguments have been set, this method will use the
	 * next argument in the array and advance the array index so the next call to an ask method
	 * will get the next argument.  If there are no script arguments and a .properties file
	 * sharing the same base name as the Ghidra Script exists (i.e., Script1.properties for
	 * Script1.java), then this method will then look there for the String value to return.
	 * The method will look in the .properties file by searching for a property name that is a
	 * space-separated concatenation of the input String parameters (title + " " + question).
	 * If that property name exists and its value represents a valid boolean value, then the
	 * .properties value will be used in the following way:
	 * <ol>
	 * 		<li>In the GUI environment, this method displays a popup dialog that prompts the user
	 * 			with a yes/no dialog with the specified title and question. Returns true if the user
	 * 			selects "yes" to the question or false if the user selects "no".</li>
	 * 		<li>In the headless environment, if a .properties file sharing the same base name as the
	 * 			Ghidra Script exists (i.e., Script1.properties for Script1.java), then this method
	 * 			looks there for the boolean value to return. The method will look in the .properties
	 * 			file by searching for a property name that is a space-separated concatenation of the
	 * 			String parameters (title + " " + question). If that property name exists and its
	 * 			value represents a valid boolean value (either 'true' or 'false', case insensitive),
	 * 			then that value	is returned. Otherwise, an Exception is thrown if there is an
	 * 			invalid or missing .properties value.</li>
	 * </ol>
	 * 
	 *
	 * @param title the title of the dialog (in GUI mode) or the first part of the variable name
	 * 			(in headless mode)
	 * @param question the question to display to the user (in GUI mode) or the second part of the
	 * 			variable name (in headless mode)
	 * @return true if the user selects "yes" to the question (in GUI mode) or "true" (in headless
	 * 			mode)
	 * @throws IllegalArgumentException if in headless mode, there was a missing or invalid boolean
	 * 			specified in the .properties file
	 */
	public boolean askYesNo(String title, String question) {

		String key = join(title, question);
		Boolean existingValue = loadAskValue(this::parseBoolean, key);
		if (isRunningHeadless()) {
			return existingValue;
		}

		return OptionDialog.showYesNoDialog(null, title, question) == OptionDialog.OPTION_ONE;
	}

	/**
	 * Returns a hex string representation of the byte.
	 *
	 * @param b        the integer
	 * @param zeropad  true if the value should be zero padded
	 * @param header   true if "0x" should be prepended
	 * @return the hex formatted string
	 */
	public String toHexString(byte b, boolean zeropad, boolean header) {
		String str = Integer.toHexString(b & 0xff);
		if (zeropad) {
			str = zeropad(str, 2);
		}
		return (header ? "0x" : "") + str;
	}

	/**
	 * Returns a hex string representation of the short.
	 *
	 * @param s        the short
	 * @param zeropad  true if the value should be zero padded
	 * @param header   true if "0x" should be prepended
	 * @return the hex formatted string
	 */
	public String toHexString(short s, boolean zeropad, boolean header) {
		String str = Integer.toHexString(s & 0xffff);
		if (zeropad) {
			str = zeropad(str, 4);
		}
		return (header ? "0x" : "") + str;
	}

	/**
	 * Returns a hex string representation of the integer.
	 *
	 * @param i        the integer
	 * @param zeropad  true if the value should be zero padded
	 * @param header   true if "0x" should be prepended
	 * @return the hex formatted string
	 */
	public String toHexString(int i, boolean zeropad, boolean header) {
		String s = Integer.toHexString(i);
		if (zeropad) {
			s = zeropad(s, 8);
		}
		return (header ? "0x" : "") + s;
	}

	/**
	 * Returns a hex string representation of the long.
	 *
	 * @param l        the long
	 * @param zeropad  true if the value should be zero padded
	 * @param header   true if "0x" should be prepended
	 * @return the hex formatted string
	 */
	public String toHexString(long l, boolean zeropad, boolean header) {
		String s = Long.toHexString(l);
		if (zeropad) {
			s = zeropad(s, 16);
		}
		return (header ? "0x" : "") + s;
	}

	/**
	 * Sends a 'goto' event that navigates the listing to the specified
	 * address.
	 *
	 * @param address the address to 'goto'
	 * @return true if the address is valid
	 */
	public boolean goTo(Address address) {
		PluginTool tool = state.getTool();
		if (tool == null) {
			return false;
		}

		GoToService gotoService = tool.getService(GoToService.class);
		if (gotoService != null) {
			return gotoService.goTo(address);
		}
		return false;
	}

	/**
	 * Sends a 'goto' event that navigates the listing to the specified symbol.
	 *
	 * @param symbol the symbol to 'goto'
	 * @return true if the symbol is valid
	 */
	public boolean goTo(Symbol symbol) {
		return goTo(symbol.getAddress());
	}

	/**
	 * Sends a 'goto' event that navigates the listing to the specified function.
	 *
	 * @param function the function to 'goto'
	 * @return true if the function is valid
	 */
	public boolean goTo(Function function) {
		return goTo(function.getEntryPoint());
	}

	/**
	 * Attempts to import the specified file. It attempts to detect the format and
	 * automatically import the file. If the format is unable to be determined, then
	 * null is returned.
	 *
	 * @param file the file to import
	 * @return the newly imported program, or null
	 * @throws Exception if any exceptions occur while importing
	 */
	public Program importFile(File file) throws Exception {
		return AutoImporter.importByUsingBestGuess(file, null, this, new MessageLog(), monitor);
	}

	/**
	 * Imports the specified file as raw binary.
	 *
	 * @param file the file to import
	 * @param language the language of the new program
	 * @param compilerSpec the compilerSpec to use for the import.
	 * @return the newly created program, or null
	 * @throws Exception if any exceptions occur when importing
	 */
	public Program importFileAsBinary(File file, Language language, CompilerSpec compilerSpec)
			throws Exception {
		return AutoImporter.importAsBinary(file, null, language, compilerSpec, this,
			new MessageLog(), monitor);
	}

	/**
	 * Opens the specified program in the current tool.
	 *
	 * @param program the program to open
	 */
	public void openProgram(Program program) {
		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program);
		end(true);
		GhidraState newState = new GhidraState(tool, tool.getProject(), program, null, null, null);
		set(newState, monitor, writer);
		start();
	}

	/**
	 * Closes the specified program in the current tool.
	 *
	 * @param program the program to close
	 */
	public void closeProgram(Program program) {
		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, false);
	}

	/**
	 * Creates a new program with specified name and language name. The actual language object
	 * is located using the language name provided.
	 * <p>
	 * Please note: the program is not automatically saved into the program.
	 *
	 * @param programName the program name
	 * @param languageID the language ID
	 * @param compilerSpecID the compiler Spec ID
	 * @return the new unsaved program
	 * @throws Exception the language name is invalid or an I/O error occurs
	 */
	public Program createProgram(String programName, LanguageID languageID,
			CompilerSpecID compilerSpecID) throws Exception {
		Language language = getLanguage(languageID);
		return createProgram(programName, language, language.getCompilerSpecByID(compilerSpecID));
	}

	/**
	 * Creates a new program with specified name and language name. The actual language object
	 * is located using the language name provided.
	 * <p>
	 * Please note: the program is not automatically saved into the program.
	 *
	 * @param programName the program name
	 * @param languageID the language name
	 * @return the new unsaved program
	 * @throws Exception the language name is invalid or an I/O error occurs
	 */
	public Program createProgram(String programName, LanguageID languageID) throws Exception {
		Language language = getLanguage(languageID);
		CompilerSpec spec = language.getDefaultCompilerSpec();
		return createProgram(programName, language, spec);
	}

	/**
	 * Creates a new program with specified name and language. It uses the default compilerSpec
	 * for the given language.
	 * <p>
	 * Please note: the program is not automatically saved into the project.
	 *
	 * @param programName the program name
	 * @param language the language
	 * @param compilerSpec the compilerSpec to use.
	 * @return the new unsaved program
	 * @throws Exception the language name is invalid or an I/O error occurs
	 */
	public Program createProgram(String programName, Language language, CompilerSpec compilerSpec)
			throws Exception {
		Program program = new ProgramDB(programName, language, compilerSpec, this);
		openProgram(program);
		program.release(this);
		return program;
	}

	/**
	 * Display a message in tools status bar.
	 * <p>
	 * This method is unavailable in headless mode.
	 *
	 * @param msg the text to display.
	 * @param beep if true, causes the tool to beep.
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void setToolStatusMessage(String msg, boolean beep) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The setToolStatusMessage() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			if (beep) {
				printerr(msg);
			}
			return;
		}
		tool.setStatusInfo(msg, beep);
	}

	/**
	 * Displays the address array in a table component. The table contains an address
	 * column, a label column, and a preview column.
	 * <p>
	 * This method is unavailable in headless mode.
	 *
	 * @param addresses the address array to display
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void show(Address[] addresses) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The show() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		TableService ts = tool.getService(TableService.class);
		if (ts == null) {
			println("Unable to show addresses, no table service exists.");
		}
		else {
			show("Addresses", ts, addresses);
		}
	}

	/**
	 * Displays the given AddressSet in a table, in a dialog.
	 * <p>
	 * This method is unavailable in headless mode.
	 *
	 * @param title The title of the table
	 * @param addresses The addresses to display
	 * @throws ImproperUseException if this method is run in headless mode
	 */
	public void show(String title, AddressSetView addresses) throws ImproperUseException {

		if (isRunningHeadless()) {
			throw new ImproperUseException(
				"The show() method can only be used when running headed Ghidra.");
		}

		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}

		TableService ts = tool.getService(TableService.class);
		if (ts == null) {
			println("Unable to show addresses, no table service exists.");
			return;
		}
		show(title, ts, addresses);
	}

	/**
	 * Returns the PLATE comment at the specified address, as rendered.  Comments support
	 * annotations, which are displayed differently than the raw text.  If you want the raw text,
	 * then you must call {@link #getPlateComment(Address)}.  This method returns the text as
	 * seen in the display.
	 *
	 * @param address the address to get the comment
	 * @return the PLATE comment at the specified address or null
	 * 			if one does not exist
	 * @see #getPlateComment(Address)
	 */
	public String getPlateCommentAsRendered(Address address) {
		String comment = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, address);
		PluginTool tool = state.getTool();
		if (tool != null) {
			comment = CommentUtils.getDisplayString(comment, currentProgram);
		}
		return comment;
	}

	/**
	 * Returns the PRE comment at the specified address.  If you want the raw text,
	 * then you must call {@link #getPreComment(Address)}.  This method returns the text as
	 * seen in the display.
	 *
	 * @param address the address to get the comment
	 * @return the PRE comment at the specified address or null
	 * 		if one does not exist
	 * @see #getPreComment(Address)
	 */
	public String getPreCommentAsRendered(Address address) {
		String comment = currentProgram.getListing().getComment(CodeUnit.PRE_COMMENT, address);
		PluginTool tool = state.getTool();
		if (tool != null) {
			comment = CommentUtils.getDisplayString(comment, currentProgram);
		}
		return comment;
	}

	/**
	 * Returns the POST comment at the specified address.  If you want the raw text,
	 * then you must call {@link #getPostComment(Address)}.  This method returns the text as
	 * seen in the display.
	 *
	 * @param address the address to get the comment
	 * @return the POST comment at the specified address or null if one does not exist
	 * @see #getPostComment(Address)
	 */
	public String getPostCommentAsRendered(Address address) {
		String comment = currentProgram.getListing().getComment(CodeUnit.POST_COMMENT, address);
		PluginTool tool = state.getTool();
		if (tool != null) {
			comment = CommentUtils.getDisplayString(comment, currentProgram);
		}
		return comment;
	}

	/**
	 * Returns the EOL comment at the specified address.  If you want the raw text,
	 * then you must call {@link #getEOLComment(Address)}.  This method returns the text as
	 * seen in the display.
	 *
	 * @param address the address to get the comment
	 * @return the EOL comment at the specified address or null if one does not exist
	 * @see #getEOLComment(Address)
	 */
	public String getEOLCommentAsRendered(Address address) {
		String comment = currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, address);
		PluginTool tool = state.getTool();
		if (tool != null) {
			comment = CommentUtils.getDisplayString(comment, currentProgram);
		}
		return comment;
	}

	/**
	 * Returns the repeatable comment at the specified address.  If you want the raw text,
	 * then you must call {@link #getRepeatableComment(Address)}.  This method returns the text as
	 * seen in the display.
	 *
	 * @param address the address to get the comment
	 * @return the repeatable comment at the specified address or null if one does not exist
	 * @see #getRepeatableComment(Address)
	 */
	public String getRepeatableCommentAsRendered(Address address) {
		String comment =
			currentProgram.getListing().getComment(CodeUnit.REPEATABLE_COMMENT, address);
		PluginTool tool = state.getTool();
		if (tool != null) {
			comment = CommentUtils.getDisplayString(comment, currentProgram);
		}
		return comment;
	}

	private void show(String title, TableService table, Address[] addresses) {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Couldn't show table!");
			return;
		}

		Runnable runnable = () -> {
			AddressArrayTableModel model = new AddressArrayTableModel(getScriptName(),
				state.getTool(), currentProgram, addresses);
			TableComponentProvider<Address> tableProvider =
				table.showTableWithMarkers(title + " " + model.getName(), "GhidraScript", model,
					Color.GREEN, null, "Script Results", null);
			tableProvider.installRemoveItemsAction();
		};
		Swing.runLater(runnable);
	}

	private void show(final String title, final TableService table,
			final AddressSetView addresses) {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Couldn't show table!");
			return;
		}

		Runnable runnable = () -> {
			AddressSetTableModel model =
				new AddressSetTableModel(title, state.getTool(), currentProgram, addresses, null);
			TableComponentProvider<Address> tableProvider = table.showTableWithMarkers(title,
				"GhidraScript", model, Color.GREEN, null, "Script Results", null);
			tableProvider.installRemoveItemsAction();
		};
		Swing.runLater(runnable);
	}

	private Map<Class<?>, Object> getScriptMap(String title, String message) {
		Map<Class<?>, Object> scriptMap = askMap.get(title + message);
		if (scriptMap == null) {
			scriptMap = new HashMap<>();
			askMap.put(title + message, scriptMap);
		}
		return scriptMap;
	}

	private static String zeropad(String s, int len) {
		if (s == null) {
			s = "";
		}
		StringBuffer buffer = new StringBuffer(s);
		int zerosNeeded = len - s.length();
		for (int i = 0; i < zerosNeeded; ++i) {
			buffer.insert(0, '0');
		}
		return buffer.toString();
	}
}
