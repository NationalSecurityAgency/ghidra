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
package ghidra.app.util.headless;

import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.framework.model.DomainFolder;
import ghidra.util.InvalidNameException;

/**
 * This class is analogous to GhidraScript, except that is only meant to be used with
 * the HeadlessAnalyzer.  That is, if a user writes a script that extends HeadlessScript,
 * it should only be run in the Headless environment.
 */
public abstract class HeadlessScript extends GhidraScript {

	/**
	 * Options for controlling disposition of program after the current script completes.
	 */
	public enum HeadlessContinuationOption {
		/**
		 * Continue running scripts and/or analysis; <code>-import</code> and <code>-process</code> 
		 * modes complete normally.
		 */
		CONTINUE,

		/**
		 *  Continue running scripts and/or analysis; 
		 *  <code>-import</code> mode does not save program, 
		 *  <code>-process</code> mode deletes program.
		 */
		CONTINUE_THEN_DELETE,

		/**
		 *  Abort any scripts or analysis that come after this script;
		 *  <code>-import</code> mode does not save program, <code>-process</code> mode deletes program.
		 */
		ABORT_AND_DELETE,

		/**
		 * Abort any scripts or analysis that come after this script; <code>-import</code> mode does 
		 * save program (but it may not be processed completely),
		 * <code>-process</code> mode completes normally, minus scripts or analysis that 
		 * runs after the ABORT request.
		 */
		ABORT
	}

	private HeadlessAnalyzer headless = null;

	private HeadlessContinuationOption currentOption = HeadlessContinuationOption.CONTINUE;
	private HeadlessContinuationOption scriptSetOption = null;

	private boolean runningInnerScript = false;

	// This is necessary because it determine when we nullify the 'scriptSetOption' variable
	private void setRunningInnerScript(boolean b) {
		runningInnerScript = b;
	}

	/**
	 * Sets the current headless instance -- doing so gives the user the ability to manipulate 
	 * headless analyzer-specific parameters.
	 * <p>
	 * This method is declared with no access modifier to only allow package-level (no subclass) 
	 * access. This method is meant to only be used by the HeadlessAnalyzer class.
	 * 
	 * @param ha  HeadlessAnalyzer instance
	 */
	void setHeadlessInstance(HeadlessAnalyzer ha) {
		headless = ha;
	}

	/**
	 * Sets the "beginning-of-script" continuation status.
	 * <p>
	 * This method is declare with no access modifier to only allow package-level (no
	 * subclass) access. This method is meant to only be used by the HeadlessAnalyzer class.
	 * 
	 * @param option initial continuation option for this script
	 */
	void setInitialContinuationOption(HeadlessContinuationOption option) {
		currentOption = option;
	}

	/**
	 * Returns the final resolved continuation option (after script processing is done).
	 * <p>
	 * The continuation option specifies whether to continue or abort follow-on processing,
	 * and whether to delete or keep the current program.
	 * <p>
	 * This method is declared with no access modifier to only allow package-level (no
	 * subclass) access. This method is meant to only be used by the HeadlessAnalyzer class.
	 * 
	 * @return the script's final HeadlessContinuationOption
	 */
	HeadlessContinuationOption getContinuationOption() {
		return currentOption;
	}

	/**
	 * Checks to see if this script is running in headless mode (it should be!).
	 * <p>
	 * This method should be called at the beginning of every public method in HeadlessScript
	 * that accesses HeadlessAnalyzer methods (for instance, 'headless.isAnalysisEnabled()').
	 * The call to this method can not be placed in the constructor, because 'setHeadlessInstance', 
	 * which connects the script with the current headless instance, is not called until after the 
	 * call to the constructor.
	 *   
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 */
	private void checkHeadlessStatus() throws ImproperUseException {
		if (headless == null || !isRunningHeadless()) {
			throw new ImproperUseException("This method can only be used in the headless case!");
		}
	}

	/**
	 * Stores a key/value pair in the HeadlessAnalyzer instance for later use.
	 * <p>
	 * This method, along with the 'getStoredHeadlessValue' method, is useful for debugging and 
	 * testing the Headless Analyzer (when the user has directly instantiated the HeadlessAnalyzer
	 * instead of running it from analyzeHeadless.sh or analyzeHeadless.bat). This method is
	 * intended to allow a HeadlessScript to store variables that reflect the current state of 
	 * processing (at the time the script is being run). Storing variables in the HeadlessAnalyzer
	 * instance may be the only way to access the state of processing during cases when the user 
	 * is forced to run in -readOnly mode, or if there is a value that is only accessible at the 
	 * scripts stage.
	 * 
	 * @param key	storage key in String form
	 * @param value value to store
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 * @see #getStoredHeadlessValue(String)
	 * @see #headlessStorageContainsKey(String)
	 */
	public void storeHeadlessValue(String key, Object value) throws ImproperUseException {
		checkHeadlessStatus();
		headless.addVariableToStorage(key, value);
	}

	/**
	 * Get stored value by key from the HeadlessAnalyzer instance.
	 * <p>
	 * This method, along with the 'storedHeadlessValue' method, is useful for debugging and 
	 * testing the Headless Analyzer (when the user has directly instantiated the HeadlessAnalyzer
	 * instead of running it from analyzeHeadless.sh or analyzeHeadless.bat). This method is
	 * intended to allow a HeadlessScript to store variables that reflect the current state of 
	 * processing (at the time the script is being run). Storing variables in the HeadlessAnalyzer
	 * instance may be the only way to access the state of processing during cases when the user 
	 * is forced to run in -readOnly mode, or if there is a value that is only accessible at the 
	 * scripts stage.	 
	 *  
	 * @param key  key to retrieve the desired stored value
	 * @return  stored Object, or null if none exists for that key
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 * @see #storeHeadlessValue(String, Object)
	 * @see #headlessStorageContainsKey(String)
	 */
	public Object getStoredHeadlessValue(String key) throws ImproperUseException {
		checkHeadlessStatus();
		return headless.getVariableFromStorage(key);
	}

	/**
	 * Returns whether the specified key was stored in the HeadlessAnalyzer instance.
	 * 
	 * @param key  value of key to check for in Headless Analyzer instance
	 * @return  true if the specified key exists
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 * @see #storeHeadlessValue(String, Object)
	 * @see #getStoredHeadlessValue(String)
	 */
	public boolean headlessStorageContainsKey(String key) throws ImproperUseException {
		checkHeadlessStatus();
		return headless.storageContainsKey(key);
	}

	/**
	 * Sets the continuation option for this script
	 * <p>
	 * The continuation option specifies whether to continue or abort follow-on processing,
	 * and whether to delete or keep the current program.
	 * 
	 * @param option HeadlessContinuationOption set by this script
	 * @see #getHeadlessContinuationOption()
	 */
	public void setHeadlessContinuationOption(HeadlessContinuationOption option) {
		scriptSetOption = option;
	}

	/**
	 * Returns the continuation option for the current script (if one has not been set in this
	 * script, the option defaults to CONTINUE).
	 * <p>
	 * The continuation option specifies whether to continue or abort follow-on processing,
	 * and whether to delete or keep the current program.
	 * 
	 * @return the current HeadlessContinuationOption
	 * @see #setHeadlessContinuationOption(HeadlessContinuationOption)
	 */
	public HeadlessContinuationOption getHeadlessContinuationOption() {
		if (scriptSetOption == null) {
			return HeadlessContinuationOption.CONTINUE;
		}

		return scriptSetOption;
	}

	/**
	 * Enables or disables analysis according to the passed-in boolean value.
	 * <p>
	 * A script that calls this method should run as a 'preScript', since preScripts
	 * execute before analysis would typically run. Running the script as a 'postScript'
	 * is ineffective, since the stage at which analysis would have happened has already 
	 * passed.
	 * <p>
	 * This change will persist throughout the current HeadlessAnalyzer session, unless
	 * changed again (in other words, once analysis is enabled via script for one program,
	 * it will also be enabled for future programs in the current session, unless changed). 
	 * 
	 * @param b  true to enable analysis, false to disable analysis
	 * @throws ImproperUseException if not in headless mode or headless instance not set 
	 * @see #isHeadlessAnalysisEnabled()
	 */
	public void enableHeadlessAnalysis(boolean b) throws ImproperUseException {
		checkHeadlessStatus();

		headless.getOptions().enableAnalysis(b);
	}

	/**
	 * Returns whether analysis is currently enabled or disabled in the HeadlessAnalyzer.
	 * 
	 * @return whether analysis has been enabled or not
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 * @see #enableHeadlessAnalysis(boolean)
	 */
	public boolean isHeadlessAnalysisEnabled() throws ImproperUseException {
		checkHeadlessStatus();

		return headless.getOptions().analyze;
	}

	/**
	 * Returns whether the headless analyzer is currently set to -import mode or not (if not,
	 * it is in -process mode). The use of -import mode implies that binaries are actively being
	 * imported into the project (with optional scripts/analysis). The use of -process mode implies
	 * that existing project files are being processed (using scripts and/or analysis).
	 * 
	 * @return whether we are in -import mode or not
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 */
	public boolean isImporting() throws ImproperUseException {
		checkHeadlessStatus();

		return !headless.getOptions().runScriptsNoImport;
	}

	/**
	 * Changes the path <i>in the Ghidra project</i> where imported files are saved. 
	 * The passed-in path is assumed to be relative to the project root. For example,
	 * if the directory structure for the Ghidra project looks like this:
	 * 
	 * <pre>
	 * 		MyGhidraProject:
	 * 		  /dir1
	 * 		    /innerDir1
	 * 		    /innerDir2
	 * </pre>
	 * 
	 * Then the following usage would ensure that any files imported after this call would
	 * be saved in the <code>MyGhidraProject:/dir1/innerDir2</code> folder.
	 * <pre>
	 * 		setHeadlessImportDirectory("dir1/innerDir2");
	 * </pre>
	 * In contrast, the following usages would add new folders to the Ghidra project and save
	 * the imported files into the newly-created path:
	 * <pre>
	 * 		setHeadlessImportDirectory("innerDir2/my/folder");
	 * </pre>
	 * changes the directory structure to:
	 * <pre>
	 * 		MyGhidraProject:
	 * 		  /dir1
	 * 		    /innerDir1
	 * 		    /innerDir2
	 * 		      /my
	 * 		        /folder
	 * </pre>
	 * and:
	 * <pre>
	 * 		setHeadlessImportDirectory("newDir/saveHere");
	 * </pre>
	 * changes the directory structure to:
	 * <pre>
	 * 		MyGhidraProject:
	 * 		  /dir1
	 * 		    /innerDir1
	 * 			/innerDir2
	 *		  /newDir
	 * 		    /saveHere
	 * </pre>
	 * As in the examples above, if the desired folder does not already exist, it is created.
	 * <p>
	 * A change in the import save folder will persist throughout the current HeadlessAnalyzer 
	 * session, unless changed again (in other words, once the import directory has been changed, 
	 * it will remain the 'save' directory for import files in the current session, unless changed).
	 * <p>
	 * To revert back to the default import location (that which was specified via command line),
	 * pass the null object as the argument to this method, as below:
	 * <pre>
	 * 		setHeadlessImportDirectory(null);	// Sets import save directory to default
	 * </pre>
	 * If a file with the same name already exists in the desired location, it will only be 
	 * overwritten if "-overwrite" is true.
	 * <p>
	 * This method is only applicable when using the HeadlessAnalyzer <code>-import</code> mode and 
	 * is ineffective in <code>-process</code> mode.
	 * 
	 * @param importDir  the absolute path (relative to root) where inputs will be saved
	 * @throws ImproperUseException if not in headless mode or headless instance not set	 
	 * @throws IOException if there are issues creating the folder
	 * @throws InvalidNameException if folder name is invalid
	 */
	public void setHeadlessImportDirectory(String importDir)
			throws ImproperUseException, IOException, InvalidNameException {
		checkHeadlessStatus();

		// Do nothing if not importing -- we don't want to have arbitrary folders
		// created when not being used!

		if (!headless.getOptions().runScriptsNoImport) {
			DomainFolder saveFolder = null;

			if (importDir != null) {

				if (!importDir.startsWith("/")) {
					importDir = "/" + importDir;
				}

				// Add ending slash so the dir gets created for server projects
				if (!importDir.endsWith("/")) {
					importDir += "/";
				}

				// Gets folder -- creates path if it doesn't already exist
				saveFolder = headless.getDomainFolder(importDir, true);
			}

			headless.setSaveFolder(saveFolder);
		}
	}

	/**
	 * Returns whether analysis for the current program has timed out.
	 * <p>
	 * Analysis will time out only in the case where:
	 * <ol>
	 * 		<li>the users has set an analysis timeout period using the <code>-analysisTimeoutPerFile</code>
	 * 	parameter</li>
	 * 		<li>analysis is enabled and has completed</li>
	 * 		<li>the current script is being run as a postScript (since postScripts run after
	 * analysis)</li>
	 * </ol>
	 * 
	 * @return whether analysis timeout occurred
	 * @throws ImproperUseException if not in headless mode or headless instance not set
	 */
	public boolean analysisTimeoutOccurred() throws ImproperUseException {
		checkHeadlessStatus();
		return headless.checkAnalysisTimedOut();
	}

	@Override
	public void runScript(String scriptName, String[] scriptArguments, GhidraState scriptState)
			throws Exception {

		boolean isHeadlessScript = false;

		if (scriptSetOption != null) {
			resolveContinuationOptionWith(scriptSetOption);
			scriptSetOption = null;
		}
		ResourceFile scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
		if (scriptSource != null) {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSource);

			if (provider == null) {
				throw new IOException("Attempting to run subscript '" + scriptName +
					"': unable to run this script type.");
			}

			GhidraScript script = provider.getScriptInstance(scriptSource, writer);
			isHeadlessScript = script instanceof HeadlessScript ? true : false;

			if (potentialPropertiesFileLocs.size() > 0) {
				script.setPotentialPropertiesFileLocations(potentialPropertiesFileLocs);
			}

			if (scriptState == state) {
				updateStateFromVariables();
			}

			if (isHeadlessScript) {
				((HeadlessScript) script).setHeadlessInstance(headless);
				((HeadlessScript) script).setRunningInnerScript(true);
			}

			script.setScriptArgs(scriptArguments);

			script.execute(scriptState, monitor, writer);

			if (scriptState == state) {
				loadVariablesFromState();
			}

			// Resolve continuations options, if they have changed
			if (isHeadlessScript) {
				HeadlessContinuationOption innerScriptOpt =
					((HeadlessScript) script).getHeadlessContinuationOption();

				if (innerScriptOpt != null) {
					resolveContinuationOptionWith(innerScriptOpt);
				}

				((HeadlessScript) script).setRunningInnerScript(false);
			}

			return;
		}

		throw new IllegalArgumentException("Script does not exist: " + scriptName);
	}

	@Override
	public void cleanup(boolean success) {
		resolveContinuationOption();

		if (!runningInnerScript) {
			scriptSetOption = null;
		}
	}

	private void resolveContinuationOption() {
		resolveContinuationOptionWith(scriptSetOption);
	}

	/**
	 * Resolve continuation options according to the table in 'analyzeHeadlessREADME.html'.
	 * (See "Multiple Scripts" section).
	 * 
	 * @param opt  continuation option to combine with current continuation option
	 */
	private void resolveContinuationOptionWith(HeadlessContinuationOption opt) {

		if (opt == null) {
			return;
		}

		switch (currentOption) {

			case CONTINUE:
				currentOption = opt;
				break;

			case CONTINUE_THEN_DELETE:
				switch (opt) {
					case ABORT:

					case ABORT_AND_DELETE:
						currentOption = HeadlessContinuationOption.ABORT_AND_DELETE;
						break;

					default:
						break;
				}
				break;

			case ABORT_AND_DELETE:
				// nothing changes
				break;

			case ABORT:
				// nothing changes
				break;
		}
	}
}
