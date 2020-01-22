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
import java.util.*;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderService;
import ghidra.framework.client.HeadlessClientAuthenticator;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.InvalidInputException;

/**
 * Options for headless analyzer.
 * <p>
 * Option state may be adjusted to reflect assumed options
 * during processing.  If multiple invocations of either
 * {@link HeadlessAnalyzer#processLocal(String, String, String, List)} or
 * {@link HeadlessAnalyzer#processURL(java.net.URL, List)} are performed,
 * these options should be reset and adjusted as necessary.
 */
public class HeadlessOptions {

	// -process and -import
	String domainFileNameToProcess; // may include pattern
	boolean runScriptsNoImport;

	// -preScript
	List<Pair<String, String[]>> preScripts;
	Map<String, ResourceFile> preScriptFileMap;

	// -postScript
	List<Pair<String, String[]>> postScripts;
	Map<String, ResourceFile> postScriptFileMap;

	// -scriptPath
	List<String> scriptPaths;

	// -propertiesPath
	List<String> propertiesFileStrPaths;
	List<ResourceFile> propertiesFilePaths;

	// -overwrite
	boolean overwrite;

	// -recursive
	boolean recursive;

	// -readOnly
	boolean readOnly;

	// -deleteProject
	boolean deleteProject;

	// -noanalysis
	boolean analyze;

	// -processor
	Language language;

	// -cspec
	CompilerSpec compilerSpec;

	// -analysisTimeoutPerFile
	int perFileTimeout;

	// -keystore
	String keystore;

	// -connect
	String connectUserID;

	// -p
	boolean allowPasswordPrompt;

	// -commit
	boolean commit;
	String commitComment;

	// -okToDelete
	boolean okToDelete;

	// -max-cpu
	int maxcpu;

	// -loader
	Class<? extends Loader> loaderClass;
	List<Pair<String, String>> loaderArgs;

	// -------------------------------------------------------------------------------------------

	/**
	 * Creates a new headless options object with default settings.
	 */
	HeadlessOptions() {
		reset();
	}

	/**
	 * Resets the options to its default settings.
	 */
	public void reset() {
		domainFileNameToProcess = null;
		runScriptsNoImport = false;
		preScripts = new LinkedList<>();
		preScriptFileMap = null;
		postScripts = new LinkedList<>();
		postScriptFileMap = null;
		scriptPaths = null;
		propertiesFileStrPaths = new ArrayList<>();
		propertiesFilePaths = new ArrayList<>();
		overwrite = false;
		recursive = false;
		readOnly = false;
		deleteProject = false;
		analyze = true;
		language = null;
		compilerSpec = null;
		perFileTimeout = -1;
		keystore = null;
		connectUserID = null;
		allowPasswordPrompt = false;
		commit = false;
		commitComment = null;
		okToDelete = false;
		maxcpu = 0;
		loaderClass = null;
		loaderArgs = null;
	}

	/**
	 * Set to run scripts (and optionally, analysis) without importing a
	 * program.  Scripts will run on specified folder or program that already
	 * exists in the project.
	 * 
	 * @param runScriptsOnly if true, no imports will occur and scripts
	 * 						 (and analysis, if enabled) will run on the specified existing program
	 * 					     or directory of programs.
	 * @param filename name of specific project file or folder to be processed (the location
	 * 					 is passed in elsewhere by the user).  If null, user has not specified
	 * 					 a file to process -- therefore, the entire directory will be processed.
	 * 					 The filename should not include folder path elements which should be 
	 *                   specified separately via project or URL specification.
	 * @throws IllegalArgumentException if the specified filename is invalid and contains the
	 * path separator character '/'. 
	 */
	public void setRunScriptsNoImport(boolean runScriptsOnly, String filename) {
		if (filename != null) {
			filename = filename.trim();
			if (filename.indexOf("/") >= 0) {
				throw new IllegalArgumentException("invalid filename specified");
			}
		}
		this.runScriptsNoImport = runScriptsOnly;
		this.domainFileNameToProcess = filename;
	}

	/**
	 * Set the ordered list of scripts to execute immediately following import and
	 * prior to analyzing an imported program.  If import not performed,
	 * these scripts will execute once prior to any post-scripts.
	 * 
	 * @param preScripts list of script names
	 */
	public void setPreScripts(List<String> preScripts) {
		List<Pair<String, String[]>> preScriptsEmptyArgs = new LinkedList<>();
		for (String preScript : preScripts) {
			preScriptsEmptyArgs.add(new Pair<>(preScript, new String[0]));
		}
		setPreScriptsWithArgs(preScriptsEmptyArgs);
	}

	/**
	 * Set the ordered list of scripts and their arguments to execute immediately following import 
	 * and prior to analyzing an imported program.  If import not performed,
	 * these scripts will execute once prior to any post-scripts.
	 * 
	 * @param preScripts list of script names/script argument pairs
	 */
	public void setPreScriptsWithArgs(List<Pair<String, String[]>> preScripts) {
		this.preScripts = preScripts;
		this.preScriptFileMap = null;
	}

	/**
	 * Set the ordered list of scripts to execute immediately following import and
	 * and analysis of a program.  If import not performed,
	 * these scripts will execute once following any pre-scripts.
	 * 
	 * @param postScripts list of script names
	 */
	public void setPostScripts(List<String> postScripts) {
		List<Pair<String, String[]>> postScriptsEmptyArgs = new LinkedList<>();
		for (String postScript : postScripts) {
			postScriptsEmptyArgs.add(new Pair<>(postScript, new String[0]));
		}
		setPostScriptsWithArgs(postScriptsEmptyArgs);
	}

	/**
	 * Set the ordered list of scripts to execute immediately following import and
	 * and analysis of a program.  If import not performed,
	 * these scripts will execute once following any pre-scripts.
	 * 
	 * @param postScripts list of script names/script argument pairs
	 */
	public void setPostScriptsWithArgs(List<Pair<String, String[]>> postScripts) {
		this.postScripts = postScripts;
		this.postScriptFileMap = null;
	}

	/**
	 * Set the script source directories to be searched for secondary scripts.
	 * The default set of enabled script directories within the Ghidra installation 
	 * will be appended to the specified list of newPaths.
	 * Individual Paths may be constructed relative to Ghidra installation directory,
	 * User home directory, or absolute system paths.  Examples:
	 * <pre>
	 *     Path.GHIDRA_HOME + "/Ghidra/Features/Base/ghidra_scripts"
	 *     Path.USER_HOME + "/Ghidra/Features/Base/ghidra_scripts"
	 *     "/shared/ghidra_scripts"
	 * </pre>
	 * 
	 * @param newPaths list of directories to be searched.
	 */
	public void setScriptDirectories(List<String> newPaths) {
		scriptPaths = newPaths;
	}

	/**
	 * List of valid script directory paths separated by a ';'.
	 * The default set of enabled script directories within the Ghidra installation 
	 * will be appended to the specified list of newPaths.
	 * Individual Paths may be constructed relative to Ghidra installation directory,
	 * User home directory, or absolute system paths.  Examples:
	 * <pre>
	 * 		Path.GHIDRA_HOME + "/Ghidra/Features/Base/ghidra_scripts"
	 *      Path.USER_HOME + "/Ghidra/Features/Base/ghidra_scripts"
	 *		"/shared/ghidra_scripts"
	 * </pre>
	 * @param paths semicolon (';') separated list of directory paths
	 */
	public void setScriptDirectories(String paths) {
		String[] pathArray = paths.split(";");
		setScriptDirectories(Arrays.asList(pathArray));
	}

	/**
	 * Sets a single location for .properties files associated with GhidraScripts.
	 * 
	 * Typically, .properties files should be located in the same directory as their corresponding 
	 * scripts. However, this method may need to be used when circumstances make it impossible to
	 * have both files in the same directory (i.e., if the scripts are included in ghidra.jar).
	 * 
	 * @param path  location of .properties file(s)
	 */
	public void setPropertiesFileDirectory(String path) {
		propertiesFileStrPaths = new ArrayList<>();
		propertiesFileStrPaths.add(path);
	}

	/**
	 * Sets one or more locations to find .properties files associated with GhidraScripts.
	 * 
	 * Typically, .properties files should be located in the same directory as their corresponding 
	 * scripts. However, this method may need to be used when circumstances make it impossible to
	 * have both files in the same directory (i.e., if the scripts are included in ghidra.jar).
	 * 
	 * @param newPaths  potential locations of .properties file(s)
	 */
	public void setPropertiesFileDirectories(List<String> newPaths) {
		propertiesFileStrPaths = newPaths;
	}

	/**
	 * List of valid .properties file directory paths, separated by a ';'.
	 * 
	 * Typically, .properties files should be located in the same directory as their corresponding 
	 * scripts. However, this method may need to be used when circumstances make it impossible to
	 * have both files in the same directory (i.e., if the scripts are included in ghidra.jar).
	 * 
	 * @param paths  String representation of directories (each separated by ';')
	 */
	public void setPropertiesFileDirectories(String paths) {
		String[] pathArray = paths.split(";");
		setPropertiesFileDirectories(Arrays.asList(pathArray));
	}

	/**
	 * During import, the default behavior is to skip the import if a conflict occurs 
	 * within the destination folder.  This method can be used to force the original 
	 * conflicting file to be removed prior to import.
	 * If the pre-existing file is versioned, the commit option must also be
	 * enabled to have the overwrite remove the versioned file.
	 * 
	 * @param enabled if true conflicting domain files will be removed from the 
	 * project prior to importing the new file.
	 */
	public void enableOverwriteOnConflict(boolean enabled) {
		this.overwrite = enabled;
	}

	/**
	 * This method can be used to enable recursive processing of files during
	 * <code>-import</code> or <code>-process</code> modes.  In order for recursive processing of files to
	 * occur, the user must have specified a directory (and not a specific file)
	 * for the Headless Analyzer to import or process.
	 * 
	 * @param enabled  if true, enables recursive processing
	 */
	public void enableRecursiveProcessing(boolean enabled) {
		this.recursive = enabled;
	}

	/**
	 * When readOnly processing is enabled, any changes made by script or analyzers
	 * are discarded when the Headless Analyzer exits.  When used with import mode,
	 * the imported program file will not be saved to the project or repository.
	 * 
	 * @param enabled  if true, enables readOnly processing or import
	 */
	public void enableReadOnlyProcessing(boolean enabled) {
		this.readOnly = enabled;
	}

	/**
	 * Set project delete flag which allows temporary projects created
	 * to be deleted upon completion.  This option has no effect if a 
	 * Ghidra URL or an existing project was specified.  This option
	 * will be assumed when importing with the readOnly option enabled.
	 * 
	 * @param enabled if true a created project will be deleted when 
	 * processing is complete.
	 */
	public void setDeleteCreatedProjectOnClose(boolean enabled) {
		this.deleteProject = enabled;
	}

	/**
	 * Auto-analysis is enabled by default following import.  This method can be
	 * used to change the enablement of auto-analysis.
	 * 
	 * @param enabled True if auto-analysis should be enabled; otherwise, false.
	 */
	public void enableAnalysis(boolean enabled) {
		this.analyze = enabled;
	}

	/**
	 * Sets the language and compiler spec from the provided input. Any null value will attempt
	 * a "best-guess" if possible.
	 * 
	 * @param languageId The language to set.
	 * @param compilerSpecId The compiler spec to set.
	 * @throws InvalidInputException if the language and compiler spec combination is not valid.
	 */
	public void setLanguageAndCompiler(String languageId, String compilerSpecId)
			throws InvalidInputException {
		if (languageId == null && compilerSpecId == null) {
			return;
		}
		if (languageId == null) {
			throw new InvalidInputException("Compiler spec specified without specifying language.");
		}
		try {
			language =
				DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
			if (compilerSpecId == null) {
				compilerSpec = language.getDefaultCompilerSpec();
			}
			else {
				compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(compilerSpecId));
			}
		}
		catch (LanguageNotFoundException e) {
			language = null;
			compilerSpec = null;
			throw new InvalidInputException("Unsupported language: " + languageId);
		}
		catch (CompilerSpecNotFoundException e) {
			language = null;
			compilerSpec = null;
			throw new InvalidInputException("Compiler spec \"" + compilerSpecId +
				"\" is not supported for language \"" + languageId + "\"");
		}
	}

	/**
	 * Set analyzer timeout on a per-file basis.
	 * 
	 * @param stringInSecs  timeout value in seconds (as a String)
	 * @throws InvalidInputException if the timeout value was not a valid value
	 */
	public void setPerFileAnalysisTimeout(String stringInSecs) throws InvalidInputException {
		try {
			perFileTimeout = Integer.parseInt(stringInSecs);
		}
		catch (NumberFormatException nfe) {
			throw new InvalidInputException(
				"'" + stringInSecs + "' is not a valid integer representation.");
		}
	}

	public void setPerFileAnalysisTimeout(int secs) {
		perFileTimeout = secs;
	}

	/**
	 * Set Ghidra Server client credentials to be used with "shared" projects.
	 * 
	 * @param userID optional userId to use if server permits the user to use
	 * a userId which differs from the process owner name.
	 * @param keystorePath file path to keystore file containing users private key
	 * to be used with PKI or SSH based authentication.
	 * @param allowPasswordPrompt if true the user may be prompted for passwords
	 * via the console (stdin).  Please note that the Java console will echo 
	 * the password entry to the terminal which may be undesirable.
	 * @throws IOException if an error occurs while opening the specified keystorePath.
	 */
	public void setClientCredentials(String userID, String keystorePath,
			boolean allowPasswordPrompt) throws IOException {
		this.connectUserID = userID;
		this.keystore = keystorePath;
		this.allowPasswordPrompt = allowPasswordPrompt;
		HeadlessClientAuthenticator.installHeadlessClientAuthenticator(userID, keystorePath,
			allowPasswordPrompt);
	}

	/**
	 * Enable committing of processed files to the repository which backs the specified
	 * project.
	 * 
	 * @param commit if true imported files will be committed
	 * @param comment optional comment to use when committing
	 */
	public void setCommitFiles(boolean commit, String comment) {
		this.commit = commit;
		this.commitComment = comment;
	}

	public void setOkToDelete(boolean deleteOk) {
		okToDelete = deleteOk;
	}

	/**
	 * Sets the maximum number of cpu cores to use during headless processing. 
	 * 
	 * @param cpu The maximum number of cpu cores to use during headless processing.
	 *     Setting it to 0 or a negative integer is equivalent to setting it to 1.
	 */
	public void setMaxCpu(int cpu) {
		this.maxcpu = cpu;
		System.setProperty("cpu.core.limit", Integer.toString(cpu));

	}

	/**
	 * Sets the loader to use for imports, as well as any loader-specific arguments.  A null loader 
	 * will attempt "best-guess" if possible.  Loader arguments are not supported if a "best-guess"
	 * is made.
	 * 
	 * @param loaderName The name (simple class name) of the loader to use.
	 * @param loaderArgs A list of loader-specific arguments.  Could be null if there are none.
	 * @throws InvalidInputException if an invalid loader name was specified, or if loader arguments
	 *   were specified but a loader was not.
	 */
	public void setLoader(String loaderName, List<Pair<String, String>> loaderArgs)
			throws InvalidInputException {
		if (loaderName != null) {
			this.loaderClass = LoaderService.getLoaderClassByName(loaderName);
			if (this.loaderClass == null) {
				throw new InvalidInputException("Invalid loader name specified: " + loaderName);
			}
			this.loaderArgs = loaderArgs;
		}
		else {
			if (loaderArgs != null && loaderArgs.size() > 0) {
				throw new InvalidInputException(
					"Loader arguments defined without a loader being specified.");
			}
			this.loaderClass = null;
			this.loaderArgs = null;
		}
	}
}
