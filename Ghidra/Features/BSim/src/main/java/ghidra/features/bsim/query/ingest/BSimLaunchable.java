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
package ghidra.features.bsim.query.ingest;

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.xml.sax.SAXException;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.protocol.ExeSpecifier;
import ghidra.features.bsim.query.protocol.QueryName;
import ghidra.framework.*;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.HeadlessClientAuthenticator;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.net.SSLContextInitializer;
import ghidra.program.database.ProgramDB;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;

public class BSimLaunchable implements GhidraLaunchable {

	private static final String BSIM_LOGGING_CONFIGURATION_FILE = "bsim.log4j.xml";

	private static final int DEFAULT_LIST_EXE_LIMIT = 20;

	private static final Set<String> COMMAND_SET = new HashSet<>();

	private static String defineCommand(String command) {
		COMMAND_SET.add(command);
		return command;
	}

	/**
	 * bsim commands
	 */
	private static final String COMMAND_CREATE_DATABASE = defineCommand("createdatabase");
	private static final String COMMAND_SET_METADATA = defineCommand("setmetadata");
	private static final String COMMAND_ADD_EXE_CATEGORY = defineCommand("addexecategory");
	private static final String COMMAND_ADD_FUNCTION_TAG = defineCommand("addfunctiontag");
	private static final String COMMAND_DROP_INDEX = defineCommand("dropindex");
	private static final String COMMAND_REBUILD_INDEX = defineCommand("rebuildindex");
	private static final String COMMAND_PREWARM = defineCommand("prewarm");
	private static final String COMMAND_GENERATE_SIGS = defineCommand("generatesigs");
	private static final String COMMAND_COMMIT_SIGS = defineCommand("commitsigs");
	private static final String COMMAND_GENERATE_UPDATES = defineCommand("generateupdates");
	private static final String COMMAND_COMMIT_UPDATES = defineCommand("commitupdates");
	private static final String COMMAND_DELETE = defineCommand("delete");
	private static final String COMMAND_LIST_FUNCTIONS = defineCommand("listfuncs");
	private static final String COMMAND_LIST_EXES = defineCommand("listexes");
	private static final String COMMAND_GET_EXE_COUNT = defineCommand("getexecount");
	private static final String COMMAND_DUMP_SIGS = defineCommand("dumpsigs");

	private static Set<String> COMMANDS_WITH_REPO_ACCESS =
		Set.of(COMMAND_GENERATE_SIGS, COMMAND_GENERATE_UPDATES);

	// Options that require a value argument
	private static final String BSIM_URL_OPTION = "--bsim";
	private static final String NAME_OPTION = "--name";
	private static final String OWNER_OPTION = "--owner";
	private static final String DESCRIPTION_OPTION = "--description";
	private static final String OVERRIDE_OPTION = "--override";
	private static final String CONFIG_OPTION = "--config";
	private static final String MD5_OPTION = "--md5";
	private static final String MAX_FUNC_OPTION = "--maxfunc";
	private static final String ARCH_OPTION = "--arch";
	private static final String COMPILER_OPTION = "--compiler";
	private static final String LIMIT_OPTION = "--limit";
	private static final String SORT_COL_OPTION = "--sortcol";

	// Global options that require a value argument
	private static final String USER_OPTION = "--user";
	private static final String CERT_OPTION = "--cert";

	// Define set of options that require a second value argument
	private static final Set<String> VALUE_OPTIONS =
		Set.of(USER_OPTION, CERT_OPTION, BSIM_URL_OPTION, NAME_OPTION, OWNER_OPTION,
			DESCRIPTION_OPTION, OVERRIDE_OPTION, CONFIG_OPTION, MD5_OPTION, MAX_FUNC_OPTION,
			ARCH_OPTION, COMPILER_OPTION, LIMIT_OPTION, SORT_COL_OPTION);

	private static final Set<String> GLOBAL_OPTIONS = Set.of(CERT_OPTION, USER_OPTION);

	// Boolean options
	private static final String COMMIT_OPTION = "--commit";
	private static final String CATEGORY_DATE_OPTION = "--date";
	private static final String NO_CALLGRAPH_OPTION = "--nocallgraph";
	private static final String OVERWRITE_OPTION = "--overwrite";
	private static final String INCLUDE_LIBS_OPTION = "--includelibs";
	private static final String PRINT_SELF_SIGNIFICANCE_OPTION = "--printselfsig";
	private static final String CALL_GRAPH_OPTION = "--callgraph";
	private static final String PRINT_JUST_EXE_OPTION = "--printjustexe";

	private static final Map<String, String> SHORTCUT_OPTION_MAP = new HashMap<>();
	static {
		SHORTCUT_OPTION_MAP.put("-a", ARCH_OPTION);
		SHORTCUT_OPTION_MAP.put("-b", BSIM_URL_OPTION);
		SHORTCUT_OPTION_MAP.put("-c", CONFIG_OPTION);
		SHORTCUT_OPTION_MAP.put("-d", DESCRIPTION_OPTION);
		SHORTCUT_OPTION_MAP.put("-l", LIMIT_OPTION);
		SHORTCUT_OPTION_MAP.put("-m", MD5_OPTION);
		SHORTCUT_OPTION_MAP.put("-n", NAME_OPTION);
		SHORTCUT_OPTION_MAP.put("-o", OWNER_OPTION);
		SHORTCUT_OPTION_MAP.put("-s", SORT_COL_OPTION);
		SHORTCUT_OPTION_MAP.put("-u", USER_OPTION);
		//SHORTCUT_OPTION_MAP.put("", OVERRIDE_OPTION);
		//SHORTCUT_OPTION_MAP.put("", MAX_FUNC_OPTION);
		//SHORTCUT_OPTION_MAP.put("", COMPILER_OPTION);
		//SHORTCUT_OPTION_MAP.put("", CERT_OPTION);
	}

	//@formatter:off
	// Populate ALLOWED_OPTION_MAP for each command
	private static final Set<String> CREATE_DATABASE_OPTIONS = 
			Set.of(NAME_OPTION, OWNER_OPTION, DESCRIPTION_OPTION, NO_CALLGRAPH_OPTION);
	private static final Set<String> COMMIT_SIGS_OPTIONS = 
			Set.of(OVERRIDE_OPTION, MD5_OPTION); // url requires override param
	private static final Set<String> COMMIT_UPDATES_OPTIONS = Set.of();
	private static final Set<String> DELETE_OPTIONS = 
			Set.of(MD5_OPTION, NAME_OPTION, ARCH_OPTION, COMPILER_OPTION); // one or more params required
	private static final Set<String> DROP_INDEX_OPTIONS = Set.of();
	private static final Set<String> REBUILD_INDEX_OPTIONS = Set.of();
	private static final Set<String> PREWARM_OPTIONS = Set.of();
	private static final Set<String> SET_METADATA_OPTIONS = 
			Set.of(NAME_OPTION, OWNER_OPTION, DESCRIPTION_OPTION);
	private static final Set<String> ADD_EXE_CATEGORY_OPTIONS = Set.of(CATEGORY_DATE_OPTION);
	private static final Set<String> ADD_FUNCTION_TAG_OPTIONS = Set.of();
	private static final Set<String> DUMP_SIGS_OPTIONS = 
			Set.of(MD5_OPTION, NAME_OPTION, ARCH_OPTION, COMPILER_OPTION); 
	private static final Set<String> GENERATE_SIGS_OPTIONS = 
			Set.of(CONFIG_OPTION, BSIM_URL_OPTION, OVERWRITE_OPTION, COMMIT_OPTION); // config OR bsimURL
	private static final Set<String> GENERATE_UPDATES_OPTIONS = 
			Set.of(CONFIG_OPTION, BSIM_URL_OPTION, OVERWRITE_OPTION, COMMIT_OPTION); // config OR bsimURL
	private static final Set<String> LIST_FUNCTIONS_OPTIONS = 
			Set.of(MD5_OPTION, NAME_OPTION, ARCH_OPTION, COMPILER_OPTION, PRINT_SELF_SIGNIFICANCE_OPTION, CALL_GRAPH_OPTION, PRINT_JUST_EXE_OPTION, MAX_FUNC_OPTION);
	private static final Set<String> GET_EXECUTABLES_OPTIONS = 
			Set.of(MD5_OPTION, NAME_OPTION, ARCH_OPTION, COMPILER_OPTION, SORT_COL_OPTION, INCLUDE_LIBS_OPTION);
	private static final Set<String> GET_EXECUTABLES_COUNT_OPTIONS = 
			Set.of(MD5_OPTION, NAME_OPTION, ARCH_OPTION, COMPILER_OPTION, INCLUDE_LIBS_OPTION);
	//@formatter:on

	private static final Map<String, Set<String>> ALLOWED_OPTION_MAP = new HashMap<>();
	static {
		ALLOWED_OPTION_MAP.put(COMMAND_CREATE_DATABASE, CREATE_DATABASE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_SET_METADATA, SET_METADATA_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_ADD_EXE_CATEGORY, ADD_EXE_CATEGORY_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_ADD_FUNCTION_TAG, ADD_FUNCTION_TAG_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_DROP_INDEX, DROP_INDEX_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_REBUILD_INDEX, REBUILD_INDEX_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_PREWARM, PREWARM_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_GENERATE_SIGS, GENERATE_SIGS_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_COMMIT_SIGS, COMMIT_SIGS_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_GENERATE_UPDATES, GENERATE_UPDATES_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_COMMIT_UPDATES, COMMIT_UPDATES_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_DELETE, DELETE_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_LIST_FUNCTIONS, LIST_FUNCTIONS_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_LIST_EXES, GET_EXECUTABLES_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_GET_EXE_COUNT, GET_EXECUTABLES_COUNT_OPTIONS);
		ALLOWED_OPTION_MAP.put(COMMAND_DUMP_SIGS, DUMP_SIGS_OPTIONS);
	}

	private URL ghidraURL;
	private URL bsimURL;

	private Map<String, String> optionValueMap = new HashMap<>();
	private Set<String> booleanOptions = new HashSet<>();

	private GhidraApplicationLayout layout;

	/**
	 * Constructor for launching from the console
	 */
	public BSimLaunchable() {
	}

	/**
	 * Clears the parameters that can be used for issuing commands. This is useful
	 * if you want to keep your established database connection and URL settings but
	 * wish to issue a new command.
	 */
	private void clearParams() {
		ghidraURL = null;
		bsimURL = null;
		booleanOptions.clear();
		optionValueMap.clear();
	}

	private BulkSignatures getBulkSignatures()
			throws IllegalArgumentException, MalformedURLException {
		BSimServerInfo serverInfo = null;
		if (bsimURL != null) {
			serverInfo = new BSimServerInfo(bsimURL);
		}
		String connectingUserName = optionValueMap.get(USER_OPTION);
		return new BulkSignatures(serverInfo, connectingUserName);
	}

	private void setupGhidraURL(String ghidraURLString) throws MalformedURLException {

		if (ghidraURLString == null) {
			return;
		}

		if (!GhidraURL.isGhidraURL(ghidraURLString)) {
			throw new MalformedURLException("URL is not ghidra protocol: " + ghidraURLString);
		}
		ghidraURL = new URL(ghidraURLString);
		if (!GhidraURL.isServerRepositoryURL(ghidraURL) &&
			!GhidraURL.isLocalProjectURL(ghidraURL)) {
			throw new MalformedURLException("Invalid repository URL: " + ghidraURLString);
		}
	}

	/**
	 * Establish the URL for the ghidra server and/or the bsim server. At least one string must be non-null
	 * @param ghidraURLString is the URL string for the ghidra server
	 * @param bsimURLString is the URL string for the bsim server
	 * @throws MalformedURLException if there is a problem parsing the given URLs
	 * @throws IllegalArgumentException if unsupported URL use occurs
	 */
	private void setupURLs(String ghidraURLString, String bsimURLString)
			throws MalformedURLException {

		if (ghidraURLString != null) {
			setupGhidraURL(ghidraURLString);
		}

		if (bsimURLString != null) {
			bsimURL = BSimClientFactory.deriveBSimURL(bsimURLString);
			if (ghidraURL == null) {
				if ("file".equals(bsimURL.getProtocol())) {
					throw new IllegalArgumentException(
						"Unable to infer ghidra URL from BSim file DB URL");
				}
				ghidraURLString = "ghidra://" + bsimURL.getHost() + bsimURL.getPath();
				setupGhidraURL(ghidraURLString);
			}
		}
		else if (ghidraURLString != null) {
			bsimURL = BSimClientFactory.deriveBSimURL(ghidraURLString);
		}
	}

	/**
	 * Read in any optional parameters, strip them from the parameter stream
	 * @param command command name
	 * @param params is the original array of command line parameters
	 * @param discard number of params already consumed
	 * @return an array of parameters with optional ones stripped
	 */
	private List<String> readOptions(String command, String[] params, int discard) {

		boolean sawOptions = false;

		Set<String> allowedParams = ALLOWED_OPTION_MAP.get(command);
		if (allowedParams == null) {
			throw new IllegalArgumentException("Unsupported command: " + command);
		}

		List<String> subParams = new ArrayList<String>();
		for (int i = discard; i < params.length; ++i) {
			String optionName = params[i];
			String value = null;

			if (optionName.startsWith("-")) {
				// although not prefered, allow option value to be specified as --option=value
				int ix = optionName.indexOf("=");
				if (ix > 1) {
					value = optionName.substring(ix + 1);
					optionName = optionName.substring(0, ix);
				}
			}

			String option = optionName;

			if (optionName.startsWith("-") && !optionName.startsWith("--")) {
				option = SHORTCUT_OPTION_MAP.get(optionName); // map option to -- long form
				if (option == null) {
					throw new IllegalArgumentException("Unsupported option use: " + optionName);
				}
			}

			if (!option.startsWith("--")) {
				if (sawOptions) {
					throw new IllegalArgumentException("Unexpected argument: " + option);
				}
				subParams.add(params[i]);
				continue;
			}

			sawOptions = true;
			if (!GLOBAL_OPTIONS.contains(option) && !allowedParams.contains(option)) {
				throw new IllegalArgumentException("Unsupported option use: " + optionName);
			}
			if (!VALUE_OPTIONS.contains(option)) {
				// consume option without value arg as a boolean option
				if (value != null) {
					throw new IllegalArgumentException(
						"Unsupported option specification: " + optionName + "=");
				}
				booleanOptions.add(option);
			}
			else if (!StringUtils.isBlank(value)) {
				optionValueMap.put(option, value);
			}
			else {
				// consume next param as option value
				if (++i == params.length) {
					throw new IllegalArgumentException("Missing option value: " + optionName);
				}
				optionValueMap.put(option, params[i]);
			}
		}
		String connectingUserName = optionValueMap.get(USER_OPTION);
		if (connectingUserName == null) {
			connectingUserName = optionValueMap.put(USER_OPTION, ClientUtil.getUserName());
		}
		return subParams;
	}

	private void checkRequiredParam(String[] params, int index, String name) {
		if (params.length <= index) {
			throw new IllegalArgumentException("Missing required parameter: " + name);
		}
		String p = params[index];
		if (p.startsWith("--") || p.contains("=")) {
			throw new IllegalArgumentException(
				"Missing required parameter (" + name + ") before specified option: " + p);
		}
	}

	private Integer parsePositiveIntegerOption(String option) {
		String optionValue = optionValueMap.get(option);
		if (optionValue == null) {
			return null;
		}
		try {
			int value = Integer.valueOf(optionValue);
			if (value < 0) {
				throw new IllegalArgumentException("Negative value not permitted for " + option);
			}
			return value;
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid integer value specified for " + option);
		}
	}

	/**
	 * Runs the command specified by the given set of params.
	 * 
	 * @param params the parameters specifying the command
	 * @param monitor the task monitor
	 * @throws IllegalArgumentException if invalid params have been specified
	 * @throws Exception if there's an error during the operation
	 * @throws CancelledException if processing is cancelled
	 */
	public void run(String[] params, TaskMonitor monitor) throws Exception, CancelledException {

		clearParams();

		checkRequiredParam(params, 0, "command");
		String command = params[0];
		if (!COMMAND_SET.contains(command)) {
			throw new IllegalArgumentException("Missing or invalid command specified");
		}

		checkRequiredParam(params, 1, "URL");
		String urlstring = params[1];

		monitor.setCancelEnabled(true);

		List<String> subParams = readOptions(command, params, 2);

		initializeApplication(command);

		if (COMMAND_CREATE_DATABASE.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doCreateDatabase(subParams);
		}
		else if (COMMAND_SET_METADATA.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doInstallMetadata(subParams);
		}
		else if (COMMAND_ADD_EXE_CATEGORY.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doInstallCategory(subParams);
		}
		else if (COMMAND_ADD_FUNCTION_TAG.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doInstallTags(subParams);
		}
		else if (COMMAND_DROP_INDEX.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doDropIndex(subParams);
		}
		else if (COMMAND_REBUILD_INDEX.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doRebuildIndex(subParams);
		}
		else if (COMMAND_PREWARM.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doPrewarm(subParams);
		}
		else if (COMMAND_GENERATE_SIGS.equals(command)) {
			processSigAndUpdateOptions(urlstring);
			doGenerateSigs(subParams, monitor);
		}
		else if (COMMAND_COMMIT_SIGS.equals(command)) {
			// --override option specified ghidra URL
			String ghidraURLOverride = optionValueMap.get(OVERRIDE_OPTION);
			if (ghidraURLOverride != null) {
				setupURLs(ghidraURLOverride, urlstring);
			}
			else {
				bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			}
			doCommitSigs(subParams, monitor);
		}
		else if (COMMAND_GENERATE_UPDATES.equals(command)) {
			processSigAndUpdateOptions(urlstring);
			doGenerateUpdates(subParams, monitor);
		}
		else if (COMMAND_COMMIT_UPDATES.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doCommitUpdates(subParams);
		}
		else if (COMMAND_DELETE.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doDeleteExecutable(subParams);
		}
		else if (COMMAND_LIST_FUNCTIONS.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doListFunctions(subParams);
		}
		else if (COMMAND_LIST_EXES.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doListExes(subParams);
		}
		else if (COMMAND_GET_EXE_COUNT.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doGetCount(subParams);
		}
		else if (COMMAND_DUMP_SIGS.equals(command)) {
			bsimURL = BSimClientFactory.deriveBSimURL(urlstring);
			doDumpSigs(subParams);
		}
		else {
			throw new IllegalArgumentException("Unknown command: " + command);
		}
	}

	private void processSigAndUpdateOptions(String urlstring) throws MalformedURLException {
		String bsimURLOption = optionValueMap.get(BSIM_URL_OPTION);
		String configOption = optionValueMap.get(CONFIG_OPTION);
		if (configOption != null) {
			if (bsimURLOption != null) {
				throw new IllegalArgumentException(
					BSIM_URL_OPTION + " and " + CONFIG_OPTION + " options may not both be present");
			}
			setupGhidraURL(urlstring);
		}
		else if (bsimURLOption != null) {
			setupURLs(urlstring, bsimURLOption);
		}
		else {
			throw new IllegalArgumentException(
				"Must specify either " + BSIM_URL_OPTION + " or " + CONFIG_OPTION + " option");
		}
	}

	/**
	 * Runs the command specified by the given set of params.
	 * 
	 * @param params the parameters specifying the command
	 * @throws Exception when initializing the application or executing the command
	 */
	public void run(String[] params) throws Exception {
		run(params, TaskMonitor.DUMMY);
	}

	/**
	 * Creates a new BSim database with a given set of properties.
	 * 
	 * @param params the command-line parameters
	 * @throws IOException if there's an error establishing the database connection
	 */
	private void doCreateDatabase(List<String> params) throws IOException {
		if (params.isEmpty()) {
			throw new IllegalArgumentException("Missing database template");
		}
		else if (params.size() > 1) {
			throw new IllegalArgumentException("Unexpected parameter: " + params.get(1));
		}

		String configTemplate = params.get(0);
		boolean noTrackCallGraph = booleanOptions.contains(NO_CALLGRAPH_OPTION);

		String nameOption = optionValueMap.get(NAME_OPTION);
		String ownerOption = optionValueMap.get(OWNER_OPTION);
		String descOption = optionValueMap.get(DESCRIPTION_OPTION);

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.createDatabase(configTemplate, nameOption, ownerOption, descOption,
				!noTrackCallGraph);
		}
	}

	private void doGenerateSigs(List<String> params, TaskMonitor monitor)
			throws Exception, CancelledException {
		// concurrent --bsim and --config option use already checked
		if (params.size() > 1) {
			throw new IllegalArgumentException("Invalid generatesigs parameter use!");
		}
		boolean commitOption = booleanOptions.contains(COMMIT_OPTION);
		boolean overwriteOption = booleanOptions.contains(OVERWRITE_OPTION);
		String configOption = optionValueMap.get(CONFIG_OPTION);

		String xmlDirectory = null;
		if (params.size() == 1) {
			xmlDirectory = params.get(0);
			if (configOption != null && commitOption) {
				throw new IllegalArgumentException(
					"Invalid option use with " + CONFIG_OPTION + " option: " + COMMIT_OPTION);
			}
		}
		else {
			if (overwriteOption) {
				throw new IllegalArgumentException("Invalid option use: " + OVERWRITE_OPTION);
			}
			commitOption = true; // assume DB commit using temp XML directory
		}

		try (BulkSignatures bsim = getBulkSignatures()) {
			if (commitOption) {
				// Generate and commit signatures to BSim database
				bsim.signatureRepo(ghidraURL, xmlDirectory, overwriteOption, monitor);
			}
			else {
				// Generate sig XML files only
				bsim.generateSignaturesFromServer(ghidraURL, xmlDirectory, overwriteOption,
					configOption, monitor);
			}
		}
	}

	private void doGenerateUpdates(List<String> params, TaskMonitor monitor)
			throws Exception, CancelledException {
		// concurrent --bsim and --config option use already checked
		if (params.size() > 1) {
			throw new IllegalArgumentException("Invalid generateupdates parameter use!");
		}
		boolean commitOption = booleanOptions.contains(COMMIT_OPTION);
		boolean overwriteOption = booleanOptions.contains(OVERWRITE_OPTION);
		String configOption = optionValueMap.get(CONFIG_OPTION);

		String xmlDirectory = null;
		if (params.size() == 1) {
			xmlDirectory = params.get(0);
			if (configOption != null && commitOption) {
				throw new IllegalArgumentException(
					"Invalid option use with " + CONFIG_OPTION + " option: " + COMMIT_OPTION);
			}

		}
		else {
			if (overwriteOption) {
				throw new IllegalArgumentException("Invalid option use: " + OVERWRITE_OPTION);
			}
			commitOption = true; // assume DB commit using temp XML directory
		}

		try (BulkSignatures bsim = getBulkSignatures()) {
			if (commitOption) {
				// Generate and commit updates to BSim database
				bsim.updateRepoSignatures(ghidraURL, xmlDirectory, overwriteOption, monitor);
			}
			else {
				// Generate update XML files only
				bsim.generateUpdatesFromServer(ghidraURL, xmlDirectory, overwriteOption,
					configOption, monitor);
			}
		}
	}

	private File checkDirectory(String dirPath) throws IOException {
		File dir = new File(dirPath);
		if (!dir.exists()) {
			throw new IOException("Commit directory does not exist: " + dirPath);
		}
		if (!dir.isDirectory()) {
			throw new IOException(dirPath + ": is not a directory");
		}
		return dir.getCanonicalFile();
	}

	private void doCommitSigs(List<String> params, TaskMonitor monitor)
			throws IOException, SAXException, LSHException, CancelledException {
		if (params.size() < 1) {
			throw new IllegalArgumentException("Missing directory containing signature files");
		}

		String xmlDirectory = params.get(0);

		File dir = checkDirectory(xmlDirectory);

		boolean hasOverride = optionValueMap.containsKey(OVERRIDE_OPTION);
		String md5Filter = optionValueMap.get(MD5_OPTION);

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.sendXmlToQueryServer(dir, hasOverride ? ghidraURL : null, md5Filter, monitor);
		}
	}

	private void doCommitUpdates(List<String> params)
			throws IOException, SAXException, LSHException {
		if (params.size() < 1) {
			throw new IllegalArgumentException("Missing directory containing update files");
		}
		String xmlDirectory = params.get(0);

		File dir = checkDirectory(xmlDirectory);

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.sendUpdateToServer(dir);
		}
	}

	private boolean isAllNull(String... strings) {
		for (String s : strings) {
			if (s != null) {
				return false;
			}
		}
		return true;
	}

	private void fillinSingleExeSpecifier(ExeSpecifier spec) throws IllegalArgumentException {

		String md5Option = optionValueMap.get(MD5_OPTION);
		String nameOption = optionValueMap.get(NAME_OPTION);
		String archOption = optionValueMap.get(ARCH_OPTION);
		String compOption = optionValueMap.get(COMPILER_OPTION);

		if (md5Option != null) {
			if (!isAllNull(nameOption, archOption, compOption)) {
				throw new IllegalArgumentException(
					"The " + NAME_OPTION + ", " + ARCH_OPTION + ", " + COMPILER_OPTION +
						" options are not valid when " + MD5_OPTION + " option is specified.");
			}
			spec.exemd5 = md5Option;
		}
		else if (nameOption != null) {
			spec.exename = nameOption;
			spec.arch = archOption;
			spec.execompname = compOption;
		}
		else {
			throw new IllegalArgumentException(
				"Must specify either " + MD5_OPTION + " or " + NAME_OPTION + " option");
		}
	}

	private void doListFunctions(List<String> params) throws IOException, LSHException {

		Integer maxFunc = parsePositiveIntegerOption(MAX_FUNC_OPTION);

		QueryName query = new QueryName();
		fillinSingleExeSpecifier(query.spec);

		if (maxFunc != null) {
			query.maxfunc = maxFunc;
		}
		if (booleanOptions.contains(PRINT_SELF_SIGNIFICANCE_OPTION)) {
			query.printselfsig = true;
		}
		if (booleanOptions.contains(CALL_GRAPH_OPTION)) {
			query.fillinCallgraph = true;
		}
		if (booleanOptions.contains(PRINT_JUST_EXE_OPTION)) {
			query.printjustexe = true;
		}

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.printFunctions(query, System.out);
		}
	}

	/**
	 * Deletes a specified executable from the database.
	 * 
	 * @param params the command-line parameters
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doDeleteExecutable(List<String> params) throws IOException, LSHException {

		ExeSpecifier spec = new ExeSpecifier();
		fillinSingleExeSpecifier(spec);

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.deleteExecutables(spec);
		}
	}

	/**
	 * Drops the current BSim database index.
	 * 
	 * This variant of the drop index method should be called by
	 * clients using the command-line
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doDropIndex(List<String> params) throws IOException, LSHException {
		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.dropIndex();
		}
	}

	/**
	 * Rebuilds the current BSim database index.
	 * 
	 * This variant of the rebuild index method should be called by
	 * clients using the command-line
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doRebuildIndex(List<String> params) throws IOException, LSHException {
		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.rebuildIndex();
		}
	}

	/**
	 * Performs a prewarm command on the BSim database.
	 * <p>
	 * This is intended for use by command-line clients.
	 * 
	 * @param params the command-line params (empty for this command)
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doPrewarm(List<String> params) throws IOException, LSHException {
		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.prewarm();
		}
	}

	/**
	 * Display list of all executable records meeting a set of search criteria.
	 * Results are written to the output stream
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doListExes(List<String> params) throws IOException, LSHException {

		int limit = DEFAULT_LIST_EXE_LIMIT;
		Integer limitOption = parsePositiveIntegerOption(LIMIT_OPTION);
		if (limitOption != null) {
			limit = limitOption;
		}
		boolean includeLibs = booleanOptions.contains(INCLUDE_LIBS_OPTION);
		String md5Option = optionValueMap.get(MD5_OPTION);
		String nameOption = optionValueMap.get(NAME_OPTION);
		String archOption = optionValueMap.get(ARCH_OPTION);
		String compOption = optionValueMap.get(COMPILER_OPTION);
		String sortColumnOption = optionValueMap.get(SORT_COL_OPTION);

		try (BulkSignatures bsim = getBulkSignatures()) {
			List<ExecutableRecord> exeList = bsim.getExes(limit, md5Option, nameOption, archOption,
				compOption, sortColumnOption, includeLibs);
			for (ExecutableRecord exeRec : exeList) {
				Msg.info(this, exeRec.printRaw());
			}
			String summary = exeList.size() + " executables found";
			if (limit > 0 && limit == exeList.size()) {
				summary += " (results limit reached)";
			}
			Msg.info(this, summary);
		}
	}

	/**
	 * Print the number of records in the database that match the filter criteria.
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doGetCount(List<String> params) throws IOException, LSHException {

		boolean includeFakes = booleanOptions.contains(INCLUDE_LIBS_OPTION);
		String md5Option = optionValueMap.get(MD5_OPTION);
		String nameOption = optionValueMap.get(NAME_OPTION);
		String archOption = optionValueMap.get(ARCH_OPTION);
		String compOption = optionValueMap.get(COMPILER_OPTION);

		try (BulkSignatures bsim = getBulkSignatures()) {
			int count = bsim.getCount(md5Option, nameOption, archOption, compOption, includeFakes);
			System.out.println("Matching executable count: " + count);
		}
	}

	/**
	 * Updates the BSim database metadata with the given values.
	 * 
	 * This variant of the update metadata method is intended for command-line
	 * users. 
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doInstallMetadata(List<String> params) throws IOException, LSHException {

		String nameOption = optionValueMap.get(NAME_OPTION);
		String ownerOption = optionValueMap.get(OWNER_OPTION);
		String descOption = optionValueMap.get(DESCRIPTION_OPTION);

		if (isAllNull(nameOption, ownerOption, descOption)) {
			throw new IllegalArgumentException("Missing one or more metadata options: " +
				NAME_OPTION + ", " + OWNER_OPTION + ", " + DESCRIPTION_OPTION);
		}

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.installMetadata(nameOption, ownerOption, descOption);
		}
	}

	/**
	 * Inserts a new category name into the BSim database. 
	 * 
	 * This variant of the install category method is intended for command-line
	 * users. 
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doInstallCategory(List<String> params) throws IOException, LSHException {
		if (params.size() < 1) {
			throw new IllegalArgumentException("Missing name of new category");
		}
		boolean dateOption = booleanOptions.contains(CATEGORY_DATE_OPTION);

		String categoryName = params.get(0);

		if (params.size() > 1) {
			throw new IllegalArgumentException("Unexpected parameter: " + params.get(1));
		}

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.installCategory(categoryName, dateOption);
		}
	}

	/**
	 * Inserts a new function tag into the BSim database.
	 * 
	 * This variant of the tag install method is intended for command-line
	 * users. 
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doInstallTags(List<String> params) throws IOException, LSHException {
		if (params.size() < 1) {
			throw new IllegalArgumentException("Missing name of new function tag");
		}
		if (params.size() > 1) {
			throw new IllegalArgumentException("Unknown option: " + params.get(1));
		}

		String functionTag = params.get(0);

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.installTags(functionTag);
		}
	}

	/**
	 * Exports exe signature to local folder in XML format.
	 * 
	 * @param params the command-line params
	 * @throws IOException if there's an error establishing the database connection
	 * @throws LSHException if there's an error issuing the query
	 */
	private void doDumpSigs(List<String> params) throws IOException, LSHException {
		if (params.size() < 1) {
			throw new IllegalArgumentException("Must specify an output directory");
		}
		File resultFolder = new File(params.get(0));

		QueryName query = new QueryName();
		fillinSingleExeSpecifier(query.spec);
		query.maxfunc = 0; // all functions

		try (BulkSignatures bsim = getBulkSignatures()) {
			bsim.doDumpSigs(resultFolder, query);
		}
	}

	private static void printMaxMemory() {
		// division is used since default case may not use even multiples of 1024
		long maxMemoryBytes = Runtime.getRuntime().maxMemory();
		float maxMem = maxMemoryBytes / (1024 * 1024); // MBytes
		String units = " MBytes";
		if (maxMem >= 1024) {
			maxMem /= 1024;
			units = " GBytes";
		}
		String maxMemStr = String.format("%.1f", maxMem);
		if (maxMemStr.endsWith(".0")) {
			// don't show .0
			maxMemStr = maxMemStr.substring(0, maxMemStr.length() - 2);
		}
		System.out.println("Max-Memory: " + maxMemStr + units);
	}

	private static void printUsage() {
		//@formatter:off
		System.err.println("\n" +
			"USAGE: bsim [command]       required-args... [OPTIONS...]\n" + 
			"            createdatabase  <bsimURL> <config_template> [--name|-n \"<name>\"] [--owner|-o \"<owner>\"] [--description|-d \"<text>\"] [--nocallgraph]\n" + 
			"            setmetadata     <bsimURL> [--name|-n \"<name>\"] [--owner|-o \"<owner>\"] [--description|-d \"<text>\"]\n" + 
			"            addexecategory  <bsimURL> <category_name> [--date]\n" + 
			"            addfunctiontag  <bsimURL> <tag_name>\n" +  
			"            dropindex       <bsimURL>\n" + 
			"            rebuildindex    <bsimURL>\n" + 
			"            prewarm         <bsimURL>\n" + 
			"            generatesigs    <ghidraURL> </xmldirectory> --config|-c <config_template> [--overwrite]\n" + 
			"            generatesigs    <ghidraURL> </xmldirectory> --bsim|-b <bsimURL> [--commit] [--overwrite]\n" + 
			"            generatesigs    <ghidraURL> --bsim|-b <bsimURL>\n" + 
			"            commitsigs      <bsimURL> </xmldirectory> [--md5|-m <hash>] [--override <ghidraURL>]\n" + 
			"            generateupdates <ghidraURL> </xmldirectory> --config|-c <config_template> [--overwrite]\n" + 
			"            generateupdates <ghidraURL> </xmldirectory> --bsim|-b <bsimURL> [--commit] [--overwrite]\n" + 
			"            generateupdates <ghidraURL> --bsim|-b <bsimURL>\n" +  
			"            commitupdates   <bsimURL> </xmldirectory>\n" + 
			"            listexes        <bsimURL> [--md5|-m <hash>] [--name|-n <exe_name>] [--arch|-a <languageID>] [--compiler <cspecID>] [--sortcol|-s md5|name] [--limit|-l <exe_count>] [--includelibs]\n" + 
			"            getexecount     <bsimURL> [--md5|-m <hash>] [--name|-n <exe_name>] [--arch|-a <languageID>] [--compiler <cspecID>] [--includelibs]\n" + 
			"            delete          <bsimURL> [--md5|-m <hash>] [--name|-n <exe_name> [--arch|-a <languageID>] [--compiler <cspecID>]]\n" + 
			"            listfuncs       <bsimURL> [--md5|-m <hash>] [--name|-n <exe_name> [--arch|-a <languageID>] [--compiler <cspecID>]] [--printselfsig] [--callgraph] [--printjustexe] [--maxfunc <max_count>]\n" + 
			"            dumpsigs        <bsimURL> </xmldirectory> [--md5|-m <hash>] [--name|-n <exe_name> [--arch|-a <languageID>] [--compiler <cspecID>]]\n" + 
			"\n" +
			"Global options:\n" +
			"    --user|-u <username>\n" +
			"    --cert </certfile-path>\n" +
			"\n" +
			"Enumerated Options:\n" +
			"    <config_template> - large_32 | medium_32 | medium_64 | medium_cpool | medium_nosize \n" +
			"\n" +
			"BSim URL Forms (bsimURL):\n" +
			"    postgresql://<hostname>[:<port>]/<dbname>\n" +
			"    elastic://<hostname>[:<port>]/<dbname>\n" +
			"    https://<hostname>[:<port>]/<dbname>\n" +
			"    file:/[<local-dirpath>/]<dbname>\n" +
			"\n" +
			"Ghidra URL Forms (ghidraURL):\n" +
			"    ghidra://<hostname>[:<port>]/<repo-name>[/<folder-path>]\n" +
			"    ghidra:/[<local-dirpath>/]<project-name>[?/<folder-path>]\n" +
			"\n" +
			"NOTE: Options with values may also be specified using the form: --option=value\n");
		//@formatter:on
	}

	@Override
	public void launch(GhidraApplicationLayout ghidraLayout, String[] params) {

		printMaxMemory();

		if (params.length == 0) {
			printUsage();
			return;
		}

		layout = ghidraLayout;

		try {
			run(params);
		}
		catch (MalformedURLException e) {
			Msg.error(this, "Invalid URL specified: " + e.getMessage());
			System.exit(22); // EINVAL
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, e.getMessage());
			System.out.println("Execute \"bsim\" without arguments to display usage details");
			System.exit(22); // EINVAL
		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
			System.exit(1); // Misc Error
		}
	}

	private void initializeApplication(String command) throws IOException {
		int initType = COMMANDS_WITH_REPO_ACCESS.contains(command) ? 2 : 1;
		if (layout != null) {

			String connectingUserName = optionValueMap.get(USER_OPTION);
			String certOption = optionValueMap.get(CERT_OPTION);

			initializeApplication(layout, initType, connectingUserName, certOption);
		}
	}

	/**
	 * From a cold start, initialize the Ghidra application to different stages, based on future requirements
	 * @param layout application layout
	 * @param type is an integer indicating how much to initialize
	 *          0 - limited initialization, enough simple execution and logging
	 *          1 - full initialization of ghidra for module path info and initialization
	 *          2 - same as #1 with class search for extensions
	 * @param connectingUserName default user name for server connections
	 * @param certPath PKI certificate path
	 * @throws IOException if there is a problem initializing the headless authenticator
	 */
	public static void initializeApplication(ApplicationLayout layout, int type,
			String connectingUserName, String certPath) throws IOException {
		if (Application.isInitialized()) {
			return;
		}

		/**
		 * Ensure that we are running in "headless mode"
		 */
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.TRUE.toString());

		try {
			URL configFileUrl =
				BSimLaunchable.class.getClassLoader().getResource(BSIM_LOGGING_CONFIGURATION_FILE);
			System.setProperty(LoggingInitialization.LOG4J2_CONFIGURATION_PROPERTY,
				configFileUrl.toURI().toString());
		}
		catch (URISyntaxException e) {
			System.err.println("ERROR: " + e.getMessage());
		}

		ApplicationConfiguration config;
		switch (type) {
			case 2:
				// application support with class searching and extensions (e.g., ContentHandler)
				config = new HeadlessGhidraApplicationConfiguration();
				break;

			case 1:
				// application support without class searching and extensions
				config = new HeadlessBSimApplicationConfiguration();
				break;

			default:
				// Setup application with minimal application support
				config = new ApplicationConfiguration();
		}

		Application.initializeApplication(layout, config);

		SSLContextInitializer.initialize();
		ghidra.framework.protocol.ghidra.Handler.registerHandler();
		ghidra.features.bsim.query.postgresql.Handler.registerHandler();

		HeadlessClientAuthenticator.installHeadlessClientAuthenticator(connectingUserName, certPath,
			true);
	}
}
