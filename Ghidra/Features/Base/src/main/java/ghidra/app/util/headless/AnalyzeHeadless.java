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

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.util.*;

import generic.stl.Pair;
import ghidra.*;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.protocol.ghidra.Handler;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.InvalidInputException;

/**
 * Launcher entry point for running headless Ghidra.
 */
public class AnalyzeHeadless implements GhidraLaunchable {

	/**
	 * Headless command line arguments.
	 * <p>
	 * NOTE: Please update 'analyzeHeadlessREADME.html' if changing command line parameters
	 */
	private enum Arg {
		//@formatter:off
		IMPORT("-import", true, "[<directory>|<file>]+"),
		PROCESS("-process", true, "[<project_file>]"),
		PRE_SCRIPT("-preScript", true, "<ScriptName>"),
		POST_SCRIPT("-postScript", true, "<ScriptName>"),
		SCRIPT_PATH("-scriptPath", true, "\"<path1>[;<path2>...]\""),
		PROPERTIES_PATH("-propertiesPath", true, "\"<path1>[;<path2>...]\""),
		SCRIPT_LOG("-scriptlog", true, "<path to script log file>"),
		LOG("-log", true, "<path to log file>"),
		OVERWRITE("-overwrite", false),
		RECURSIVE("-recursive", false),
		READ_ONLY("-readOnly", false),
		DELETE_PROJECT("-deleteProject", false),
		NO_ANALYSIS("-noanalysis", false),
		PROCESSOR("-processor", true, "<languageID>"),
		CSPEC("-cspec", true, "<compilerSpecID>"),
		ANALYSIS_TIMEOUT_PER_FILE("-analysisTimeoutPerFile", true, "<timeout in seconds>"),
		KEYSTORE("-keystore", true, "<KeystorePath>"),
		CONNECT("-connect", false, "[<userID>]"),
		PASSWORD("-p", false),
		COMMIT("-commit", false, "[\"<comment>\"]]"),
		OK_TO_DELETE("-okToDelete", false),
		MAX_CPU("-max-cpu", true, "<max cpu cores to use>"),
		LIBRARY_SEARCH_PATHS("-librarySearchPaths", true, "<path1>[;<path2>...]"),
		LOADER(Loader.COMMAND_LINE_ARG_PREFIX, true, "<desired loader name>"),
		LOADER_ARGS(Loader.COMMAND_LINE_ARG_PREFIX + "-", true, "<loader argument value>") {
			@Override
			public boolean matches(String arg) {
				return arg.startsWith(Loader.COMMAND_LINE_ARG_PREFIX + "-");
			}
		};
		//@formatter:on

		private String name;
		private boolean requiresSubArgs;
		private String subArgFormat;

		private Arg(String name, boolean requiresSubArgs, String subArgFormat) {
			this.name = name;
			this.requiresSubArgs = requiresSubArgs;
			this.subArgFormat = subArgFormat;
		}

		private Arg(String name, boolean requiresSubArgs) {
			this(name, requiresSubArgs, "");
		}

		public String usage() {
			return "%s%s%s".formatted(name, subArgFormat.isEmpty() ? "" : " ", subArgFormat);
		}

		public boolean matches(String arg) {
			return arg.equalsIgnoreCase(name);
		}

		@Override
		public String toString() {
			return name;
		}
	}

	private static final int EXIT_CODE_ERROR = 1;

	/**
	 * The entry point of 'analyzeHeadless.bat'. Parses the command line arguments to the script
	 * and takes the appropriate headless actions.
	 * 
	 * @param args Detailed list of arguments is in 'analyzeHeadlessREADME.html'
	 */
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		String projectName = null;
		String rootFolderPath = null;
		URL ghidraURL = null;
		List<File> filesToImport = new ArrayList<>();
		int optionStartIndex;

		// Make sure there are arguments
		if (args.length < 1) {
			usage();
		}

		// Ghidra URL handler registration
		Handler.registerHandler();

		if (args[0].startsWith("ghidra:")) {
			optionStartIndex = 1;
			try {
				ghidraURL = new URI(args[0]).toURL();
			}
			catch (MalformedURLException e) {
				System.err.println("Invalid Ghidra URL: " + args[0]);
				usage();
			}
		}
		else {
			if (args.length < 2) {
				usage();
			}
			optionStartIndex = 2;
			String projectNameAndFolder = args[1];

			// Check to see if projectName uses back-slashes (likely if they are using Windows)
			projectNameAndFolder = projectNameAndFolder.replaceAll("\\\\", DomainFolder.SEPARATOR);
			projectName = projectNameAndFolder;

			rootFolderPath = "/";
			int folderIndex = projectNameAndFolder.indexOf(DomainFolder.SEPARATOR);
			if (folderIndex == 0) {
				System.err.println(args[1] + " is an invalid project_name/folder_path.");
				usage();
			}
			else if (folderIndex > 0) {
				projectName = projectNameAndFolder.substring(0, folderIndex);
				rootFolderPath = projectNameAndFolder.substring(folderIndex);
			}
		}

		// Determine the desired logging.
		File logFile = null;
		File scriptLogFile = null;
		for (int argi = optionStartIndex; argi < args.length; argi++) {
			if (checkArgument(Arg.LOG, args, argi)) {
				logFile = new File(args[++argi]);
			}
			else if (checkArgument(Arg.SCRIPT_LOG, args, argi)) {
				scriptLogFile = new File(args[++argi]);
			}
		}

		// Instantiate new headless analyzer and parse options.
		// NOTE: The application may already be initialized if this is being called 
		// from an integration test
		HeadlessAnalyzer analyzer = null;
		if (Application.isInitialized()) {
			analyzer = HeadlessAnalyzer.getInstance();
		}
		else {
			analyzer = HeadlessAnalyzer.getLoggableInstance(logFile, scriptLogFile, true);
		}
		HeadlessOptions options = analyzer.getOptions();
		parseOptions(options, args, optionStartIndex, ghidraURL, filesToImport);

		Msg.info(AnalyzeHeadless.class,
			"Headless startup complete (" + GhidraLauncher.getMillisecondsFromLaunch() + " ms)");
		ClassSearcher.logStatistics();

		// Do the headless processing
		try {
			if (ghidraURL != null) {
				analyzer.processURL(ghidraURL, filesToImport);
			}
			else {
				analyzer.processLocal(args[0], projectName, rootFolderPath, filesToImport);
			}
		}
		catch (Throwable e) {
			Msg.error(HeadlessAnalyzer.class,
				"Abort due to Headless analyzer error: " + e.getMessage(), e);
			System.exit(EXIT_CODE_ERROR);
		}
	}

	/**
	 * Parses the command line arguments and uses them to set the headless options.
	 * 
	 * @param options The headless options to set.
	 * @param args The command line arguments to parse.
	 * @param startIndex The index into the args array of where to start parsing.
	 * @param ghidraURL The ghidra server url to connect to, or null if not using a url.
	 * @param filesToImport A list to put files to import into.
	 * @throws InvalidInputException if an error occurred parsing the arguments or setting
	 *         the options.
	 */
	private void parseOptions(HeadlessOptions options, String[] args, int startIndex, URL ghidraURL,
			List<File> filesToImport) throws InvalidInputException {

		String loaderName = null;
		List<Pair<String, String>> loaderArgs = new LinkedList<>();
		String languageId = null;
		String compilerSpecId = null;
		String keystorePath = null;
		String userId = null;
		boolean allowPasswordPrompt = false;
		List<Pair<String, String[]>> preScripts = new LinkedList<>();
		List<Pair<String, String[]>> postScripts = new LinkedList<>();

		for (int argi = startIndex; argi < args.length; argi++) {

			String arg = args[argi];
			if (checkArgument(Arg.LOG, args, argi)) {
				// Already processed
				argi++;
			}
			else if (checkArgument(Arg.SCRIPT_LOG, args, argi)) {
				// Already processed
				argi++;
			}
			else if (checkArgument(Arg.OVERWRITE, args, argi)) {
				options.enableOverwriteOnConflict(true);
			}
			else if (checkArgument(Arg.NO_ANALYSIS, args, argi)) {
				options.enableAnalysis(false);
			}
			else if (checkArgument(Arg.DELETE_PROJECT, args, argi)) {
				options.setDeleteCreatedProjectOnClose(true);
			}
			else if (checkArgument(Arg.LOADER, args, argi)) {
				loaderName = args[++argi];
			}
			else if (checkArgument(Arg.LOADER_ARGS, args, argi)) {
				if (isExistingArg(args[argi + 1])) {
					throw new InvalidInputException(args[argi] + " expects value to follow.");
				}
				loaderArgs.add(new Pair<>(arg, args[++argi]));
			}
			else if (checkArgument(Arg.PROCESSOR, args, argi)) {
				languageId = args[++argi];
			}
			else if (checkArgument(Arg.CSPEC, args, argi)) {
				compilerSpecId = args[++argi];
			}
			else if (checkArgument(Arg.PRE_SCRIPT, args, argi)) {
				String scriptName = args[++argi];
				String[] scriptArgs = getSubArguments(args, argi);
				argi += scriptArgs.length;
				preScripts.add(new Pair<>(scriptName, scriptArgs));
			}
			else if (checkArgument(Arg.POST_SCRIPT, args, argi)) {
				String scriptName = args[++argi];
				String[] scriptArgs = getSubArguments(args, argi);
				argi += scriptArgs.length;
				postScripts.add(new Pair<>(scriptName, scriptArgs));
			}
			else if (checkArgument(Arg.SCRIPT_PATH, args, argi)) {
				options.setScriptDirectories(args[++argi]);
			}
			else if (checkArgument(Arg.PROPERTIES_PATH, args, argi)) {
				options.setPropertiesFileDirectories(args[++argi]);
			}
			else if (checkArgument(Arg.IMPORT, args, argi)) {
				File inputFile = null;
				try {
					inputFile = new File(args[++argi]);
					inputFile = inputFile.getCanonicalFile();
				}
				catch (IOException e) {
					throw new InvalidInputException(
						"Failed to get canonical form of: " + inputFile);
				}
				if (!inputFile.isDirectory() && !inputFile.isFile()) {
					throw new InvalidInputException(
						inputFile + " is not a valid directory or file.");
				}

				HeadlessAnalyzer.checkValidFilename(inputFile.toString());

				filesToImport.add(inputFile);

				// Keep checking for OS-expanded files
				String nextArg;

				while (argi < (args.length - 1)) {
					nextArg = args[++argi];

					// Check if next argument is a parameter
					if (isExistingArg(nextArg)) {
						argi--;
						break;
					}

					File otherFile = new File(nextArg).getAbsoluteFile();
					if (!otherFile.isFile() && !otherFile.isDirectory()) {
						throw new InvalidInputException(
							otherFile + " is not a valid directory or file.");
					}

					HeadlessAnalyzer.checkValidFilename(otherFile.toString());

					filesToImport.add(otherFile);
				}
			}
			else if (checkArgument(Arg.CONNECT, args, argi)) {
				if ((argi + 1) < args.length) {
					arg = args[argi + 1];
					if (!isExistingArg(arg)) {
						// serverUID is optional argument after -connect
						userId = arg;
						++argi;
					}
				}
			}
			else if (checkArgument(Arg.COMMIT, args, argi)) {
				String comment = null;
				if ((argi + 1) < args.length) {
					arg = args[argi + 1];
					if (!isExistingArg(arg)) {
						// commit is optional argument after -commit
						comment = arg;
						++argi;
					}
				}
				options.setCommitFiles(true, comment);
			}
			else if (checkArgument(Arg.KEYSTORE, args, argi)) {
				keystorePath = args[++argi];
				File keystore = new File(keystorePath);
				if (!keystore.isFile()) {
					throw new InvalidInputException(
						keystore.getAbsolutePath() + " is not a valid keystore file.");
				}
			}
			else if (checkArgument(Arg.PASSWORD, args, argi)) {
				allowPasswordPrompt = true;
			}
			else if (checkArgument(Arg.ANALYSIS_TIMEOUT_PER_FILE, args, argi)) {
				options.setPerFileAnalysisTimeout(args[++argi]);
			}
			else if (checkArgument(Arg.PROCESS, args, argi)) {
				if (options.runScriptsNoImport) {
					throw new InvalidInputException(
						"The -process option may only be specified once.");
				}
				String processBinary = null;
				if ((argi + 1) < args.length) {
					arg = args[argi + 1];
					if (!isExistingArg(arg)) {
						// processBinary is optional argument after -process
						processBinary = arg;
						++argi;
					}
				}
				options.setRunScriptsNoImport(true, processBinary);
			}
			else if (checkArgument(Arg.RECURSIVE, args, argi)) {
				Integer depth = null;
				if ((argi + 1) < args.length) {
					arg = args[argi + 1];
					if (!isExistingArg(arg)) {
						// depth is optional argument after -recursive
						try {
							depth = Integer.parseInt(arg);
						}
						catch (NumberFormatException e) {
							throw new InvalidInputException("Invalid recursion depth: " + depth);
						}
						++argi;
					}
				}
				options.enableRecursiveProcessing(true, depth);
			}
			else if (checkArgument(Arg.READ_ONLY, args, argi)) {
				options.enableReadOnlyProcessing(true);
			}
			else if (checkArgument(Arg.MAX_CPU, args, argi)) {
				String cpuVal = args[++argi];
				try {
					options.setMaxCpu(Integer.parseInt(cpuVal));
				}
				catch (NumberFormatException nfe) {
					throw new InvalidInputException("Invalid value for max-cpu: " + cpuVal);
				}
			}
			else if (checkArgument(Arg.OK_TO_DELETE, args, argi)) {
				options.setOkToDelete(true);
			}
			else if (checkArgument(Arg.LIBRARY_SEARCH_PATHS, args, argi)) {
				LibrarySearchPathManager.setLibraryPaths(args[++argi].split(";"));
			}
			else if (isExistingArg(args[argi])) {
				throw new AssertionError("Valid option was not processed: " + args[argi]);
			}
			else {
				throw new InvalidInputException("Bad argument: " + arg);
			}
		}

		// Set up pre and post scripts
		options.setPreScriptsWithArgs(preScripts);
		options.setPostScriptsWithArgs(postScripts);

		// Set loader and loader args
		options.setLoader(loaderName);
		options.setLoaderArgs(loaderArgs);

		// Set user-specified language and compiler spec
		options.setLanguageAndCompiler(languageId, compilerSpecId);

		// Set up optional Ghidra Server authenticator
		try {
			options.setClientCredentials(userId, keystorePath, allowPasswordPrompt);
		}
		catch (IOException e) {
			throw new InvalidInputException(
				"Failed to install Ghidra Server authenticator: " + e.getMessage());
		}

		// If -process was specified, inputFiles must be null or inputFiles.size must be 0.
		// Otherwise when not in -process mode, inputFiles can be null or inputFiles.size can be 0,
		// only if there are scripts to be run.
		if (options.runScriptsNoImport) {

			if (filesToImport != null && filesToImport.size() > 0) {
				System.err.print("Must use either -process or -import parameters, but not both.");
				System.err.print(" -process runs scripts over existing program(s) in a project, " +
					"whereas -import");
				System.err.println(" imports new programs and runs scripts and/or analyzes them " +
					"after import.");
				System.exit(EXIT_CODE_ERROR);
			}

			if (options.overwrite) {
				Msg.warn(HeadlessAnalyzer.class,
					"The -overwrite parameter does not apply to -process mode.  Ignoring overwrite " +
						"and continuing.");
			}

			if (options.readOnly && options.okToDelete) {
				System.err.println("You have specified the conflicting parameters -readOnly and " +
					"-okToDelete. Please pick one and try again.");
				System.exit(EXIT_CODE_ERROR);
			}
		}
		else {
			if (filesToImport == null || filesToImport.size() == 0) {
				if (options.preScripts.isEmpty() && options.postScripts.isEmpty()) {
					System.err.println("Nothing to do ... must specify -import, -process, or " +
						"prescript and/or postscript.");
					System.exit(EXIT_CODE_ERROR);
				}
				else {
					Msg.warn(HeadlessAnalyzer.class,
						"Neither the -import parameter nor the -process parameter was specified; " +
							"therefore, the specified prescripts and/or postscripts will be " +
							"executed without any type of program context.");
				}
			}
		}

		if (options.commit) {
			if (options.readOnly) {
				System.err.println("Can not use -commit and -readOnly at the same time.");
				System.exit(EXIT_CODE_ERROR);
			}
		}

		// Implied commit, only if not in process mode
		if (!options.commit && ghidraURL != null) {
			if (!options.readOnly) {
				// implied commit
				options.setCommitFiles(true, null);
			}
			else {
				Msg.warn(HeadlessAnalyzer.class,
					"-readOnly mode is on: for -process, changes will not be saved.");
			}
		}
	}

	/**
	 * Prints out the usage details and exits the Java application with an exit code that
	 * indicates error.
	 * 
	 * @param execCmd the command used to run the headless analyzer from the calling method.
	 */
	public static void usage(String execCmd) {
		StringBuilder sb = new StringBuilder();
		final String INDENT = "           ";
		
		sb.append("Headless Analyzer Usage: %s\n".formatted(execCmd));
		sb.append(INDENT + "<project_location> <project_name>[/<folder_path>]\n");
		sb.append(INDENT + "  | ghidra://<server>[:<port>]/<repository_name>[/<folder_path>]\n");
		for (Arg arg : Arg.values()) {
			switch (arg) {
				case IMPORT -> {
					// Can't use both IMPORT and PROCESS, so must handle the usage a little
					// differently
					sb.append(
						INDENT + "[[%s] | [%s]]\n".formatted(arg.usage(), Arg.PROCESS.usage()));
				}
				case PROCESS -> {
					// Handled above by IMPORT
				}
				case LOADER_ARGS -> {
					// Loader args are a little different because we don't know the full
					// argument name ahead of time...just what it starts with
					sb.append(INDENT + "[%s<loader argument name> %s]\n"
							.formatted(Arg.LOADER_ARGS.name, Arg.LOADER_ARGS.subArgFormat));
				}
				default -> {
					sb.append(INDENT + "[%s]\n".formatted(arg.usage()));
				}
			}
		}

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.WINDOWS) {
			sb.append("\n");
			sb.append(
				"     - All uses of $GHIDRA_HOME or $USER_HOME in script path must be" +
					" preceded by '\\'\n");
		}
		sb.append("\n");
		sb.append(
			"Please refer to 'analyzeHeadlessREADME.html' for detailed usage examples " +
				"and notes.\n");

		sb.append("\n");
		System.out.println(sb);
		System.exit(EXIT_CODE_ERROR);
	}

	private void usage() {
		usage("analyzeHeadless");
	}

	private String[] getSubArguments(String[] args, int argi) {
		List<String> subArgs = new ArrayList<>();
		int i = argi + 1;
		while (i < args.length && !isExistingArg(args[i])) {
			subArgs.add(args[i++]);
		}
		return subArgs.toArray(new String[subArgs.size()]);
	}

	private boolean checkArgument(Arg arg, String[] args, int argi)
			throws InvalidInputException {
		if (!arg.matches(args[argi])) {
			return false;
		}
		if (arg.requiresSubArgs && argi + 1 == args.length) {
			throw new InvalidInputException(args[argi] + " requires an argument");
		}
		return true;
	}

	private boolean isExistingArg(String s) {
		return Arrays.stream(Arg.values()).anyMatch(e -> e.matches(s));
	}
}
