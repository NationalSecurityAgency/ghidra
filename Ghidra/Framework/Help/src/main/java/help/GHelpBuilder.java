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
package help;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import help.validator.*;
import help.validator.links.InvalidLink;
import help.validator.location.HelpModuleCollection;

/**
 * A class to build help for an entire 'G' application.  This class will take in a list of
 * module paths and build the help for each module.  To build single modules, call this class
 * with only one module path.
 * <p>
 * Note: Help links must not be absolute.  They can be relative, including <code>. and ..</code>
 * syntax.  Further, they can use the special help system syntax, which is:
 * <ul>
 * 	<li><code><b>help/topics/</b>topicName/Filename.html</code> for referencing help topic files
 *  <li><code><b>help/</b>shared/image.png</code> for referencing image files at paths rooted under
 *                                            the module's root help dir
 * </ul>
 */
public class GHelpBuilder {
	private static final String TOC_OUTPUT_FILE_APPENDIX = "_TOC.xml";
	private static final String MAP_OUTPUT_FILE_APPENDIX = "_map.xml";
	private static final String HELP_SET_OUTPUT_FILE_APPENDIX = "_HelpSet.hs";
	private static final String HELP_SEARCH_DIRECTORY_APPENDIX = "_JavaHelpSearch";

	private static final String OUTPUT_DIRECTORY_OPTION = "-o";
	private static final String MODULE_NAME_OPTION = "-n";
	private static final String HELP_PATHS_OPTION = "-hp";
	private static final String DEBUG_SWITCH = "-debug";
	private static final String IGNORE_INVALID_SWITCH = "-ignoreinvalid";

	private String outputDirectoryName;
	private String moduleName;
	private Collection<File> dependencyHelpPaths = new LinkedHashSet<File>();
	private Collection<File> helpInputDirectories = new LinkedHashSet<File>();
	private static boolean debugEnabled = false;
	private boolean ignoreInvalid = false; // TODO: Do actual validation here

	boolean exitOnError = false;
	boolean failed = false;

	public static void main(String[] args) throws Exception {
		GHelpBuilder builder = new GHelpBuilder();
		builder.exitOnError = true;

		ApplicationConfiguration config = new ApplicationConfiguration();
		Application.initializeApplication(new GhidraApplicationLayout(), config);

		builder.build(args);
	}

	void build(String[] args) {
		parseArguments(args);

		HelpModuleCollection allHelp = collectAllHelp();
		LinkDatabase linkDatabase = new LinkDatabase(allHelp);

		debug("Validating help directories...");
		Results results = validateHelpDirectories(allHelp, linkDatabase);
		if (results.failed()) {
			String message = "Found invalid help:\n" + results.getMessage();
			if (ignoreInvalid) {
				printErrorMessage(message);
			}
			else {
				exitWithError(message, null);
			}
		}
		debug("\tfinished validating help directories");

		debug("Building JavaHelp output files...");
		buildJavaHelpFiles(linkDatabase);
		debug("\tfinished building output files");
	}

	private HelpModuleCollection collectAllHelp() {
		List<File> allHelp = new ArrayList<File>(helpInputDirectories);
		for (File file : dependencyHelpPaths) {
			allHelp.add(file);
		}
		return HelpModuleCollection.fromFiles(allHelp);
	}

	private Results validateHelpDirectories(HelpModuleCollection help, LinkDatabase linkDatabase) {

		JavaHelpValidator validator = new JavaHelpValidator(moduleName, help);
		validator.setDebugEnabled(debugEnabled);

		Collection<InvalidLink> invalidLinks = validator.validate(linkDatabase);
		Collection<DuplicateAnchorCollection> duplicateAnchors = linkDatabase.getDuplicateAnchors();

		// report the results
		if (invalidLinks.size() == 0 && duplicateAnchors.size() == 0) {
			// everything is valid!
			return new Results("Finished validating help files--all valid!", false);
		}

		// flush the output stream so our error reporting is not mixed with the previous output
		flush();

		StringBuilder buildy = new StringBuilder();
		if (invalidLinks.size() > 0) {
			//@formatter:off
			buildy.append('[').append(JavaHelpValidator.class.getSimpleName()).append(']');
			buildy.append(" - Found the following ").append(invalidLinks.size()).append(" invalid links:\n");
			for (InvalidLink invalidLink : invalidLinks) {
				buildy.append("Module ").append(moduleName).append(" - ").append(invalidLink);
				buildy.append('\n').append("\n");
			}
			//@formatter:on
		}

		if (duplicateAnchors.size() > 0) {
			//@formatter:off
			buildy.append('[').append(JavaHelpValidator.class.getSimpleName()).append(']');
			buildy.append(" - Found the following ").append(duplicateAnchors.size()).append(" topic(s) with duplicate anchor definitions:\n");
			for (DuplicateAnchorCollection collection : duplicateAnchors) {
				buildy.append(collection).append('\n').append("\n");
			}
			//@formatter:on
		}

		return new Results(buildy.toString(), true);
	}

	private void buildJavaHelpFiles(LinkDatabase linkDatabase) {

		Path outputDirectory = Paths.get(outputDirectoryName);
		JavaHelpFilesBuilder fileBuilder =
			new JavaHelpFilesBuilder(outputDirectory, moduleName, linkDatabase);

		HelpModuleCollection help = HelpModuleCollection.fromFiles(helpInputDirectories);

		// 1) Generate JavaHelp files for the module (e.g., TOC file, map file)
		try {
			fileBuilder.generateHelpFiles(help);
		}
		catch (Exception e) {
			exitWithError("Unexpected error building help module files:\n", e);
		}

		// 2) Generate the help set file for the module
		Path helpSetFile = outputDirectory.resolve(moduleName + HELP_SET_OUTPUT_FILE_APPENDIX);
		Path helpMapFile = outputDirectory.resolve(moduleName + MAP_OUTPUT_FILE_APPENDIX);
		Path helpTOCFile = outputDirectory.resolve(moduleName + TOC_OUTPUT_FILE_APPENDIX);
		Path indexerOutputDirectory =
			outputDirectory.resolve(moduleName + HELP_SEARCH_DIRECTORY_APPENDIX);

		JavaHelpSetBuilder helpSetBuilder = new JavaHelpSetBuilder(moduleName, helpMapFile,
			helpTOCFile, indexerOutputDirectory, helpSetFile);
		try {
			helpSetBuilder.writeHelpSetFile();
		}
		catch (IOException e) {
			exitWithError("\tError building helpset for module: " + moduleName + "\n", e);
		}
	}

	private void exitWithError(String message, Throwable t) {
		failed = true;

		// this prevents error messages getting interspursed with output messages
		flush();

		if (!exitOnError) {
			// the test environment does not want to exit, so just print the error, even though
			// it may appear in the incorrect order with the builder's output messages
			System.err.println(message);
			if (t != null) {
				t.printStackTrace(System.err);
			}
			return;
		}

		// Unusual Code Alert!: If we print the error right away, sometimes the System.out
		// data has not yet been flushed.  Using a thread, with a sleep seems to work.
		PrintErrorRunnable runnable = new PrintErrorRunnable(message, t);
		Thread thread = new Thread(runnable);
		thread.setDaemon(false);
		thread.start();

		try {
			thread.join(2000);
		}
		catch (InterruptedException e) {
			// just exit
		}

		System.exit(1);
	}

	private static class PrintErrorRunnable implements Runnable {

		private String message;
		private Throwable t;

		PrintErrorRunnable(String message, Throwable t) {
			this.message = message;
			this.t = t;
		}

		@Override
		public void run() {
			try {
				Thread.sleep(250);
			}
			catch (InterruptedException e) {
				// don't care
			}

			System.err.println(message);
			if (t != null) {
				t.printStackTrace(System.err);
			}

		}
	}

	private static void flush() {
		System.out.flush();
		System.out.println();
		System.out.flush();
		System.err.flush();
		System.err.println();
		System.err.flush();
	}

	private static void debug(String string) {
		if (debugEnabled) {
			flush();
			System.out.println("[" + GHelpBuilder.class.getSimpleName() + "] " + string);
		}
	}

	private void parseArguments(String[] args) {

		for (int i = 0; i < args.length; i++) {
			String opt = args[i];
			if (opt.equals(OUTPUT_DIRECTORY_OPTION)) {
				i++;
				if (i >= args.length) {
					errorMessage(OUTPUT_DIRECTORY_OPTION + " requires an argument");
					printUsage();
					System.exit(1);
				}
				outputDirectoryName = args[i];
			}
			else if (opt.equals(MODULE_NAME_OPTION)) {
				i++;
				if (i >= args.length) {
					errorMessage(MODULE_NAME_OPTION + " requires an argument");
					printUsage();
					System.exit(1);
				}
				moduleName = args[i];
			}
			else if (opt.equals(HELP_PATHS_OPTION)) {
				i++;
				if (i >= args.length) {
					errorMessage(HELP_PATHS_OPTION + " requires an argument");
					printUsage();
					System.exit(1);
				}
				String hp = args[i];
				if (hp.length() > 0) {
					for (String p : hp.split(File.pathSeparator)) {
						dependencyHelpPaths.add(new File(p));
					}
				}
			}
			else if (opt.equals(DEBUG_SWITCH)) {
				debugEnabled = true;
			}
			else if (opt.equals(IGNORE_INVALID_SWITCH)) {
				ignoreInvalid = true;
			}
			else if (opt.startsWith("-")) {
				errorMessage("Unknown option " + opt);
				printUsage();
				System.exit(1);
			}
			else {
				// It must just be an input
				helpInputDirectories.add(new File(opt));
			}
		}

		HelpBuildUtils.debug = debugEnabled;

		if (helpInputDirectories.size() == 0) {
			errorMessage("Must specify at least one input directory");
			printUsage();
			System.exit(1);
		}
		if (outputDirectoryName == null) {
			errorMessage("Missing output directory: " + OUTPUT_DIRECTORY_OPTION + " [output]");
			printUsage();
			System.exit(1);
		}
		if (moduleName == null) {
			errorMessage("Missing module name: " + MODULE_NAME_OPTION + " [name]");
			printUsage();
			System.exit(1);
		}

	}

	private static void printUsage() {
		StringBuilder buffy = new StringBuilder();
		// TODO: Complete this once the options are stable

		buffy.append("Usage: ");
		buffy.append(GHelpBuilder.class.getName()).append(" [-options] [inputs...]\n");
		buffy.append("          (to build help for a Ghidra module)\n");
		buffy.append("where options include:\n");
		buffy.append("    ").append(OUTPUT_DIRECTORY_OPTION).append(" <output directory>\n");
		buffy.append(
			"                  REQUIRED to specify the output location of the built help\n");
		buffy.append("    ").append(DEBUG_SWITCH).append("        to enable debugging output\n");
		buffy.append("    ").append(IGNORE_INVALID_SWITCH).append("\n");
		buffy.append("                  to continue despite broken links and anchors\n");

		errorMessage(buffy.toString());
	}

	private static void warningMessage(String... message) {
		StringBuilder buffy = new StringBuilder();
		buffy.append("\n");
		buffy.append("              !!!!!     WARNING     !!!!!\n");
		for (String string : message) {
			buffy.append('\t').append('\t').append(string).append('\n');
		}
		buffy.append("\n");
		errorMessage(buffy.toString());
	}

	private static void printErrorMessage(String message) {
		// this prevents error messages getting interspersed with output messages
		flush();
		errorMessage(message);
	}

	private static void errorMessage(String message) {
		errorMessage(message, null);
	}

	private static void errorMessage(String message, Throwable t) {
		try {
			// give the output thread a chance to finish it's output (this is a workaround for
			// the Eclipse editor, and its use of two threads in its console).
			Thread.sleep(250);
		}
		catch (InterruptedException e) {
			// don't care; we tried
		}

		System.err.println("[" + GHelpBuilder.class.getSimpleName() + "] " + message);
		if (t != null) {
			t.printStackTrace();
		}

		flush();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class Results {
		private final String message;

		private final boolean failed;

		Results(String message, boolean failed) {
			this.message = message;
			this.failed = failed;
		}

		String getMessage() {
			return message;
		}

		@Override
		public String toString() {
			return getMessage();
		}

		boolean failed() {
			return failed;
		}
	}
}
