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
package ghidra.pcodeCPort.slgh_compile;

import java.io.*;
import java.util.*;

import org.antlr.runtime.RecognitionException;
import org.jdom.JDOMException;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * <code>SleighCompileLauncher</code> Sleigh compiler launch provider
 */
public class SleighCompileLauncher implements GhidraLaunchable {

	public static final String FILE_IN_DEFAULT_EXT = ".slaspec";
	public static final String FILE_OUT_DEFAULT_EXT = ".sla";
	private static final FileFilter SLASPEC_FILTER =
		pathname -> pathname.getName().endsWith(".slaspec");

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args)
			throws JDOMException, IOException, RecognitionException {

		// Initialize the application
		ApplicationConfiguration configuration = new ApplicationConfiguration();
		Application.initializeApplication(layout, configuration);

		System.exit(runMain(args));
	}

	/**
	 * Execute the Sleigh compiler process
	 * 
	 * @param args sleigh compiler command line arguments
	 * @return exit code (TODO: exit codes are not well defined)
	 * @throws JDOMException for XML errors
	 * @throws IOException for file access errors
	 * @throws RecognitionException for parse errors
	 */
	public static int runMain(String[] args)
			throws JDOMException, IOException, RecognitionException {
		int retval;
		String filein = null;
		String fileout = null;
		Map<String, String> preprocs = new HashMap<>();

		SleighCompile.yydebug = false;
		boolean allMode = false;

		if (args.length < 1) {
			// @formatter:off
			Msg.info(SleighCompile.class, "Usage: sleigh [options...] [<infile.slaspec> [<outfile.sla>] | -a <directory-path>]");
			Msg.info(SleighCompile.class, "    sleigh [options...] <infile.slaspec> [<outfile.sla>]");
			Msg.info(SleighCompile.class, "       <infile.slaspec>   source slaspec file to be compiled");
			Msg.info(SleighCompile.class, "       <outfile.sla>      optional output sla file (infile.sla assumed)");
			Msg.info(SleighCompile.class, "  or");
			Msg.info(SleighCompile.class, "    sleigh [options...] -a <directory-path>");
			Msg.info(SleighCompile.class, "       <directory-path>   directory to have all slaspec files compiled");
			Msg.info(SleighCompile.class, "  options:");
			Msg.info(SleighCompile.class, "   -x                turns on parser debugging");
			Msg.info(SleighCompile.class, "   -u                print warnings for unnecessary pcode instructions");
			Msg.info(SleighCompile.class, "   -l                report pattern conflicts");
			Msg.info(SleighCompile.class, "   -n                print warnings for all NOP constructors");
			Msg.info(SleighCompile.class, "   -t                print warnings for dead temporaries");
			Msg.info(SleighCompile.class, "   -e                enforce use of 'local' keyword for temporaries");
			Msg.info(SleighCompile.class, "   -c                print warnings for all constructors with colliding operands");
			Msg.info(SleighCompile.class, "   -f                print warnings for unused token fields");
			Msg.info(SleighCompile.class, "   -o                print warnings for temporaries which are too large");
			Msg.info(SleighCompile.class,  "  -s                treat register names as case sensitive");
			Msg.info(SleighCompile.class, "   -DNAME=VALUE      defines a preprocessor macro NAME with value VALUE (option may be repeated)");
			Msg.info(SleighCompile.class, "   -dMODULE          defines a preprocessor macro MODULE with a value of its module path (option may be repeated)");
			Msg.info(SleighCompile.class, "   -i <options-file> inject options from specified file");
			// @formatter:on
			return 2;
		}

		boolean unnecessaryPcodeWarning = false;
		boolean lenientConflict = true;
		boolean allCollisionWarning = false;
		boolean allNopWarning = false;
		boolean deadTempWarning = false;
		boolean enforceLocalKeyWord = false;
		boolean unusedFieldWarning = false;
		boolean largeTemporaryWarning = false;
		boolean caseSensitiveRegisterNames = false;

		int i;
		for (i = 0; i < args.length; ++i) {
			if (args[i].charAt(0) != '-') {
				break;
			}
			else if (args[i].charAt(1) == 'i') {
				// inject options from file specified by next argument
				args = injectOptionsFromFile(args, ++i);
				if (args == null) {
					return 1;
				}
			}
			else if (args[i].charAt(1) == 'D') {
				String preproc = args[i].substring(2);
				int pos = preproc.indexOf('=');
				if (pos == -1) {
					Msg.error(SleighCompile.class, "Bad sleigh option: " + args[i]);
					return 1;
				}
				String name = preproc.substring(0, pos);
				String value = preproc.substring(pos + 1);
				preprocs.put(name, value); // Preprocessor macro definitions
			}
			else if (args[i].charAt(1) == 'd') {
				String moduleName = args[i].substring(2);
				ResourceFile module = Application.getModuleRootDir(moduleName);
				if (module == null || !module.isDirectory()) {
					Msg.error(SleighCompile.class,
						"Failed to resolve module reference: " + args[i]);
					return 1;
				}
				Msg.debug(SleighCompile.class,
					"Sleigh resolved module: " + moduleName + "=" + module.getAbsolutePath());
				preprocs.put(moduleName, module.getAbsolutePath()); // Preprocessor macro definitions
			}
			else if (args[i].charAt(1) == 'u') {
				unnecessaryPcodeWarning = true;
			}
			else if (args[i].charAt(1) == 't') {
				deadTempWarning = true;
			}
			else if (args[i].charAt(1) == 'e') {
				enforceLocalKeyWord = true;
			}
			else if (args[i].charAt(1) == 'f') {
				unusedFieldWarning = true;
			}
			else if (args[i].charAt(1) == 'l') {
				lenientConflict = false;
			}
			else if (args[i].charAt(1) == 'c') {
				allCollisionWarning = true;
			}
			else if (args[i].charAt(1) == 'n') {
				allNopWarning = true;
			}
			else if (args[i].charAt(1) == 'a') {
				allMode = true;
			}
			else if (args[i].charAt(1) == 'o') {
				largeTemporaryWarning = true;
			}
			else if (args[i].charAt(1) == 's') {
				caseSensitiveRegisterNames = true;
			}
			else if (args[i].charAt(1) == 'x') {
				SleighCompile.yydebug = true; // Debug option
			}
			else {
				Msg.error(SleighCompile.class, "Unknown option: " + args[i]);
				return 1;
			}
		}

		if (i < args.length - 2) {
			Msg.error(SleighCompile.class, "Too many parameters");
			return 1;
		}

		if (allMode) {
			if (i == args.length) {
				Msg.error(SleighCompile.class, "Missing input directory path");
				return 1;
			}
			String directory = args[i];
			File dir = new File(directory);
			if (!dir.exists() || !dir.isDirectory()) {
				Msg.error(SleighCompile.class, directory + " is not a directory");
				return 1;
			}
			TreeSet<String> failures = new TreeSet<>();
			int totalFailures = 0;
			int totalSuccesses = 0;
			DirectoryVisitor visitor = new DirectoryVisitor(dir, SLASPEC_FILTER);
			for (File input : visitor) {
				System.out.println("Compiling " + input + ":");
				SleighCompile compiler = new SleighCompile();
				compiler.setAllOptions(preprocs, unnecessaryPcodeWarning, lenientConflict,
					allCollisionWarning, allNopWarning, deadTempWarning, unusedFieldWarning,
					enforceLocalKeyWord, largeTemporaryWarning, caseSensitiveRegisterNames);

				String outname = input.getName().replace(".slaspec", ".sla");
				File output = new File(input.getParent(), outname);
				retval =
					compiler.run_compilation(input.getAbsolutePath(), output.getAbsolutePath());
				System.out.println();
				if (retval != 0) {
					++totalFailures;
					failures.add(input.getAbsolutePath());
				}
				else {
					++totalSuccesses;
				}
			}
			System.out.println(totalSuccesses + " languages successfully compiled");
			if (totalFailures != 0) {
				for (String path : failures) {
					System.out.println(path + " failed to compile");
				}
				System.out.println(totalFailures + " languages total failed to compile");
			}
			return -totalFailures;
		}

		// single file compile
		SleighCompile compiler = new SleighCompile();
		compiler.setAllOptions(preprocs, unnecessaryPcodeWarning, lenientConflict,
			allCollisionWarning, allNopWarning, deadTempWarning, unusedFieldWarning,
			enforceLocalKeyWord, largeTemporaryWarning, caseSensitiveRegisterNames);
		if (i == args.length) {
			Msg.error(SleighCompile.class, "Missing input file name");
			return 1;
		}

		filein = args[i];
		if (i < args.length - 1) {
			fileout = args[i + 1];
		}

		String baseName = filein;
		if (filein.toLowerCase().endsWith(FILE_IN_DEFAULT_EXT)) {
			baseName = filein.substring(0, filein.length() - FILE_IN_DEFAULT_EXT.length());
		}
		filein = baseName + FILE_IN_DEFAULT_EXT;

		String baseOutName = fileout;
		if (fileout == null) {
			baseOutName = baseName;
		}
		else if (fileout.toLowerCase().endsWith(FILE_OUT_DEFAULT_EXT)) {
			baseOutName = fileout.substring(0, fileout.length() - FILE_OUT_DEFAULT_EXT.length());
		}
		fileout = baseOutName + FILE_OUT_DEFAULT_EXT;

		return compiler.run_compilation(filein, fileout);
	}

	private static String[] injectOptionsFromFile(String[] args, int index) {
		if (index >= args.length) {
			Msg.error(SleighCompile.class, "Missing options input file name");
			return null;
		}

		File optionsFile = new File(args[index]);
		if (!optionsFile.isFile()) {
			Msg.error(SleighCompile.class,
				"Options file not found: " + optionsFile.getAbsolutePath());
			if (SystemUtilities.isInDevelopmentMode()) {
				Msg.error(SleighCompile.class,
					"Eclipse language module must be selected and 'gradle prepdev' prevously run");
			}
			return null;
		}
		ArrayList<String> list = new ArrayList<>();
		for (int i = 0; i <= index; i++) {
			list.add(args[i]);
		}

		try (BufferedReader r = new BufferedReader(new FileReader(optionsFile))) {
			String option = r.readLine();
			while (option != null) {
				option = option.trim();
				if (option.length() != 0 && !option.startsWith("#")) {
					list.add(option);
				}
				option = r.readLine();
			}
		}
		catch (IOException e) {
			Msg.error(SleighCompile.class,
				"Reading options file failed (" + optionsFile.getName() + "): " + e.getMessage());
			return null;
		}

		for (int i = index + 1; i < args.length; i++) {
			list.add(args[i]);
		}
		return list.toArray(new String[list.size()]);
	}

}
