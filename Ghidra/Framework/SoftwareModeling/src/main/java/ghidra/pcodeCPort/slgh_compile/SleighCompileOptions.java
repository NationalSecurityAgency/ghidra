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

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguageFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

/**
 * Represents the options the sleigh compiler uses
 */
public class SleighCompileOptions {
	public File inputFile;
	public File outputFile;
	public boolean allMode = false;
	public File allDir;

	public Map<String, String> preprocs = new HashMap<>();
	public boolean unnecessaryPcodeWarning = false;
	public boolean lenientConflict = true;
	public boolean allCollisionWarning = false;
	public boolean allNopWarning = false;
	public boolean deadTempWarning = false;
	public boolean enforceLocalKeyWord = false;
	public boolean unusedFieldWarning = false;
	public boolean caseSensitiveRegisterNames = false;
	public boolean debugOutput = false;

	public static void usage() {
		// @formatter:off
		Msg.info(SleighCompileOptions.class, "Usage: sleigh [options...] [<infile.slaspec> [<outfile.sla>] | -a <directory-path>]");
		Msg.info(SleighCompileOptions.class, "    sleigh [options...] <infile.slaspec> [<outfile.sla>]");
		Msg.info(SleighCompileOptions.class, "       <infile.slaspec>   source slaspec file to be compiled");
		Msg.info(SleighCompileOptions.class, "       <outfile.sla>      optional output sla file (infile.sla assumed)");
		Msg.info(SleighCompileOptions.class, "  or");
		Msg.info(SleighCompileOptions.class, "    sleigh [options...] -a <directory-path>");
		Msg.info(SleighCompileOptions.class, "       <directory-path>   directory to have all slaspec files compiled");
		Msg.info(SleighCompileOptions.class, "  options:");
		Msg.info(SleighCompileOptions.class, "   -x                turns on parser debugging");
		Msg.info(SleighCompileOptions.class, "   -y                write .sla using XML debug format");
		Msg.info(SleighCompileOptions.class, "   -u                print warnings for unnecessary pcode instructions");
		Msg.info(SleighCompileOptions.class, "   -l                report pattern conflicts");
		Msg.info(SleighCompileOptions.class, "   -n                print warnings for all NOP constructors");
		Msg.info(SleighCompileOptions.class, "   -t                print warnings for dead temporaries");
		Msg.info(SleighCompileOptions.class, "   -e                enforce use of 'local' keyword for temporaries");
		Msg.info(SleighCompileOptions.class, "   -c                print warnings for all constructors with colliding operands");
		Msg.info(SleighCompileOptions.class, "   -f                print warnings for unused token fields");
		Msg.info(SleighCompileOptions.class,  "  -s                treat register names as case sensitive");
		Msg.info(SleighCompileOptions.class, "   -DNAME=VALUE      defines a preprocessor macro NAME with value VALUE (option may be repeated)");
		Msg.info(SleighCompileOptions.class, "   -dMODULE          defines a preprocessor macro MODULE with a value of its module path (option may be repeated)");
		Msg.info(SleighCompileOptions.class, "   -i <options-file> inject options from specified file");
		// @formatter:on
	}

	/**
	 * Evaluates an array of string arguments and saves the values into a {@link SleighCompileOptions}
	 * instance.
	 * 
	 * @param args array of arg strings
	 * @return new {@link SleighCompileOptions} instance
	 * @throws SleighException if error in an argument
	 */
	public static SleighCompileOptions parse(String[] args) throws SleighException {

		SleighCompileOptions results = new SleighCompileOptions();

		Deque<String> argList = new ArrayDeque<>(List.of(args));
		while (!argList.isEmpty()) {
			if (!argList.peekFirst().startsWith("-")) {
				break;
			}
			String arg = argList.removeFirst();
			if (arg.isBlank()) {
				continue;
			}
			results.processArg(arg, argList);
		}

		if (!results.allMode) {
			// Process trailing source and destination filename parameters
			if (argList.isEmpty()) {
				Msg.error(SleighCompileOptions.class, "Missing input file name");
				throw new SleighException("Missing input file name");
			}

			results.inputFile = new File(argList.removeFirst()).getAbsoluteFile();
			results.outputFile =
				!argList.isEmpty() ? new File(argList.removeFirst()).getAbsoluteFile() : null;

			String baseName = results.inputFile.getName();
			if (baseName.toLowerCase().endsWith(SleighLanguageFile.SLASPEC_EXT)) {
				baseName = FilenameUtils.getBaseName(baseName);
			}
			else {
				results.inputFile = new File(results.inputFile.getParentFile(),
					results.inputFile.getName() + SleighLanguageFile.SLASPEC_EXT);
			}

			if (results.outputFile == null) {
				results.outputFile = new File(results.inputFile.getParentFile(),
					baseName + SleighLanguageFile.SLA_EXT);
			}
			else if (!results.outputFile.getName()
					.toLowerCase()
					.endsWith(SleighLanguageFile.SLA_EXT)) {
				results.outputFile = new File(results.outputFile.getParentFile(),
					results.outputFile.getName() + SleighLanguageFile.SLA_EXT);
			}
		}

		if (!argList.isEmpty()) {
			Msg.error(SleighCompileOptions.class, "Too many parameters: " + argList.toString());
			throw new SleighException("Too many parameters: " + argList.toString());
		}


		return results;
	}

	/**
	 * Evaluates the arguments in a sleighArgs.txt file and returns a {@link SleighCompileOptions} 
	 * 
	 * @param argsFile file containing an argument per line
	 * @return {@link SleighCompileOptions}
	 */
	public static SleighCompileOptions fromFile(File argsFile) {
		SleighCompileOptions results = new SleighCompileOptions();

		Deque<String> argList = new ArrayDeque<>(getOptionsFromFile(argsFile));
		while (!argList.isEmpty()) {
			String arg = argList.removeFirst();
			if (arg.isBlank()) {
				continue;
			}
			if (!arg.startsWith("-")) {
				break;
			}
			results.processArg(arg, argList);
		}
		return results;
	}

	public void addPreprocessorMacroDefinition(String name, String value) {
		preprocs.put(name, value); // Preprocessor macro definitions
	}

	private void processArg(String arg, Deque<String> argList) {
		if (arg.length() < 2 || arg.charAt(0) != '-') {
			throw new SleighException("Invalid argument: " + arg);
		}
		switch (arg.charAt(1)) {
			case 'i':
				// inject options from file specified by next argument
				if (argList.isEmpty()) {
					Msg.error(SleighCompileOptions.class, "Missing options input file name");
					throw new SleighException("Missing options input file name");
				}
				String optFilename = argList.removeFirst();
				File optionsFile = new File(optFilename).getAbsoluteFile();
				if (!optionsFile.isFile()) {
					Msg.error(SleighCompileOptions.class, "Options file not found: " + optionsFile);
					if (SystemUtilities.isInDevelopmentMode()) {
						Msg.error(SleighCompileOptions.class,
							"Eclipse language module must be selected and 'gradle prepdev' prevously run");
					}
					throw new SleighException("Options file not found: " + optionsFile);
				}
				Deque<String> newArgList = new ArrayDeque<>(getOptionsFromFile(optionsFile));
				newArgList.addAll(argList);
				argList.clear();
				argList.addAll(newArgList);
				break;
			case 'D':
				String preproc = arg.substring(2);
				int pos = preproc.indexOf('=');
				if (pos == -1) {
					Msg.error(SleighCompileOptions.class, "Bad sleigh option: " + arg);
					throw new SleighException("Bad sleigh option: " + arg);
				}
				String name = preproc.substring(0, pos);
				String value = preproc.substring(pos + 1);
				addPreprocessorMacroDefinition(name, value);
				break;
			case 'd':
				String moduleName = arg.substring(2);
				ResourceFile module = Application.getModuleRootDir(moduleName);
				if (module == null || !module.isDirectory()) {
					Msg.error(SleighCompileOptions.class,
						"Failed to resolve module reference: " + arg);
					throw new SleighException("Failed to resolve module reference: " + arg);
				}
				Msg.debug(SleighCompileOptions.class,
					"Sleigh resolved module: " + moduleName + "=" + module.getAbsolutePath());
				addPreprocessorMacroDefinition(moduleName, module.getAbsolutePath());
				break;
			case 'u':
				unnecessaryPcodeWarning = true;
				break;
			case 't':
				deadTempWarning = true;
				break;
			case 'e':
				enforceLocalKeyWord = true;
				break;
			case 'f':
				unusedFieldWarning = true;
				break;
			case 'l':
				lenientConflict = false;
				break;
			case 'c':
				allCollisionWarning = true;
				break;
			case 'n':
				allNopWarning = true;
				break;
			case 'a':
				if (argList.isEmpty()) {
					Msg.error(SleighCompileOptions.class, "Missing input directory path");
					throw new SleighException("Missing input directory path");
				}
				File dir = new File(argList.removeFirst()).getAbsoluteFile();
				if (!dir.exists() || !dir.isDirectory()) {
					Msg.error(SleighCompileOptions.class, dir + " is not a directory");
					throw new SleighException(dir + " is not a directory");
				}
				allMode = true;
				allDir = dir;
				break;
			case 's':
				caseSensitiveRegisterNames = true;
				break;
			case 'y':
				debugOutput = true;
				break;
			case 'x':
				SleighCompile.yydebug = true; // Debug option
				break;
			default:
				Msg.error(SleighCompileOptions.class, "Unknown option: " + arg);
				throw new SleighException("Unknown option: " + arg);
		}
	}

	private static List<String> getOptionsFromFile(File optionsFile) throws SleighException {
		try {
			return FileUtilities.getLines(optionsFile)
					.stream()
					.map(String::trim)
					.filter(option -> !option.isBlank() && !option.startsWith("#"))
					.toList();
		}
		catch (IOException e) {
			Msg.error(SleighCompileOptions.class,
				"Reading options file failed (" + optionsFile.getName() + "): " + e.getMessage());
			throw new SleighException("Failed reading options file [%s]".formatted(optionsFile), e);
		}
	}

}
