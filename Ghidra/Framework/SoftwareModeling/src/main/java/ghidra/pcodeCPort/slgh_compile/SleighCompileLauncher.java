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
import java.util.Map.Entry;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.CommonTreeNodeStream;
import org.jdom.JDOMException;

import generic.jar.ResourceFile;
import generic.stl.IteratorSTL;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.sleigh.grammar.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

/**
 * <code>SleighCompileLauncher</code> Sleigh compiler launch provider
 */
public class SleighCompileLauncher implements GhidraLaunchable {

	public static final String FILE_IN_DEFAULT_EXT = ".slaspec";
	public static final String FILE_OUT_DEFAULT_EXT = ".sla";
	private static final FileFilter SLASPEC_FILTER =
		pathname -> pathname.getName().endsWith(".slaspec");

	private static void initCompiler(SleighCompile compiler, Map<String, String> preprocs,
			boolean unnecessaryPcodeWarning, boolean lenientConflict, boolean allCollisionWarning,
			boolean allNopWarning, boolean deadTempWarning, boolean unusedFieldWarning,
			boolean enforceLocalKeyWord, boolean largeTemporaryWarning) {
		Set<Entry<String, String>> entrySet = preprocs.entrySet();
		for (Entry<String, String> entry : entrySet) {
			compiler.setPreprocValue(entry.getKey(), entry.getValue());
		}
		compiler.setUnnecessaryPcodeWarning(unnecessaryPcodeWarning);
		compiler.setLenientConflict(lenientConflict);
		compiler.setLocalCollisionWarning(allCollisionWarning);
		compiler.setAllNopWarning(allNopWarning);
		compiler.setDeadTempWarning(deadTempWarning);
		compiler.setUnusedFieldWarning(unusedFieldWarning);
		compiler.setEnforceLocalKeyWord(enforceLocalKeyWord);
		compiler.setLargeTemporaryWarning(largeTemporaryWarning);
	}

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
	 * @throws JDOMException
	 * @throws IOException
	 * @throws RecognitionException
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
				initCompiler(compiler, preprocs, unnecessaryPcodeWarning, lenientConflict,
					allCollisionWarning, allNopWarning, deadTempWarning, unusedFieldWarning,
					enforceLocalKeyWord, largeTemporaryWarning);

				String outname = input.getName().replace(".slaspec", ".sla");
				File output = new File(input.getParent(), outname);
				retval =
					run_compilation(input.getAbsolutePath(), output.getAbsolutePath(), compiler);
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
		initCompiler(compiler, preprocs, unnecessaryPcodeWarning, lenientConflict,
			allCollisionWarning, allNopWarning, deadTempWarning, unusedFieldWarning,
			enforceLocalKeyWord, largeTemporaryWarning);
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

		return run_compilation(filein, fileout, compiler);
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

	private static int run_compilation(String filein, String fileout, SleighCompile compiler)
			throws IOException, RecognitionException {
//        try {
//            compiler.parseFromNewFile(filein);
		//FileInputStream yyin = new FileInputStream(new File(filein));
//		StringWriter output = new StringWriter();

//            System.out.println(output.toString());
//		UGLY_STATIC_GLOBAL_COMPILER = null; // Set global pointer up for parser

//            SleighCompiler realCompiler = new SleighCompiler(new StringReader(output.toString()));

		// too late for this because we snarf a token or two on constructor time?
//            if (yydebug) {
//                realCompiler.enable_tracing();
//            } else {
//                realCompiler.disable_tracing();
//            }

		LineArrayListWriter writer = new LineArrayListWriter();
		ParsingEnvironment env = new ParsingEnvironment(writer);
		try {
			final SleighCompilePreprocessorDefinitionsAdapater definitionsAdapter =
				new SleighCompilePreprocessorDefinitionsAdapater(compiler);
			final File inputFile = new File(filein);
			FileResolutionResult result = FileUtilities.existsAndIsCaseDependent(inputFile);
			if (!result.isOk()) {
				throw new BailoutException("input file \"" + inputFile +
					"\" is not properly case dependent: " + result.getMessage());
			}
			SleighPreprocessor sp = new SleighPreprocessor(definitionsAdapter, inputFile);
			sp.process(writer);

			CharStream input = new ANTLRStringStream(writer.toString());
			SleighLexer lex = new SleighLexer(input);
			lex.setEnv(env);
			UnbufferedTokenStream tokens = new UnbufferedTokenStream(lex);
			SleighParser parser = new SleighParser(tokens);
			parser.setEnv(env);
			parser.setLexer(lex);
			SleighParser.spec_return root = parser.spec();
			/*ANTLRUtil.debugTree(root.getTree(),
				new PrintStream(new FileOutputStream("blargh.tree")));*/
			CommonTreeNodeStream nodes = new CommonTreeNodeStream(root.getTree());
			nodes.setTokenStream(tokens);
			// ANTLRUtil.debugNodeStream(nodes, System.out);
			SleighCompiler walker = new SleighCompiler(nodes);

			int parseres = -1;
			try {
				parseres = walker.root(env, compiler); // Try to parse
			}
			catch (SleighError e) {
				compiler.reportError(e.location, e.getMessage());
			}
//                yyin.close();
			if (parseres == 0) {
				if (compiler.noplist.size() > 0) {
					if (compiler.warnallnops) {
						IteratorSTL<String> iter;
						for (iter = compiler.noplist.begin(); !iter.isEnd(); iter.increment()) {
							Msg.warn(SleighCompile.class, iter.get());
						}
					}
					Msg.warn(SleighCompile.class,
						compiler.noplist.size() + " NOP constructors found");
					if (!compiler.warnallnops) {
						Msg.warn(SleighCompile.class, "Use -n switch to list each individually");
					}
				}
				compiler.process(); // Do all the post-processing
			}
			if ((parseres == 0) && (compiler.numErrors() == 0)) {
				// If no errors
//                    try {
				PrintStream s = new PrintStream(new FileOutputStream(new File(fileout)));
				compiler.saveXml(s); // Dump output xml
				s.close();
//                    }
//                    catch (Exception e) {
//                        throw new SleighError("Unable to open output file: "
//                                + fileout);
//                    }
			}
			else {
				Msg.error(SleighCompile.class, "No output produced");
				return 2;
			}
		}
		catch (BailoutException e) {
			Msg.error(SleighCompile.class, "Unrecoverable error(s), halting compilation", e);
			return 3;
		}
		catch (NullPointerException e) {
			Msg.error(SleighCompile.class, "Unrecoverable error(s), halting compilation", e);
			return 4;
		}
		catch (PreprocessorException e) {
			Msg.error(SleighCompile.class, e.getMessage());
			Msg.error(SleighCompile.class, "Errors during preprocessing, halting compilation");
			return 5;
		}
//            catch (LowlevelError err) {
//                Msg.info(this, "Unrecoverable error: " + err.getMessage());
//                err.printStackTrace();
//                return 2;
//            }
//            catch (IOException e) {
//                Msg.info(this, "Couldn't close file: " + e.getMessage());
//                return 1;
//            }
//        }
//        catch (FileNotFoundException e) {
//            Msg.info(this, "Unable to open specfile: " + filein);
//            return 2;
//        }
//        catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        catch (ParseException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
		return 0;
	}

}
