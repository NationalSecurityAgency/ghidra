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
import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.stl.IteratorSTL;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.translate.XmlError;
import ghidra.sleigh.grammar.*;
import ghidra.util.Msg;
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
			boolean unnecessaryPcodeWarning, boolean lenientConflict, boolean allNopWarning,
			boolean deadTempWarning, boolean unusedFieldWarning, boolean enforceLocalKeyWord) {
		Set<Entry<String, String>> entrySet = preprocs.entrySet();
		for (Entry<String, String> entry : entrySet) {
			compiler.setPreprocValue(entry.getKey(), entry.getValue());
		}
		compiler.setUnnecessaryPcodeWarning(unnecessaryPcodeWarning);
		compiler.setLenientConflict(lenientConflict);
		compiler.setAllNopWarning(allNopWarning);
		compiler.setDeadTempWarning(deadTempWarning);
		compiler.setUnusedFieldWarning(unusedFieldWarning);
		compiler.setEnforceLocalKeyWord(enforceLocalKeyWord);
	}

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args)
			throws JDOMException, IOException, RecognitionException {
		System.exit(runMain(args, new HashMap<String, String>()));
	}

	/**
	 * Execute the Sleigh compiler process 
	 * @param args sleigh compiler command line arguments
	 * @param preprocs additional preprocessor macro 
	 * @return exit code (TODO: exit codes are not well defined)
	 * @throws JDOMException
	 * @throws IOException
	 * @throws RecognitionException
	 */
	public static int runMain(String[] args, Map<String, String> preprocs)
			throws JDOMException, IOException, RecognitionException {
		int retval;
		String filein = null;
		String fileout = null;

		SleighCompile.yydebug = false;
		boolean allMode = false;

		if (args.length < 1) {
			// @formatter:off
			Msg.info(SleighCompile.class, "USAGE: sleigh [-x] [-dNAME=VALUE] inputfile outputfile");
			Msg.info(SleighCompile.class, "   -x              turns on parser debugging");
			Msg.info(SleighCompile.class, "   -u              print warnings for unnecessary pcode instructions");
			Msg.info(SleighCompile.class, "   -l              report pattern conflicts");
			Msg.info(SleighCompile.class, "   -n              print warnings for all NOP constructors");
			Msg.info(SleighCompile.class, "   -t              print warnings for dead temporaries");
			Msg.info(SleighCompile.class, "   -e              enforce use of 'local' keyword for temporaries");
			Msg.info(SleighCompile.class, "   -f              print warnings for unused token fields");
			Msg.info(SleighCompile.class, "   -DNAME=VALUE    defines a preprocessor macro NAME with value VALUE");
			Msg.info(SleighCompile.class, " OR    sleigh -a directory-root");
			Msg.info(SleighCompile.class, "                   compiles all .slaspec files to .sla files anywhere under directory-root");
			// @formatter:on
			return 2;
		}

		boolean unnecessaryPcodeWarning = false;
		boolean lenientConflict = true;
		boolean allNopWarning = false;
		boolean deadTempWarning = false;
		boolean enforceLocalKeyWord = false;
		boolean unusedFieldWarning = false;

		int i;
		for (i = 0; i < args.length; ++i) {
			if (args[i].charAt(0) != '-') {
				break;
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
			else if (args[i].charAt(1) == 'n') {
				allNopWarning = true;
			}
			else if (args[i].charAt(1) == 'a') {
				allMode = true;
			}
			else if (args[i].charAt(1) == 'x') {
				SleighCompile.yydebug = true; // Debug option
			}
			else {
				Msg.error(SleighCompile.class, "Unknown option: " + args[i]);
				return 1;
			}
		}

		if (allMode) {
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
					allNopWarning, deadTempWarning, unusedFieldWarning, enforceLocalKeyWord);

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

		SleighCompile compiler = new SleighCompile();
		initCompiler(compiler, preprocs, unnecessaryPcodeWarning, lenientConflict, allNopWarning,
			deadTempWarning, unusedFieldWarning, enforceLocalKeyWord);
		if (i == args.length) {
			Msg.error(SleighCompile.class, "Missing input file name");
			return 1;
		}
		if (i < args.length - 2) {
			Msg.error(SleighCompile.class, "Too many parameters");
			return 1;
		}

		filein = args[i];
		if (i < args.length - 1) {
			fileout = args[i + 1];
		}

		String fileinExamine = filein;
		int extInPos = fileinExamine.indexOf(FILE_IN_DEFAULT_EXT);
		boolean autoExtInSet = false;
		String fileinPreExt = "";
		if (extInPos == -1) {// No Extension Given...
			// cout << "No Ext Given" << endl;
			fileinPreExt = fileinExamine;
			fileinExamine += FILE_IN_DEFAULT_EXT;
			filein = fileinExamine;
			// cout << "filein = " << filein << endl;
			autoExtInSet = true;
		}
		else {
			fileinPreExt = fileinExamine.substring(0, extInPos);
		}
		// cout << "fileinPreExt = " << fileinPreExt << endl;

		if (fileout != null) {
			String fileoutExamine = fileout;
			int extOutPos = fileoutExamine.indexOf(FILE_OUT_DEFAULT_EXT);
			if (extOutPos == -1) {// No Extension Given...
				// cout << "No Ext Given" << endl;
				fileoutExamine += FILE_OUT_DEFAULT_EXT;
				fileout = fileoutExamine;
				// cout << "fileout = " << fileout << endl;
			}
			retval = run_compilation(filein, fileout, compiler);
		}
		else {
			// First determine whether or not to use Run_XML...
			if (autoExtInSet) {// Assumed format of at least "sleigh file" .
				// "sleigh file.slaspec file.sla"
				String fileoutSTR = fileinPreExt;
				fileoutSTR += FILE_OUT_DEFAULT_EXT;
				fileout = fileoutSTR;
				// cout << "generated fileout = " << fileout << endl;
				retval = run_compilation(filein, fileout, compiler);
			}
			else {
				retval = run_xml(filein, compiler);
			}

		}
		return retval;
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

	private static int run_xml(String filein, SleighCompile compiler)
			throws JDOMException, IOException, RecognitionException {
		FileInputStream s = new FileInputStream(new File(filein));
		Document doc = null;
		String specfileout = "";
		String specfilein = "";

		try {
			SAXBuilder builder = new SAXBuilder(false);
			doc = builder.build(s);
		}
		catch (XmlError err) {
			Msg.error(SleighCompile.class,
				"Unable to parse single input file as XML spec: " + filein, err);
			return 1;
		}
		s.close();

		Element el = doc.getRootElement();
		for (;;) {
			List<?> list = el.getChildren();
			Iterator<?> iter = list.iterator();
			while (iter.hasNext()) {
				el = (Element) iter.next();
				if (el.getName().equals("processorfile")) {
					specfileout = el.getText();
					List<?> atts = el.getAttributes();
					Iterator<?> i = atts.iterator();
					while (i.hasNext()) {
						Attribute att = (Attribute) i.next();
						if (att.getName().equals("slaspec")) {
							specfilein = att.getValue();
						}
						else {
							compiler.setPreprocValue(att.getName(), att.getValue());
						}
					}
				}
				else if (el.getName().equals("language_spec")) {
					break;
				}
				else if (el.getName().equals("language_description")) {
					break;
				}
			}
			if (!iter.hasNext()) {
				break;
			}
		}

		if (specfilein.length() == 0) {
			Msg.error(SleighCompile.class, "Input slaspec file was not specified in " + filein);
			return 1;
		}
		if (specfileout.length() == 0) {
			Msg.error(SleighCompile.class, "Output sla file was not specified in " + filein);
			return 1;
		}
		return run_compilation(specfilein, specfileout, compiler);
	}
}
