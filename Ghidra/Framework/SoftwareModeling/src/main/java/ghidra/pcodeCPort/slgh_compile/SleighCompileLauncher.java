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
import java.util.TreeSet;

import org.antlr.runtime.RecognitionException;
import org.jdom2.JDOMException;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;

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
	 * @throws IOException for file access errors
	 * @throws RecognitionException for parse errors
	 */
	public static int runMain(String[] args) throws IOException, RecognitionException {
		if (args.length == 0) {
			SleighCompileOptions.usage();
			return 2;
		}
		SleighCompileOptions options;
		try {
			options = SleighCompileOptions.parse(args);
		}
		catch (SleighException e) {
			return 1;
		}
		return launchCompile(options);
	}

	public static int launchCompile(SleighCompileOptions options)
			throws IOException, RecognitionException {
		if (options.allMode) {
			return compileAll(options);
		}
		else {
			return compileOne(options);
		}
	}

	public static int compileOne(SleighCompileOptions options)
			throws IOException, RecognitionException {
		SleighCompile compiler = new SleighCompile();
		compiler.setOptions(options);

		return compiler.run_compilation(options.inputFile.getPath(), options.outputFile.getPath());
	}

	public static int compileAll(SleighCompileOptions options)
			throws IOException, RecognitionException {
		TreeSet<String> failures = new TreeSet<>();
		int totalFailures = 0;
		int totalSuccesses = 0;
		DirectoryVisitor visitor = new DirectoryVisitor(options.allDir, SLASPEC_FILTER);
		for (File input : visitor) {
			System.out.println("Compiling " + input + ":");
			SleighCompile compiler = new SleighCompile();
			compiler.setOptions(options);

			String outname = input.getName().replace(".slaspec", ".sla");
			File output = new File(input.getParentFile(), outname);
			int retval = compiler.run_compilation(input.getPath(), output.getPath());
			System.out.println();
			if (retval != 0) {
				++totalFailures;
				failures.add(input.getPath());
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
}
