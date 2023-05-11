/* ###
 * IP: GHIDRA
 * NOTE: The presence of the MIPS and 8051 path flags beg the question: what OTHER languages besides what we know about need these defines?
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
package ghidra.pcodeCPort.slgh_compile.regression;

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

import org.antlr.runtime.RecognitionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.JDOMException;
import org.junit.*;
import org.junit.experimental.categories.Category;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import generic.test.category.NightlyCategory;
import ghidra.framework.*;
import ghidra.pcodeCPort.slgh_compile.SleighCompileLauncher;

@Category(NightlyCategory.class)
public class SleighCompileRegressionTest extends AbstractGenericTest {
	private static final int TOO_MANY_ERRORS = 100;

	private Logger log;

	@Before
	public void setUp() throws Exception {

		log = LogManager.getLogger(SleighCompileRegressionTest.class);
	}

	private boolean allOK = true;
	private int currentLangBadCount;

	private boolean itsOK(String message, boolean condition) {
		if (!condition) {
			++currentLangBadCount;
			if (currentLangBadCount <= TOO_MANY_ERRORS + 1) {
				log.fatal(message);
			}
			allOK = false;
		}
		return condition;
	}

	@Test
	public void testExternal() throws Exception {

		StringBuffer summary = new StringBuffer();

		LoggingInitialization.initializeLoggingSystem();
		List<ResourceFile> inputs = getSlaspecFiles();
		Iterator<ResourceFile> ii = inputs.iterator();

		while (ii.hasNext()) {
			ResourceFile inputFile = ii.next();
			String inputName = inputFile.getName().replaceFirst("\\.slaspec$", "-");
			File targetFile = createTempFile("target-" + inputName, ".sla");
			File actualFile = createTempFile("actual-" + inputName, ".sla");
			log.info("testing " + inputFile + " (in " + targetFile + " and " + actualFile + ")");

			int targetRetval = runTargetCompiler(inputFile, targetFile);
			if (itsOK("non-zero target compiler return value", 0 == targetRetval)) {

				int actualRetval = runActualCompiler(inputFile.getFile(false), actualFile);
				if (itsOK("non-zero actual compiler return value", 0 == actualRetval)) {
					currentLangBadCount = 0;
					boolean ok = comparesOK(actualFile, targetFile);

					if (ok) {
						assertTrue("could not delete target output file " + targetFile,
							targetFile.delete());
						assertTrue("could not delete actual output file " + actualFile,
							actualFile.delete());
					}
					else {
						summary.append("Sleigh compile mismatch for: " + inputFile + "\n");
					}
				}
				else {
					summary.append("Sleigh(Java) compile failed for: " + inputFile + "\n");
				}
			}
			else {
				summary.append("Sleigh(C) compile failed for: " + inputFile + "\n");
			}
//            printMemory();
		}
		if (allOK) {
			log.info("SUCCESS!  Finished all tests.");
		}
		else {
			log.error("FAILURE.  Look in the log above for Sleigh ERROR messages\n" + summary);
			Assert.fail("Sleigh language errors found");
		}
	}

	private int runTargetCompiler(ResourceFile inputFile, File targetFile)
			throws IOException, InterruptedException {
		String command = getCppSleighCompilerForArch();
		ProcessBuilder processBuilder =
			new ProcessBuilder(command, "-DMIPS=../../../../../../ghidra/Ghidra/Processors/MIPS",
				"-D8051=../../../../../../ghidra/Ghidra/Processors/8051",
				inputFile.getAbsolutePath(), targetFile.getAbsolutePath());
		processBuilder.directory(inputFile.getParentFile().getFile(false));
		Process process = processBuilder.start();

		new IOThread(process.getInputStream()).start();
		new IOThread(process.getErrorStream()).start();

		int retval = process.waitFor();
		return retval;
	}

	private String getCppSleighCompilerForArch() throws FileNotFoundException {
		String exeName;
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			exeName = "sleigh.exe";
		}
		else {
			exeName = "sleigh";
		}
		File file = Application.getOSFile(exeName);
		return file.getAbsolutePath();
	}

	private class IOThread extends Thread {
		private BufferedReader shellOutput;

		public IOThread(InputStream input) {
			shellOutput = new BufferedReader(new InputStreamReader(input));
		}

		@Override
		public void run() {
			String line = null;
			try {
				while ((line = shellOutput.readLine()) != null) {
					System.out.println(line);
				}
			}
			catch (Exception e) {
				// DO NOT USE LOGGING HERE (class loader)
				System.err.println("Unexpected Exception: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	private int runActualCompiler(File inputFile, File actualFile)
			throws JDOMException, IOException, RecognitionException {
		return SleighCompileLauncher.runMain(new String[] { "-DBaseDir=../../../../../../",
			"-DMIPS=ghidra/Ghidra/Processors/MIPS", "-D8051=ghidra/Ghidra/Processors/8051",
			inputFile.getAbsolutePath(), actualFile.getAbsolutePath() });
	}

	private static final Pattern SPACEMATCH = Pattern.compile("^\\s*<print piece=\" \"/>\\s*$");
	private static final Pattern TPLMATCH = Pattern.compile("^\\s*<construct_tpl>\\s*$");

	private boolean comparesOK(File actualFile, File targetFile) throws Exception {
		boolean ok = true;
		PushbackEntireLine actualReader =
			new PushbackEntireLine(new BufferedReader(new FileReader(actualFile)));
		PushbackEntireLine targetReader =
			new PushbackEntireLine(new BufferedReader(new FileReader(targetFile)));
		int actualLineNumber = 1;
		int targetLineNumber = 1;
		while (true) {
			try {
				if (currentLangBadCount >= 100) {
					ok = itsOK("WAY TOO MANY DIFFERENCES, BAILING", false);
					break;
				}
				String actual = actualReader.readLine();
				String target = targetReader.readLine();
				if (target == null) {
					ok &= itsOK("actual has too many lines", actual == null);
					break;
				}
				if (actual == null) {
					ok &= itsOK("actual has too few lines", false);
					break;
				}

				boolean actualIsSpace = SPACEMATCH.matcher(actual).find();
				boolean targetIsSpace = SPACEMATCH.matcher(target).find();

				boolean bothSpace = actualIsSpace && targetIsSpace;
				boolean oneIsSpace = actualIsSpace || targetIsSpace;

				if (!oneIsSpace) {
					ok &= itsOK(
						"difference on actual line " + actualLineNumber + ", target line " +
							targetLineNumber + ":\nEXPECTED:\n" + target + "\nACTUAL:\n" + actual,
						target.equals(actual));
					continue;
				}
				else if (!bothSpace) {
					// expected absent trailing space in Java version
					if (!TPLMATCH.matcher(actual).find()) {
						ok &= itsOK("difference (space!) on actual line " + actualLineNumber +
							", target line " + targetLineNumber + ":\nEXPECTED:\n" + target +
							"\nACTUAL:\n" + actual, false);
					}
				}

				while (actualIsSpace) {
					actual = actualReader.readLine();
					++actualLineNumber;
					actualIsSpace = actual != null && SPACEMATCH.matcher(actual).find();
				}
				actualReader.putbackLine(actual);
				--actualLineNumber;

				while (targetIsSpace) {
					target = targetReader.readLine();
					++targetLineNumber;
					targetIsSpace = target != null && SPACEMATCH.matcher(target).find();
				}
				targetReader.putbackLine(target);
				--targetLineNumber;

			}
			finally {
				++actualLineNumber;
				++targetLineNumber;
			}
		}
		actualReader.close();
		targetReader.close();
		return ok;
	}

	private List<ResourceFile> getSlaspecFiles() {
		List<ResourceFile> allSlaspecFiles =
			Application.findFilesByExtensionInApplication(".slaspec");
		return allSlaspecFiles;

//		Predicate<ResourceFile> predicate = new Predicate<ResourceFile>() {
//			@Override
//			public boolean accept(ResourceFile t) {
//				String absolutePath = t.getAbsolutePath();
//				if (absolutePath.contains("<processor you do not want to include>")) {
//					return false;
//				}
//				return true;
//			}
//		};
//
//		return Fx.filter(predicate, allSlaspecFiles);
	}
}
