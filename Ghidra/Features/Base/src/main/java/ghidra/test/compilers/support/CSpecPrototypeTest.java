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
package ghidra.test.compilers.support;

import static org.junit.Assert.*;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.pcode.emu.EmulatorUtilities;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.InterruptPcodeExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.test.compilers.support.CSpecPrototypeTestUtil.TestResult;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * <code>CSpecPrototypeTest</code> provides an abstract JUnit test implementation
 * for processor-specific and compiler-specific calling convention test cases.
 * 
 * Tests which extend this class must implement abstract functions to specify LANGUAGE_ID,
 * COMPILER_SPEC_ID, and CALLING_CONVENTION.
 * 
 * An optional list of function names that contain errors can be passed to the constructor to
 * designate those errors as expected. The test will pass as long as only expected errors are found.
 * 
 * Source and binary files have a naming scheme.
 * (LANGUAGE_ID)_(COMPILER_SPEC_ID)_(CALLING_CONVENTION)
 * 
 * Trace logging is disabled by default. Specific traceLevel and traceLog disabled controlled via 
 * environment properties CSpecTestTraceLevel and EmuTestTraceDisable.
 * 
 * To create a new CSpecPrototypeTest for a given Module (e.g. Processors x86) complete the 
 * following steps:
 * 
 * 1. Generate source code using Ghidra and the Ghidra script "GeneratePrototypeTestFileScript".
 * NOTE: Do not rename the generated file; the filename is required for the test suit.
 * 2. Compile the source code using the following recommended GCC flags:
 * gcc -O1 -c -fno-inline -fno-leading-underscore -o filename_without_extension filename.c
 * 3. Place the source code and compiled binary in the module's "data/cspectests" directory or the 
 * ghidra.bin repository in the directory: "Ghidra/Test/TestResources/data/cspectests"
 * 4. Add a new package named "ghidra.test.processors.cspec" to the module if it does not exist and 
 * place all new CSpecTest's in this package.
 * 5. New CSpecTests should extend this class and have a class name which ends in 'CSpecTest' and 
 * starts with processor details that indicate what cspec prototype is being tested.
 * - Implement abstract methods for Language ID, Compiler Spec ID, and Calling Convention.
 * 6. Use Ghidra and the Ghidra script "TestPrototypeScript" to debug errors. 
 * - Click function links in the Script Console to jump to the Listing View.
 * - To isolate a single function, highlight it in the Listing and re-run the script 
 * for detailed debug output.
 * 
 * */
public abstract class CSpecPrototypeTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String EMULATOR_TRACE_DISABLE_PROPERTY = "CSpecTestTraceDisable";
	private static final String EMULATOR_TRACE_LEVEL_PROPERTY = "CSpecTestTraceLevel";

	// If cspectests data directory can not be found for the module containing the junit test,
	// This default ProcessorTest module will be searched instead.
	private static final String DEFAULT_PROCESSOR_TEST_MODULE = "Test/TestResources"; // module path relative to the Ghidra directory

	private static final String TEST_RESOURCE_PATH = "data/cspectests/";

	private TestEnv env;

	private DataConverter dataConverter;
	private LanguageCompilerSpecPair langCompPair;
	private CSpecTestPCodeEmulator emulator;
	private Program currentProgram;

	private final String languageId;
	private final String compilerSpecId;
	private final String testExecutableFileName;

	private Collection<ResourceFile> applicationRootDirectories;
	private File resourcesTestDataDir;

	private final String[] EXPECTED_PROTOTYPE_ERRORS;

	private static boolean traceDisabled = true;
	private static int traceLevel = 3; // 0:disabled 1:Instruction 2:RegisterState 3:Reads-n-Writes

	static {
		if (System.getProperty(EMULATOR_TRACE_DISABLE_PROPERTY) != null) {
			traceDisabled = Boolean.getBoolean(EMULATOR_TRACE_DISABLE_PROPERTY);
		}
	}

	protected CSpecPrototypeTest() throws Exception {
		this(new String[] {});
	}

	protected CSpecPrototypeTest(String[] expectedPrototypeErrors) throws Exception {
		languageId = getLanguageID();
		compilerSpecId = getCompilerSpecID();
		testExecutableFileName = this.languageId.toString().replace(":", "_") + "_" +
			this.compilerSpecId + "_" + getCallingConvention();
		EXPECTED_PROTOTYPE_ERRORS = expectedPrototypeErrors;

		if (System.getProperty(EMULATOR_TRACE_DISABLE_PROPERTY) == null) {
			traceDisabled = true;
		}

		String levelStr = System.getProperty(EMULATOR_TRACE_LEVEL_PROPERTY);
		if (levelStr != null) {
			traceLevel = Integer.parseInt(levelStr);
		}
	}

	/**
	 * Ran before every test to prepare Ghidra for testing.
	 * @throws Exception when the test environment fails to be created or the emulator fails to
	 * load the program.
	 */
	@Before
	public void setUp() throws Exception {
		env = new TestEnv(10, "CSpec Prototype Tests");
		applicationRootDirectories = Application.getApplicationRootDirectories();

		ResourceFile myModuleRootDirectory =
			Application.getModuleContainingClass(getClass());
		if (myModuleRootDirectory != null) {
			File myModuleRoot = myModuleRootDirectory.getFile(false);
			if (myModuleRoot != null) {
				resourcesTestDataDir = new File(myModuleRoot, TEST_RESOURCE_PATH);
				if (!resourcesTestDataDir.isDirectory()) {
					findTestResourceDirectory(getRelativeModulePath(myModuleRootDirectory));
				}
			}
		}
		else {
			Msg.warn(this,
				"Unable to identify pcodetest module directory! Project must contain Module.manifest file");
		}

		if (resourcesTestDataDir == null || !resourcesTestDataDir.isDirectory()) {
			findTestResourceDirectory(DEFAULT_PROCESSOR_TEST_MODULE);
		}

		Msg.info(this,
			"Locating " + testExecutableFileName + " C-Spec Prototype test binaries in: " +
				resourcesTestDataDir.getPath());

		GhidraProject project = env.getGhidraProject();

		File binaryFile = new File(resourcesTestDataDir + File.separator + testExecutableFileName);

		LanguageService languageService = DefaultLanguageService.getLanguageService();
		Language language = languageService.getLanguage(new LanguageID(languageId));
		CompilerSpec compilerSpec =
			language.getCompilerSpecByID(new CompilerSpecID(compilerSpecId));

		LoadResults<Program> loadResults = ProgramLoader.builder()
				.source(binaryFile)
				.project(project.getProject())
				.language(language)
				.compiler(compilerSpec)
				.monitor(TaskMonitor.DUMMY)
				.load();

		currentProgram = loadResults.getPrimaryDomainObject(this);

		currentProgram.startTransaction("Analysis");
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		aam.initializeOptions();
		aam.reAnalyzeAll(null);
		aam.startAnalysis(TaskMonitor.DUMMY);

		langCompPair = currentProgram.getLanguageCompilerSpecPair();
		dataConverter = DataConverter.getInstance(langCompPair.getLanguage().isBigEndian());

		// Load program into emulator
		emulator =
			new CSpecTestPCodeEmulator(currentProgram.getLanguage(), traceDisabled, traceLevel);
		EmulatorUtilities.loadProgram(emulator, currentProgram);
	}

	@After
	public void tearDown() throws Exception {
		Msg.info(this, "Disposing of testing environment.");

		if (env != null) {
			env.dispose();
		}
	}

	/**
	 * Tests that for a given binary and source code all functions in the binary are
	 * interpreted correctly by Ghidra using cspec files for the given calling convention.
	 * @throws Exception when the Prototype cannot be established, the source code could not be 
	 * parsed correctly, or the test could not be completed.
	 */
	@Test
	public void prototypeTest() throws Exception {
		PrototypeModel model =
			CSpecPrototypeTestUtil.getProtoModelToTest(currentProgram, langCompPair);
		FunctionManager fManager = currentProgram.getFunctionManager();

		Msg.info(this, "Locating C-Spec Prototype test source in: " +
			currentProgram.getExecutablePath());
		CSpecPrototypeTestUtil.applyInfoFromSourceIfNeeded(currentProgram, model);

		Iterator<Function> fIter = fManager.getFunctionsNoStubs(true);

		List<Function> errors = new ArrayList<>();
		while (fIter.hasNext()) {
			Function caller = fIter.next();
			if (!(caller.getName().startsWith("params") || caller.getName().startsWith("return"))) {
				continue;
			}

			Function callee = CSpecPrototypeTestUtil.getFirstCall(caller);
			ArrayList<ParameterPieces> pieces =
				CSpecPrototypeTestUtil.getParameterPieces(caller, callee, model);
			Address breakpoint = null;
			if (caller.getName().startsWith("params")) {
				breakpoint = callee.getEntryPoint();
			}
			else {
				// find the address of the call to producer
				ReferenceIterator refIter =
					currentProgram.getReferenceManager().getReferencesTo(callee.getEntryPoint());
				if (!refIter.hasNext()) {
					throw new AssertionError(
						"no references to " + callee.getName() + " in " + caller.getName());
				}
				Reference ref = null;
				while (refIter.hasNext()) {
					Reference r = refIter.next();
					if (!r.getReferenceType().isCall()) {
						continue;
					}
					if (caller.getBody().contains(r.getFromAddress())) {
						ref = r;
						break;
					}
				}
				if (ref == null) {
					throw new AssertionError(
						"call to " + callee.getName() + " not found in " + caller.getName());
				}
				Instruction afterCall =
					currentProgram.getListing().getInstructionAfter(ref.getFromAddress());
				// For architectures with a delay slot, break on the actual aftercall instruction,
				// by stepping instructions until we are out of the delay slot.
				while (afterCall.isInDelaySlot()) {
					afterCall = afterCall.getNext();
				}
				breakpoint = afterCall.getAddress();

			}

			boolean error = testFunction(caller, callee, breakpoint, pieces);

			if (error) {
				errors.add(caller);
			}
		}

		if (errors.size() == 0) {
			Msg.info(this, "No prototype errors found.");
		}
		else {
			Msg.info(this, errors.size() + " prototype error(s) found:");
			for (Function errFunc : errors) {
				Msg.info(this, "\t" + errFunc.getName());
			}
		}

		Set<String> actualErrors = errors.stream()
				.map(Function::getName)
				.collect(Collectors.toSet());

		Set<String> expectedErrors = Set.of(EXPECTED_PROTOTYPE_ERRORS);

		List<String> missingErrors = expectedErrors.stream()
				.filter(name -> !actualErrors.contains(name))
				.collect(Collectors.toList());

		List<String> unexpectedErrors = actualErrors.stream()
				.filter(name -> !expectedErrors.contains(name))
				.collect(Collectors.toList());

		assertTrue(
			"The following prototype errors were expected, but no corresponding error was found: " +
				missingErrors,
			missingErrors.isEmpty());

		assertTrue(
			"The following prototype errors were found, but they were not in the expected list: " +
				unexpectedErrors,
			unexpectedErrors.isEmpty());
	}

	/**
	 * Compare the 'expected' parameters to the 'from emulator' parameters of a function call
	 * to determine if the binary was correctly interpreted by Ghidra using the cspec file for the 
	 * specified calling convention.
	 * @param caller function calling the function to be tested
	 * @param callee function that is being tested, called by the caller.
	 * @param breakPoint Address to stop the emulator.
	 * @param pieces ArrayList<ParameterPieces> parameter pieces gathered from parsing the binary's
	 * source code.
	 * @return boolean indicating the result of the test
	 * @throws Exception when there's a problem establishing expected parameter or getting parameter 
	 * pieces from the emulator.
	 */
	private boolean testFunction(Function caller, Function callee, Address breakPoint,
			ArrayList<ParameterPieces> pieces) throws Exception {

		List<byte[]> groundTruth =
			CSpecPrototypeTestUtil.getPassedValues(callee, pieces, dataConverter,
				(msg -> Msg.warn(this, msg)));

		// breakpoint will be skipped if condition is false, so add condition that is always true
		emulator.addBreakpoint(breakPoint, "1:1");

		PcodeThread<byte[]> emuThread = emulator.prepareFunction(caller);

		Register stackReg = caller.getProgram().getCompilerSpec().getStackPointer();

		try {
			emuThread.run();
			Msg.error(this, "Emulator should have hit breakpoint");
		}
		catch (InterruptPcodeExecutionException e) {
			// this is the breakpoint, which is what we want to happen
		}

		List<byte[]> fromEmulator = new ArrayList<>();
		for (ParameterPieces piece : pieces) {
			fromEmulator.add(CSpecPrototypeTestUtil.readParameterPieces(emuThread, piece,
				emulator.getLanguage().getDefaultDataSpace(), stackReg, langCompPair,
				dataConverter));
		}

		TestResult result =
			CSpecPrototypeTestUtil.getTestResult(callee, caller, pieces, fromEmulator, groundTruth);

		if (result.hasError()) {
			Msg.info(this, result.message());
		}

		return result.hasError();

	}

	/**
	 * Sets the resource directory for the test, this is where a binary and it's source code
	 * should be located.
	 * @param relativeModulePath directory of the module that contains this class
	 */
	private void findTestResourceDirectory(String relativeModulePath) {
		if (relativeModulePath == null) {
			return;
		}
		for (ResourceFile appRoot : applicationRootDirectories) {
			File moduleRoot = new File(appRoot.getAbsolutePath(), relativeModulePath);
			File dir = new File(moduleRoot, TEST_RESOURCE_PATH);
			if (dir.isDirectory()) {
				resourcesTestDataDir = dir;
				break;
			}
		}
	}

	/**
	 * Find the path of the test module for the purposes of finding a binary and source code to use with
	 * the test.
	 * @param myModuleRootDirectory directory of the root of the module that contains this class
	 * @return String
	 */
	private String getRelativeModulePath(ResourceFile myModuleRootDirectory) {
		String absolutePath = myModuleRootDirectory.getAbsolutePath();
		for (ResourceFile appRoot : applicationRootDirectories) {
			String rootPath = appRoot.getAbsolutePath();
			if (absolutePath.startsWith(rootPath)) {
				return absolutePath.substring(rootPath.length() + 1);
			}
		}
		return null;
	}

	/**
	 * @return String Language ID
	 */
	public abstract String getLanguageID();

	/**
	 * @return String Compiler Spec ID
	 */
	public abstract String getCompilerSpecID();

	/**
	 * @return String Calling Convention
	 */
	public abstract String getCallingConvention();
}
