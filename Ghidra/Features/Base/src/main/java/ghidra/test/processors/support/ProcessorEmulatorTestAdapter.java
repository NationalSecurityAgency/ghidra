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
package ghidra.test.processors.support;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import generic.test.AbstractGTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.TestEnv;
import ghidra.test.TestProgramManager;
import ghidra.test.processors.support.EmulatorTestRunner.DumpFormat;
import ghidra.test.processors.support.PCodeTestAbstractControlBlock.FunctionInfo;
import ghidra.test.processors.support.PCodeTestAbstractControlBlock.InvalidControlBlockException;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import junit.framework.*;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;

/**
 * <code>ProcessorEmulatorTestAdapter</code> provides an abstract JUnit test implementation
 * for processor-specific test cases.  All test cases which extend this class must have a
 * class name which ends with 'EmulatorTest' and starts with the processor designator which
 * will be used to identify associated test binaries within either the processor module's
 * data/pcodetests/ directory or the Ghidra/Test/TestResources/data/pcodetests/ directory generally 
 * contained within the binary repository (e.g., ghidra.bin).
 * <p>
 * Within the pcodetests directory all files and folders which start with the prefix
 * {@literal <processor-designator>_pcodetest*} will be processed.  All files contained within a matching
 * subdirectory will be treated as related binaries and imported.  Any *.gzf file will be
 * imported but assumed to be pre-analyzed.  Binary files to be imported and analyzed must
 * utilize the *.out file extension.
 * <p>
 * JUnit X86EmulatorTest could utilize the following binary file naming strategy:
 * <pre>
 * pcodetests/X86_PCodeTests
 * - binary1.o
 * - binary2.o
 * - binary3.gzf
 * pcodetests/X86_PCodeTests/data (could be used for any associated files not to be imported)
 * - binary3.o
 * - binary3.d
 *
 * or, a single binary file could suffice:
 * - pcodetests/X86_PCodeTest.out
 * </pre>
 *
 * Any *.out binary found will be imported and analyzed.  The resulting program will
 * be stored as a gzf in the test-output cache directory.  These cached files will be used
 * instead of a test resource binary if that binary's md5 checksum has not changed since its cached
 * gzf was created.  This use of cache files will allow the tests to run quickly on subsequent
 * executions.  If re-analysis is required, the cache will need to be cleared manually.
 * 
 * NOTES:
 * 1. Dummy Test Methods must be added for all known test groups.  See bottom of this file.  This
 *    all allows for the single test trace mode execution to work within Eclipse.
 * 2. Trace logging disabled by default when all test groups are run (see buildEmulatorTestSuite method).
 *    Specific traceLevel and traceLog file controlled via environment properties
 *    EmuTestTraceLevel and EmuTestTraceFile.
 * 3. The TestInfo structure must be properly maintained within the datatype archive EmuTesting.gdt
 *    and field naming consistent with use in PCodeTestControlBlock.java
 * 4. The {@link #initializeState(EmulatorTestRunner, Program)} may be overriden to initialize the
 *    register values if needed.  This should be based upon symbols or other program information
 *    if possible since hardcoded constants may not track future builds of a test binaries.  
 *    An attempt is made to initialize the stack pointer automatically based upon well known
 *    stack initialization symbols.
 */
public abstract class ProcessorEmulatorTestAdapter extends TestCase implements ExecutionListener {

	public final static String BATCH_MODE_OUTPUT_DIR =
		System.getProperty("ghidra.test.property.output.dir");

	// If pcodetests data directory can not be found for the module containing the junit,
	// This default ProcessorTest module will be searched instead.
	private static final String DEFAULT_PROCESSOR_TEST_MODULE = "Test/TestResources"; // module path relative to the Ghidra directory

	// TODO: Add support for duplicate test-group name within different test binaries.
	// must enumerate CUint binaries and reflect in test name somehow ??

	private static final String TEST_INFO_STRUCT_NAME = "TestInfo";
	private static final String GROUP_INFO_STRUCT_NAME = "GroupInfo";

	private static final String PCODE_TEST_FILE_BASE_REGEX = "_PCodeTest.*";

	private static final String EMULATOR_TEST_SUFFIX = "EmulatorTest";

	private static final String EMULATOR_TRACE_LEVEL_PROPERTY = "EmuTestTraceLevel";
	private static int traceLevel = 3; // 0:disabled 1:Instruction 2:RegisterState 3:Reads-n-Writes

	private static Map<Class<?>, LogData> logDataMap = new HashMap<>();

	private static Class<?> lastTestClass;

	private static final String EMULATOR_TRACE_DISABLE_PROPERTY = "EmuTestTraceDisable";
	public static boolean traceDisabled = false;
	static {
		if (System.getProperty(EMULATOR_TRACE_DISABLE_PROPERTY) != null) {
			traceDisabled = Boolean.getBoolean(EMULATOR_TRACE_DISABLE_PROPERTY);
		}
	}

	private static final int MAX_REGDUMP_WIDTH = 80;

	private static final int EXECUTION_TIMEOUT_MS = 4 * 60000;
	private static final int MAX_EXECUTION_STEPS = 2000000;

	private static final String GZF_FILE_EXT = ".gzf";
	private static final String BINARY_FILE_EXT = ".out";

	// directory which will contain the following outputs: cache, logs, results
	private static final String TEST_OUTPUT_PATH = "test-output";

	private static final String GZF_CACHEDIR_NAME = "cache";
	private static final String LOG_DIR_NAME = "logs";
	private static final String RESULTS_DIR_NAME = "results";

	static {
		File testDir = new File(TestProgramManager.getDbTestDir(), "PCodeTest");
		TestProgramManager.setDbTestDir(testDir);
		cleanupTempData();
	}

	private static final String TEST_RESOURCE_PATH = "data/pcodetests";

	private static final String FAILURE_RESULT_NAME = "failure";

	private static final String TEST_PREFIX = "test_";

//	static {
//		forceProgramCaching();
//	}

	private static File outputDir;
	private static File resourcesCacheDir;
	private static File logDir;
	private static File resultsDir;

	private static PCodeTestCombinedTestResults combinedResults;
	private static Runnable resultsWriter;

	private static boolean initialized = false;

	protected String processorDesignator;

	private static Map<String, List<PCodeTestControlBlock>> testControlBlocksMap = new HashMap<>();

	private List<PCodeTestControlBlock> testControlBlocks;
	private HashMap<String, PCodeTestGroup> testGroupMap; // group-name -> TestGroup

	protected Language language;
	protected CompilerSpec compilerSpec;
	protected Register[] regDumpSet;
	protected Set<Register> floatRegSet;

	// set of blocks which should not be searched when looking for control structures
	protected Set<String> ignoredBlocks;

	private TestEnv env;
	private LogData logData;

	private Collection<ResourceFile> applicationRootDirectories;
	private File resourcesTestDataDir;

	private FileDataTypeManager archiveDtMgr;
	private Structure testInfoStruct;
	private Structure groupInfoStruct;

	private ParallelInstructionLanguageHelper parallelHelper;

	private static boolean deleteResultFilesOnStartup = false;

	private static void cleanupTempData() {
		FileUtilities.deleteDir(TestProgramManager.getDbTestDir());
		FileUtilities.deleteDir(new File(AbstractGTest.getTestDirectoryPath()));
	}

	public static void deleteResultFilesOnStartup() {
		deleteResultFilesOnStartup = true;
	}

	private static synchronized void initializeSharedResources() {

		if (initialized) {
			return;
		}

		System.setProperty(SystemUtilities.TESTING_PROPERTY, "true");

		try {
			ApplicationLayout layout =
				new GhidraTestApplicationLayout((new File(AbstractGTest.getTestDirectoryPath())));
			ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
			Application.initializeApplication(layout, configuration);
			initialized = true;
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}

		String outputRoot;
		if (BATCH_MODE_OUTPUT_DIR != null) {
			// Use explicit output directory root if specified
			outputRoot = BATCH_MODE_OUTPUT_DIR;
		}
		else if (!SystemUtilities.isInDevelopmentMode()) {
			outputRoot = Application.getUserTempDirectory().getAbsolutePath();
		}
		else {
			try {
				// By default, create test output within a directory at the same level as the
				// development repositories
				outputRoot = Application.getApplicationRootDirectory()
						.getParentFile()
						.getParentFile()
						.getCanonicalPath();
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		if (!(new File(outputRoot)).isDirectory()) {
			throw new RuntimeException("Output directory not found: " + BATCH_MODE_OUTPUT_DIR);
		}

		outputDir = new File(outputRoot, TEST_OUTPUT_PATH);

		Msg.info(ProcessorEmulatorTestAdapter.class,
			"Using test output directory: " + outputDir.getAbsolutePath());

		resourcesCacheDir = new File(outputDir, GZF_CACHEDIR_NAME);

		logDir = new File(outputDir, LOG_DIR_NAME);
		FileUtilities.mkdirs(logDir);

		resultsDir = new File(outputDir, RESULTS_DIR_NAME);

		if (deleteResultFilesOnStartup) {
			File xmlFile = new File(resultsDir, PCodeTestCombinedTestResults.FILENAME + ".xml");
			File htmlFile = new File(resultsDir, PCodeTestCombinedTestResults.FILENAME + ".html");
			xmlFile.delete();
			htmlFile.delete();
		}

		String levelStr = System.getProperty(EMULATOR_TRACE_LEVEL_PROPERTY);
		if (levelStr != null) {
			traceLevel = Integer.parseInt(levelStr);
		}

		try {
			combinedResults = new PCodeTestCombinedTestResults(resultsDir, true);
		}
		catch (IOException e) {
			Msg.error(ProcessorEmulatorTestAdapter.class,
				"Error occurred reading previous XML P-Code test results, file will be re-written");
			try {
				combinedResults = new PCodeTestCombinedTestResults(resultsDir, true);
			}
			catch (IOException e1) {
				throw new AssertException(); // unexpected
			}
		}

		// resultWriter now invoked by EmulationTestSuite run instead of shutdown hook
		resultsWriter = () -> {
			if (combinedResults == null) {
				return;
			}
			try {
				combinedResults.saveToXml();
				combinedResults.saveToHTML();

				// cleanup
				//TestEnv.
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		};

		// Runtime.getRuntime().addShutdownHook(new Thread(resultsWriter, "Results Writer"));
	}

	public ProcessorEmulatorTestAdapter(String name, String languageID, String compilerSpecID,
			String[] regDumpSetNames)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		this(name, languageID, compilerSpecID, regDumpSetNames, null);
	}

	public ProcessorEmulatorTestAdapter(String name, String languageID, String compilerSpecID,
			String[] regDumpSetNames, String[] floatRegSetNames)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		super(name);

		if (FAILURE_RESULT_NAME.equals(name)) {
			return; // simple construction for failure case
		}

		initializeSharedResources();

		try {
			processorDesignator = getProcessorDesignator();

			LanguageService languageService = DefaultLanguageService.getLanguageService();
			language = languageService.getLanguage(new LanguageID(languageID));
			compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(compilerSpecID));

			Register pcReg = language.getProgramCounter();
			if (pcReg == null ||
				pcReg.getMinimumByteSize() < language.getDefaultSpace().getPointerSize()) {
				throw new AssertException(
					"Language must define properly sized program-counter register in pspec");
			}

			parallelHelper = language.getParallelInstructionHelper();

			// build register dump set
			regDumpSet = getRegisters(regDumpSetNames);

			// build floatRegSet
			floatRegSet = new HashSet<>(Arrays.asList(getRegisters(floatRegSetNames)));

		}
		catch (LanguageNotFoundException e) {
			Msg.error(this, getClass().getSimpleName() + " instantiation error", e);
			throw e;
		}
		catch (CompilerSpecNotFoundException e) {
			Msg.error(this, getClass().getSimpleName() + " instantiation error", e);
			throw e;
		}
		catch (RuntimeException e) {
			Msg.error(this, getClass().getSimpleName() + " instantiation error", e);
			throw e;
		}
	}

	private Register[] getRegisters(String[] regNames) {
		if (regNames == null) {
			return new Register[0];
		}
		Register[] regs = new Register[regNames.length];
		for (int i = 0; i < regNames.length; i++) {
			Register reg = language.getRegister(regNames[i]);
			if (reg == null) {
				throw new IllegalArgumentException("Undefined " + processorDesignator + " (" +
					language.getLanguageID() + ") dump register: " + regNames[i]);
			}
			regs[i] = reg;
		}
		return regs;
	}

	protected final void setIgnoredBlocks(String... blockNames) {
		ignoredBlocks = new HashSet<>();
		for (String name : blockNames) {
			ignoredBlocks.add(name);
		}
	}

	private AddressSetView getRestrictedSearchSet(Program program) {
		if (ignoredBlocks == null) {
			return program.getMemory().getLoadedAndInitializedAddressSet();
		}
		AddressSet set = new AddressSet();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isInitialized() && !ignoredBlocks.contains(block.getName())) {
				set.add(block.getStart(), block.getEnd());
			}
		}
		return set;
	}

//	/**
//	 * Force use of program DB cache to avoid re-import and analysis of binaries
//	 * during single run.
//	 */
//	private static void forceProgramCaching() {
//
//		String dirPath = System.getProperty(TEST_DB_PARM);
//		if (dirPath != null) {
//			return; // already enabled by batch test environment
//		}
//
//		String tmpDir = System.getProperty("java.io.tmpdir");
//		File cacheDir = new File(tmpDir, "EmulatorDBTestCache");
//		if (cacheDir.exists() && !FileUtilities.deleteDir(cacheDir)) {
//			Msg.warn(ProcessorEmulatorTestAdapter.class,
//				"Unable to remove existing program cache: " + cacheDir);
//			return;
//		}
//		if (!cacheDir.mkdir()) {
//			Msg.warn(ProcessorEmulatorTestAdapter.class, "Unable to create program cache: " +
//				cacheDir);
//			return;
//		}
//
//		String cachePath = cacheDir.getAbsolutePath();
//		Msg.info(ProcessorEmulatorTestAdapter.class, "Forcing use of program DB cache: " +
//			cachePath);
//		System.setProperty(TEST_DB_PARM, cachePath);
//
//		Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
//			public void run() {
//				// try to remove program cache
//				FileUtilities.deleteDir(getDbTestDir());
//			}
//		}));
//
//	}

	private static Map<Class<?>, MyTestFailure> testFailureMap = new HashMap<>();

	private static Throwable getCause(Throwable t) {
		if (t instanceof InvocationTargetException) {
			t = ((InvocationTargetException) t).getCause();
		}
		return t;
	}

	private static class MyTestFailure extends TestSuite {

		private Throwable failure;

		MyTestFailure(Class<?> emulatorTestClass, Throwable failure) {
			this.failure = failure;
			addTest(TestSuite.createTest(emulatorTestClass, FAILURE_RESULT_NAME));
		}

		void throwFailure() throws Exception {
			if (failure instanceof Error) {
				throw (Error) failure;
			}
			if (failure instanceof Exception) {
				throw (Exception) failure;
			}
			AssertionFailedError error = new AssertionFailedError("Severe Failure");
			error.initCause(failure);
		}
	}

	public static Test getTestFailure(Class<?> emulatorTestClass, String message, Throwable t) {
		if (t == null) {
			t = new AssertionFailedError(message);
		}
		MyTestFailure testFailure = new MyTestFailure(emulatorTestClass, getCause(t));
		testFailureMap.put(emulatorTestClass, testFailure);
		return testFailure;
	}

	/**
	 * Create TestSuite based upon available test groups contained within binary
	 * test files associated with target processor.
	 * @param emulatorTestClass test which extends <code>ProcessorEmulatorTestAdapter</code>
	 * and whose name ends with "EmulatorTest".
	 * @return test suite
	 */
	public static final Test buildEmulatorTestSuite(Class<?> emulatorTestClass) {

		// Method currently only gets invoked when running all test groups
		// For now lets limit dumping of execution state to single
		// test only, unless the property was give on command line.

		if (System.getProperty(EMULATOR_TRACE_DISABLE_PROPERTY) == null) {
			traceDisabled = true;
		}

		if (!emulatorTestClass.getSimpleName().endsWith(EMULATOR_TEST_SUFFIX)) {
			return getTestFailure(emulatorTestClass,
				"Invalid emulator test classname, must end with '" + EMULATOR_TEST_SUFFIX + "'",
				null);
		}

		if (!ProcessorEmulatorTestAdapter.class.isAssignableFrom(emulatorTestClass)) {
			return getTestFailure(emulatorTestClass,
				"Test class does not extend " + ProcessorEmulatorTestAdapter.class.getSimpleName(),
				null);
		}

		Constructor<?> constructor;
		try {
			constructor = emulatorTestClass.getConstructor(String.class);
		}
		catch (NoSuchMethodException e) {
			return getTestFailure(emulatorTestClass,
				"Class has no public constructor TestCase(String name)", null);
		}

		ProcessorEmulatorTestAdapter instance = null;
		try {
			instance = (ProcessorEmulatorTestAdapter) constructor.newInstance((String) null);
		}
		catch (Exception e) {
			return getTestFailure(emulatorTestClass, "Cannot instantiate test class", e);
		}

		try {
			instance.setUp();
			if (instance.testGroupMap == null || instance.testGroupMap.size() == 0) {
				return getTestFailure(emulatorTestClass, "No test binaries found", null);
			}
			ArrayList<PCodeTestGroup> testGroups = new ArrayList<>(instance.testGroupMap.values());
			Collections.sort(testGroups);
// TODO: May need custom test suite and implement
// public void run(TestResult result) -- which can do something after invoking super.run
			TestSuite suite = new EmulationTestSuite();
			for (PCodeTestGroup testGroup : testGroups) {
				// TODO: HACK! must prefix each test name with "test" to allow for
				// running single test within Eclipse
				suite.addTest(
					TestSuite.createTest(emulatorTestClass, TEST_PREFIX + testGroup.testGroupName));
			}
			return suite;
		}
		catch (Exception e) {
			e.printStackTrace();
			return getTestFailure(emulatorTestClass, "Exception during trial test setup", e);
		}
		finally {
			try {
				instance.tearDown();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static class EmulationTestSuite extends TestSuite {
		@Override
		public void run(TestResult result) {
			super.run(result);

			// Dump XML and HTML when suite done runnings
			resultsWriter.run();
		}
	}

	@Override
	public void log(PCodeTestGroup testGroup, String msg) {
		int index = 0;
		while (index < msg.length()) {
			int nextIndex = msg.indexOf('\n', index);
			String text;
			if (nextIndex >= 0) {
				text = msg.substring(index, nextIndex);
				index = nextIndex + 1;
			}
			else {
				text = msg.substring(index);
				index = msg.length();
			}
			if (testGroup != null) {
				text = testGroup.testGroupName + ": " + text;
			}
			if (logData.traceLog != null) {
				logData.traceLog.println(text);
			}
			System.out.println(text);
		}
	}

	@Override
	public void log(PCodeTestGroup testGroup, String msg, Throwable t) {
		log(testGroup, msg);
		log(testGroup, exceptionToString(t));
	}

	private Address getCallAddress(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.getReferenceType().isCall()) {
				return ref.getToAddress();
			}
		}
		return null;
	}

	@Override
	public void logState(EmulatorTestRunner testRunner) {
		if (traceDisabled || traceLevel <= 0) {
			return;
		}
		if (traceLevel >= 1) {
			StringBuilder buf = new StringBuilder();
			Address curAddr = testRunner.getCurrentAddress();
			SymbolTable symbolTable = testRunner.getProgram().getSymbolTable();
			Symbol s = symbolTable.getPrimarySymbol(curAddr);
			if (s != null) {
				buf.append("<<");
				buf.append(s.getName());
			}
			Instruction instr = testRunner.getCurrentInstruction();
			buf.append(">> ");
			buf.append(curAddr.toString(true));
			buf.append(" ");
			if (instr != null) {

				if (parallelHelper != null) {
					String prefix = parallelHelper.getMnemonicPrefix(instr);
					if (prefix != null) {
						buf.append(prefix);
						buf.append(' ');
					}
				}

				buf.append(instr.toString());

				if (instr.getDelaySlotDepth() != 0) {
					buf.append(" (delay-slots not shown)");
				}
				if (instr.getFlowType().isCall()) {
					// output call reference
					Address callAddr = getCallAddress(instr);
					if (callAddr != null) {
						s = symbolTable.getPrimarySymbol(callAddr);
						if (s != null) {
							buf.append(" (call -> ");
							buf.append(s.getName());
							buf.append(")");
						}
					}
				}
			}
			log(testRunner.getTestGroup(), buf.toString());
		}
		if (traceLevel >= 2) {
			StringBuilder buf1 = new StringBuilder(" ");
			StringBuilder buf2 = new StringBuilder(" ");
			int width = 0;
			for (Register reg : regDumpSet) {
				String regName = reg.getName();
				int len = Math.max(regName.length(), (reg.getMinimumByteSize() * 2));
				width += len;
				if (width > MAX_REGDUMP_WIDTH) {
					log(testRunner.getTestGroup(), buf1.toString());
					log(testRunner.getTestGroup(), buf2.toString());
					buf1 = new StringBuilder(" ");
					buf2 = new StringBuilder(" ");
					width = len;
				}
				buf1.append(regName);
				buf1.append(' ');
				buf2.append(testRunner.getRegisterValueString(reg));
				buf2.append(' ');
				int diff = buf1.length() - buf2.length();
				for (int n = diff; n < 0; n++) {
					buf1.append(' ');
				}
				for (int n = diff; n > 0; n--) {
					buf2.append(' ');
				}
			}
			if (buf1.length() > 1) {
				log(testRunner.getTestGroup(), buf1.toString());
				log(testRunner.getTestGroup(), buf2.toString());
			}
		}
	}

	private static abstract class DumpFormatter {
		final int elementSize;
		final boolean bigEndian;

		DumpFormatter(int elementSize, boolean bigEndian) {
			this.elementSize = elementSize;
			this.bigEndian = bigEndian;
		}

		abstract int getMaxWidth();

		abstract String getString(byte[] bytes, int index);
	}

	private static class HexFormatter extends DumpFormatter {
		HexFormatter(int elementSize, boolean bigEndian) {
			super(elementSize, bigEndian);
		}

		@Override
		int getMaxWidth() {
			return 2 * elementSize;
		}

		@Override
		String getString(byte[] bytes, int index) {
			BigInteger val = bigEndian
					? BigEndianDataConverter.INSTANCE.getBigInteger(bytes, index, elementSize,
						false)
					: LittleEndianDataConverter.INSTANCE.getBigInteger(bytes, index, elementSize,
						false);
			String valStr = val.toString(16);
			return StringUtilities.pad(valStr, '0', 2 * elementSize);
		}
	}

	private static class DecimalFormatter extends DumpFormatter {
		DecimalFormatter(int elementSize, boolean bigEndian) {
			super(elementSize, bigEndian);
		}

		@Override
		int getMaxWidth() {
			byte[] sampleBytes = new byte[elementSize];
			sampleBytes[0] = (byte) 0x80;
			BigInteger sample = new BigInteger(-1, sampleBytes);
			return sample.toString().length();
		}

		@Override
		String getString(byte[] bytes, int index) {
			BigInteger val = bigEndian
					? BigEndianDataConverter.INSTANCE.getBigInteger(bytes, index, elementSize, true)
					: LittleEndianDataConverter.INSTANCE.getBigInteger(bytes, index, elementSize,
						true);
			return val.toString();
		}
	}

	private static class FloatFormatter extends DumpFormatter {
		private final FloatFormat ff;
		private final int maxWidth;

		FloatFormatter(int elementSize, boolean bigEndian) {
			super(elementSize, bigEndian);
			ff = FloatFormatFactory.getFloatFormat(elementSize);
			maxWidth = ff.round(ff.maxValue).negate().toString().length();
		}

		@Override
		int getMaxWidth() {
			return maxWidth;
		}

		@Override
		String getString(byte[] bytes, int index) {
			BigInteger encoding = bigEndian
					? BigEndianDataConverter.INSTANCE.getBigInteger(bytes, index, elementSize,
						false)
					: LittleEndianDataConverter.INSTANCE.getBigInteger(bytes, index, elementSize,
						false);
			BigDecimal val = ff.round(ff.getHostFloat(encoding));
			return val.toString();
		}
	}

	@Override
	public void logState(EmulatorTestRunner emulatorTestRunner, Address dumpAddr, int dumpSize,
			int elementSize, DumpFormat elementFormat, String comment) {

		if (dumpSize == 0) {
			return;
		}

		DumpFormatter dumpFormatter;
		if (elementFormat == DumpFormat.FLOAT) {
			dumpFormatter = new FloatFormatter(elementSize, language.isBigEndian());
		}
		else if (elementFormat == DumpFormat.DECIMAL) {
			dumpFormatter = new DecimalFormatter(elementSize, language.isBigEndian());
		}
		else {
			dumpFormatter = new HexFormatter(elementSize, language.isBigEndian());
		}

		int maxElementWidth = dumpFormatter.getMaxWidth();
		int elementsPerRow = (80 - dumpAddr.toString().length()) / (maxElementWidth + 1);
		if (elementsPerRow > 16) {
			elementsPerRow = 16;
		}
		else if (elementsPerRow > 8) {
			elementsPerRow = 8;
		}
		else if (elementsPerRow > 4) {
			elementsPerRow = 4;
		}
		else if (elementsPerRow == 0) {
			elementsPerRow = 1;
		}

		int byteCount = dumpSize * elementSize;

		byte[] bytes = emulatorTestRunner.getEmulatorHelper().readMemory(dumpAddr, byteCount);
		int index = 0;

		log(null, "MEMORY DUMP (" + elementFormat + "): " + comment);
		while (index < byteCount) {
			StringBuilder buf = new StringBuilder();
			buf.append("  ");
			buf.append(dumpAddr.toString(true));
			buf.append(":");
			for (int i = 0; i < elementsPerRow && index < byteCount; i++) {
				String valStr = dumpFormatter.getString(bytes, index);
				index += elementSize;
				valStr = StringUtilities.pad(valStr, ' ', maxElementWidth + 1);
				buf.append(valStr);
			}
			log(null, buf.toString());
			if (index < byteCount) {
				dumpAddr = dumpAddr.add(elementsPerRow * elementSize);
			}
		}
	}

	private void logUnimplemented(TreeSet<String> unimplementedSet) {
		if (unimplementedSet.isEmpty()) {
			return;
		}
		log(null, "Summary of Unimplemented Pcodeops encountered (CALLOTHER):");
		for (String name : unimplementedSet) {
			log(null, "   " + name);
		}
	}

	private byte[] flipBytes(byte[] bytes) {
		int index = bytes.length;
		byte[] flippedBytes = new byte[bytes.length];
		for (byte b : bytes) {
			flippedBytes[--index] = b;
		}
		return flippedBytes;
	}

	private String formatAssignmentString(Address address, int size, byte[] values) {
		if (!language.isBigEndian()) {
			values = flipBytes(values);
		}

		Register reg = language.getRegister(address, size);

		String name = reg != null ? reg.getName() : (address.toString(true) + ":" + size);

		String floatStr = "";
		if (reg != null && floatRegSet.contains(reg)) {
			FloatFormat floatFormat = FloatFormatFactory.getFloatFormat(size);
			BigDecimal hostFloat =
				floatFormat.round(floatFormat.getHostFloat(new BigInteger(1, values)));
			floatStr = " (" + hostFloat.toString() + ")";
		}

		return name + "=0x" + NumericUtilities.convertBytesToString(values, "") + floatStr;
	}

	@Override
	public void logRead(EmulatorTestRunner testRunner, Address address, int size, byte[] values) {
		if (traceLevel < 3) {
			return;
		}
		log(testRunner.getTestGroup(), " Read " + formatAssignmentString(address, size, values));
	}

	@Override
	public void logWrite(EmulatorTestRunner testRunner, Address address, int size, byte[] values) {
		if (traceLevel < 3) {
			return;
		}
		log(testRunner.getTestGroup(), " Write " + formatAssignmentString(address, size, values));
	}

	@Override
	public void stepCompleted(EmulatorTestRunner testRunner) {
		logState(testRunner);
	}

	/**
	 * Converts the stack trace into a string
	 */
	private static String exceptionToString(Throwable t) {
		StringWriter stringWriter = new StringWriter();
		PrintWriter writer = new PrintWriter(stringWriter);
		t.printStackTrace(writer);
		return stringWriter.toString();
	}

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

	@Override
	protected void setUp() throws Exception {

		env = new TestEnv();
		applicationRootDirectories = Application.getApplicationRootDirectories();

		ResourceFile myModuleRootDirectory =
			Application.getModuleContainingClass(getClass().getName());
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

		if (resourcesTestDataDir == null || !resourcesTestDataDir.isDirectory()) {
			throw new RuntimeException(
				"Failed to locate pcodetest resource directory: " + TEST_RESOURCE_PATH);
		}

		logData = initializeLog(getClass());

		if (FAILURE_RESULT_NAME.equals(getName())) {
			// running a failure case so we can produce junit failure result
			logData.testResults.summaryHasIngestErrors = true;
			testFailureMap.get(getClass()).throwFailure();
		}

		ResourceFile emuTestingArchive = Application.getModuleDataFile("pcodetest/EmuTesting.gdt");
		archiveDtMgr = FileDataTypeManager.openFileArchive(emuTestingArchive, false);
		DataType dt = archiveDtMgr.getDataType(CategoryPath.ROOT, TEST_INFO_STRUCT_NAME);
		if (dt == null || !(dt instanceof Structure)) {
			fail(TEST_INFO_STRUCT_NAME +
				" structure data-type not found in resource EmuTesting.gdt");
		}
		testInfoStruct = (Structure) dt;

		dt = archiveDtMgr.getDataType(CategoryPath.ROOT, GROUP_INFO_STRUCT_NAME);
		if (dt == null || !(dt instanceof Structure)) {
			fail(GROUP_INFO_STRUCT_NAME +
				" structure data-type not found in resource EmuTesting.gdt");
		}
		groupInfoStruct = (Structure) dt;

		testControlBlocks = testControlBlocksMap.get(processorDesignator);
		if (testControlBlocks == null) {
			try {
				ingestTestBinaries();
			}
			catch (RuntimeException e) {
				e.printStackTrace(logData.traceLog);
				logData.testResults.addSevereFailResult("", "TestFileIngest");
				throw e;
			}
			testControlBlocksMap.put(processorDesignator, testControlBlocks);
		}

		testGroupMap = new HashMap<>();
		for (PCodeTestControlBlock testControlBlock : testControlBlocks) {
			for (PCodeTestGroup testGroup : testControlBlock.getTestGroups()) {
				testGroupMap.put(testGroup.testGroupName, testGroup);
				//System.out.println("test_" + testGroup.testGroupName);
			}
		}
	}

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

	private static class LogData {
		File traceFile;
		PrintWriter traceLog;
		PCodeTestResults testResults;
		private TreeSet<String> unimplementedSet = new TreeSet<>();
	}

	private static LogData initializeLog(Class<?> testClass) throws FileNotFoundException {

		try {
			LogData data = logDataMap.get(testClass);
			if (data == null) {
				data = new LogData();
				logDataMap.put(testClass, data);

				data.testResults = combinedResults.getTestResults(testClass.getSimpleName(), true);
				data.testResults.clear();

				data.traceFile = new File(logDir, testClass.getSimpleName() + ".log");
				if (data.traceFile.exists()) {
					data.traceFile.delete();
				}

			}
			else {

				// Test has previously been run so we know ingest initialization has already been
				// completed.  If test class is switching we can flush that tests results to HTML
				// file.
				if (lastTestClass != null && !lastTestClass.equals(testClass)) {
					resultsWriter.run(); // write out html results on test change
				}

				if (data.traceLog != null) {
					return data;
				}
			}

			data.traceLog = new PrintWriter(new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(data.traceFile, true))));

			data.traceLog.println((new Date()).toString());

			return data;
		}
		finally {
			lastTestClass = testClass;
		}
	}

	@Override
	protected void tearDown() throws Exception {
		if (logData != null && logData.traceLog != null) {
			logUnimplemented(logData.unimplementedSet);
			logData.traceLog.flush();
			logData.traceLog.close();
			logData.traceLog = null;
		}
		if (archiveDtMgr != null) {
			archiveDtMgr.close();
		}
		if (env != null) {
			env.dispose();
		}
		super.tearDown();
	}

	/**
	 * Single unit test which handles named test group specified during test
	 * instantiation.
	 */
	@Override
	public final void runTest() {

		String testGroupName = getName();

		// TODO: HACK! Must strip "test" prefix which was added to original group name
		// to facilitate running single test in Eclipse
		if (testGroupName != null) {
			if (testGroupName.startsWith(TEST_PREFIX)) {
				testGroupName = testGroupName.substring(TEST_PREFIX.length());
			}
			else {
				fail("Expected test name to start with " + TEST_PREFIX);
			}
		}

		if (testGroupName == null || testGroupName.length() == 0) {
			fail("Empty test group name");
		}

		PCodeTestGroup testGroup = testGroupMap.get(testGroupName);
		assertNotNull("TestGroup not found for '" + testGroupName + "'", testGroup);

		log(testGroup, "Prepare for executing group test '" + testGroup.testGroupName + "' at: " +
			testGroup.functionEntryPtr.toString(true));

		log(testGroup,
			"Loading test binary: " + testGroup.mainTestControlBlock.testFile.fileReferencePath);

		log(testGroup, "Using cached program: " + testGroup.mainTestControlBlock.cachedProgramPath);

		Program program = null;
		EmulatorTestRunner testRunner = null;
		try {
			program = getGzfProgram(testGroup.mainTestControlBlock.cachedProgramPath);

			assertNotNull(
				"Failed to open test program: " + testGroup.mainTestControlBlock.cachedProgramPath,
				program);

			if (program.isChanged()) {
				// update cached program
				String fpath = testGroup.mainTestControlBlock.testFile.fileReferencePath;
				Msg.info(ProcessorEmulatorTestAdapter.class,
					"Updating cached gzf file following program upgrade: " + fpath);
				File gzfFile = new File(resourcesCacheDir, fpath + GZF_FILE_EXT);
				env.getGhidraProject().saveAsPackedFile(program, gzfFile, true);
				if (!gzfFile.exists()) {
					throw new IOException("Failed to cache gzf file: " + gzfFile);
				}
			}

			assertFalse(
				"Program contains severe disassembly/relocation errors: " +
					testGroup.mainTestControlBlock.cachedProgramPath,
				logData.testResults.summaryHasRelocationErrors ||
					logData.testResults.summaryHasDisassemblyErrors);

			testRunner = new EmulatorTestRunner(program, testGroup, this);

			// Clear hard-coded stack pointer value established by SimpleProgramLoadData.
			// If not set by initializeState checkStackPointerValue will attempt to initialize
			// TODO: not required if use of SimpleProgramLoadData eliminated
			testRunner.setRegister(compilerSpec.getStackPointer().getName(), 0);

			// Initialize context register based upon function entry within listing
			Address address = EmulatorTestRunner.alignAddress(testGroup.functionEntryPtr,
				language.getInstructionAlignment());
			ProgramContext programContext = program.getProgramContext();
			Register contextRegister = programContext.getBaseContextRegister();
			if (contextRegister != null) {
				testRunner.setContextRegister(
					programContext.getRegisterValue(contextRegister, address));
			}

			initializeState(testRunner, program);

			checkStackPointerValue(testRunner);

			int totalExpectedAsserts = 0;
			int numSubTests = testGroup.controlBlock.getNumberFunctions();
			for (int i = 1; i < numSubTests; i++) {
				FunctionInfo functionInfo = testGroup.controlBlock.getFunctionInfo(i);
				String name = functionInfo.functionName;
				logData.testResults.declareTest(testGroup.testGroupName, name,
					functionInfo.numberOfAsserts);
				totalExpectedAsserts += functionInfo.numberOfAsserts;
			}

			// Initialize pass/fail counts at runtime to detect severe failure
			testGroup.mainTestControlBlock.setNumberPassed(testRunner, Integer.MIN_VALUE);
			testGroup.mainTestControlBlock.setNumberFailed(testRunner, Integer.MIN_VALUE);

			boolean done;
			if (traceDisabled) {
				done = testRunner.execute(EXECUTION_TIMEOUT_MS, TaskMonitor.DUMMY);
			}
			else {
				done = testRunner.executeSingleStep(MAX_EXECUTION_STEPS);
			}

			int pass = testGroup.mainTestControlBlock.getNumberPassed(testRunner);
			int callOtherErrors = testRunner.getCallOtherErrors();
			int fail = testGroup.mainTestControlBlock.getNumberFailed(testRunner);

			if (pass < 0 || fail < 0) {
				failTest(testRunner,
					"ERROR Invalid pass/fail counts - test may not have run properly or improper TestInfo structure updates occurred: pass " +
						pass + " fail " + fail);
			}

			pass -= callOtherErrors;

			String passFailText = "Passed: " + pass + " Failed: " + fail;
			if (callOtherErrors != 0) {
				passFailText += " Passed(w/CALLOTHER): " + callOtherErrors;
			}
			passFailText += " Expected Assertions: " + totalExpectedAsserts;
			log(testGroup, passFailText);

			List<String> testFailures = testGroup.getTestFailures();
			if (!testFailures.isEmpty()) {
				log(testGroup, "TEST FAILURES:");
				for (String testFailure : testFailures) {
					log(testGroup, " >>> " + testFailure);
				}
			}

			if (!done) {
				StringBuilder msg = new StringBuilder("ERROR Test execution failed");

				// TODO: not currently set until assert function has been emulated
				//String lastFunction = testGroup.mainTestControlBlock.getLastFunctionName(testRunner);

				String emuError = testRunner.getEmuError();
				if (emuError != null) {
					msg.append(" - ");
					msg.append(emuError);
				}
				Address pcAddr = testRunner.getCurrentAddress();
				String pcStr = Long.toHexString(pcAddr.getOffset());
				if ((emuError == null) || (emuError.indexOf(pcStr) < 0)) {
					msg.append(", pc=0x");
					msg.append(pcStr);
				}
				failTest(testRunner, msg.toString());
			}
			int ranCnt = pass + fail + callOtherErrors;
			if ((totalExpectedAsserts != 0) && (totalExpectedAsserts != ranCnt)) {
				failTest(testRunner,
					"ERROR Unexpected number of assertions ( " + passFailText + " )");
			}
			if (fail != 0 || callOtherErrors != 0 || testFailures.size() != 0) {
				failTest(testRunner,
					"ERROR One or more group tests failed ( " + passFailText + " )");
			}

		}
		catch (Exception e) {
			log(testGroup, "Exception occurred during test", e);
			fail("Exception occurred during test: " + e.getMessage());
		}
		finally {
			if (testRunner != null) {
				logData.unimplementedSet.addAll(testRunner.getUnimplementedPcodeops());
				testRunner.dispose();
			}
			if (program != null) {
				env.release(program);
			}
		}
	}

	private void checkStackPointerValue(EmulatorTestRunner testRunner) {
		Program program = testRunner.getProgram();
		Register spReg = compilerSpec.getStackPointer();
		if (spReg != null) {
			RegisterValue spValue = testRunner.getRegisterValue(spReg);
			long stackOffset = spValue.getUnsignedValue().longValue();
			if (stackOffset == 0) { // default uninitialized value is 0
				initStackPointer(testRunner, spReg);
			}
			AddressSpace stackSpace = compilerSpec.getStackBaseSpace();
			if (stackSpace != null) {
				Address stackPtr = stackSpace.getAddress(stackOffset);
				if (program.getMemory().getLoadedAndInitializedAddressSet().contains(stackPtr)) {
					fail("Stack pointer defined within initialized memory region: " + stackPtr);
				}
			}
		}
	}

	private Symbol findAnyMatchingSymbol(Program program, String... names) {
		for (String name : names) {
			if (name == null) {
				continue;
			}
			Symbol s =
				SymbolUtilities.getExpectedLabelOrFunctionSymbol(program, name, m -> m.toString()); // error ignored
			if (s != null) {
				return s;
			}
		}
		return null;
	}

	private void initStackPointer(EmulatorTestRunner testRunner, Register spReg) {
		Program program = testRunner.getProgram();
		Symbol stackSymbol = findAnyMatchingSymbol(program, getPreferredStackSymbolName(), "_stack",
			"stack", "__STACK_START");
		if (stackSymbol != null) {
			long stackOffset = stackSymbol.getAddress().getAddressableWordOffset();
			testRunner.setRegister(spReg.getName(), stackOffset);
			log(null, "Stack Pointer (" + spReg.getName() + ") auto-assigned using symbol '" +
				stackSymbol.getName() + "' offset: 0x" + Long.toHexString(stackOffset));
		}
		else {
			log(null, "Stack Pointer (" + spReg.getName() + ") using default offset: 0");
		}
	}

	/**
	 * Get symbol name which defines initial stack pointer offset
	 * @return stack symbol or null
	 */
	protected String getPreferredStackSymbolName() {
		return null;
	}

	private void failTest(EmulatorTestRunner testRunner, String msg) {
		log(testRunner.getTestGroup(), msg);
		checkInstructionDecodeFailure(testRunner);
		fail(msg);
	}

	private void checkInstructionDecodeFailure(EmulatorTestRunner testRunner) {
		// assume general error has already been logged
		String emuError = testRunner.getEmuError();
		if (emuError == null || (emuError.indexOf("Instruction decode failed") < 0) ||
			(emuError.indexOf("Uninitialized Memory") > 0)) {
			return;
		}

		Address currentAddr = testRunner.getCurrentAddress();

		// dump context register state if decode failure
		RegisterValue contextRegValue =
			testRunner.getEmulatorHelper().getEmulator().getContextRegisterValue();
		if (contextRegValue == null) {
			return;
		}
		StringBuilder buf = new StringBuilder("Context register state at: ");
		buf.append(currentAddr.toString(true));
		for (Register contextField : contextRegValue.getRegister().getChildRegisters()) {
			RegisterValue ctxValue = contextRegValue.getRegisterValue(contextField);
			String valueStr = ctxValue.getUnsignedValueIgnoreMask().toString(16);
			buf.append("\n  ");
			buf.append(contextField.getName());
			buf.append(" = 0x");
			buf.append(valueStr);
		}
		log(testRunner.getTestGroup(), buf.toString());

		// If parse OK within program - check for modified bytes within emu memory state
		Program program = testRunner.getProgram();
		boolean inDelaySlot = false;
		DumbMemBufferImpl memBuf = new DumbMemBufferImpl(program.getMemory(), currentAddr);
		DisassemblerContextImpl context = new DisassemblerContextImpl(program.getProgramContext());
		try {
			context.flowStart(currentAddr);
			context.setRegisterValue(contextRegValue);
			InstructionPrototype proto = language.parse(memBuf, context, false);
			int len = proto.getLength();
			if (proto.hasDelaySlots()) {
				// TODO: Avoid use of InstructionContext by just guessing at potential byte count
				len *= 3;
			}

			// check for memory modification
			byte[] emuBytes = testRunner.getEmulatorHelper().readMemory(currentAddr, len);
			byte[] programBytes = new byte[emuBytes.length];
			program.getMemory().getBytes(currentAddr, programBytes);
			if (!Arrays.equals(emuBytes, programBytes)) {
				buf = new StringBuilder(
					"Instruction bytes differ between program and emulator state at: ");
				buf.append(currentAddr.toString(true));
				if (inDelaySlot) {
					buf.append(" (includes delay-slots)");
				}
				buf.append("\n");
				buf.append("  Program Bytes:  ");
				buf.append(NumericUtilities.convertBytesToString(programBytes, " "));
				buf.append("\n");
				buf.append("  Emulator Bytes: ");
				buf.append(NumericUtilities.convertBytesToString(emuBytes, " "));
				log(testRunner.getTestGroup(), buf.toString());
			}
			else {
				log(testRunner.getTestGroup(),
					"Test unable to determine cause of instruction parse failure");
			}
			return; // if not byte difference - not sure what cause is
		}
		catch (UsrException e) {
			if (inDelaySlot) {
				log(testRunner.getTestGroup(),
					"Instruction parse error occurred in delay-slot at: " +
						memBuf.getAddress().toString(true));
			}
			// parse failed
		}

		// Run parse debug
		SleighDebugLogger logger =
			new SleighDebugLogger(memBuf, context, language, SleighDebugMode.VERBOSE);
		log(testRunner.getTestGroup(), logger.toString());

	}

	/**
	 * Get the maximum defined memory address ignoring any overlays which have been defined.
	 * @return max defined physical address
	 */
	protected static final Address getMaxDefinedMemoryAddress(Program program) {
		Address maxAddr = null;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getStart().getAddressSpace().isOverlaySpace()) {
				continue;
			}
			if (maxAddr == null || maxAddr.compareTo(block.getEnd()) < 0) {
				maxAddr = block.getEnd();
			}
		}
		return maxAddr;
	}

	//
	// Protected helper methods which may be overriden
	//

	/**
	 * Get the processor designator used to identify test binary files/folder.
	 * The default implementation requires the JUnit test class name to end with
	 * "EmulatorTest" where the portion of the name proceeding this suffix will be
	 * used as the processor designator
	 * @return processor designator
	 */
	protected String getProcessorDesignator() {
		String className = getClass().getSimpleName();
		if (!className.endsWith(EMULATOR_TEST_SUFFIX)) {
			throw new RuntimeException(
				"Invalid emulator test classname, must end with '" + EMULATOR_TEST_SUFFIX + "'");
		}
		return className.substring(0, className.length() - EMULATOR_TEST_SUFFIX.length());
	}

	/**
	 * Get CUint file designator if use of A, B, C... is not suitable.
	 * @param fileIndex file index within sorted list
	 * @param filePath binary file path
	 * @return short file designator for use in qualified test name
	 */
	protected String buildTestFileDesignator(int fileIndex, String filePath) {
		return null;
	}

	/**
	 * Invoked for each program immediately prior to executing a test group.
	 * By default this method will initialize the register states based upon the 
	 * specific register values/context stored at the test group function entry point.
	 * Such register values may have been established via the processor specification,
	 * loader or analyzers.  A specific test may override or extend
	 * this behavior for other registers as needed.
	 * @param testRunner emulator group test runner/facilitator
	 * @param program
	 * @throws Exception if initialization criteria has not been satisfied
	 */
	protected void initializeState(EmulatorTestRunner testRunner, Program program)
			throws Exception {
		Address addr = testRunner.getTestGroup().functionEntryPtr;
		addr = PseudoDisassembler.getNormalizedDisassemblyAddress(program, addr);
		ProgramContext programContext = program.getProgramContext();
		for (Register reg : programContext.getRegisters()) {
			if (reg.isProcessorContext() || reg.isProgramCounter()) {
				continue;
			}
			RegisterValue value = programContext.getRegisterValue(reg, addr);
			if (value != null && value.hasValue()) {
				log(testRunner.getTestGroup(),
					"Initialized register " + reg.getName() + "=0x" +
						value.getUnsignedValue().toString(16) + " using context at " +
						addr.toString(true));
				testRunner.setRegister(reg.getName(), value.getUnsignedValue());
			}
		}
	}

	/**
	 * Invoked immediately following import allow byte processing prior to
	 * control structure identification.
	 * NOTE: This method will only be invoked once during the first test setup
	 * for all test binaries found.  This method will not be invoked
	 * during subsequent tests since the analyzed program will be cached.
	 * @param program
	 * @throws Exception
	 */
	protected void postImport(Program program) throws Exception {
		// optional: may be implemented by test
	}

	/**
	 * Invoked prior to analysis to allow analysis options or other pre-analysis
	 * inspection/modification to be performed.
	 * NOTE: This method will only be invoked once during the first test setup
	 * for all test binaries found.  This method will not be invoked
	 * during subsequent tests since the analyzed program will be cached.
	 * @param program
	 * @throws Exception
	 */
	protected void preAnalyze(Program program) throws Exception {
		// optional: may be implemented by test
	}

	/**
	 * Invoked for non-gzf files immediately after the analyze method to
	 * perform any follow-up changes of inspection of the program.
	 * NOTE: This method will only be invoked once during the first test setup
	 * for all test binaries found.  This method will not be invoked
	 * during subsequent tests since the analyzed program will be cached.
	 * @param program
	 * @throws Exception
	 */
	protected void postAnalyze(Program program) throws Exception {
		// optional: may be implemented by test
	}

	/**
	 * Invoked for non-gzf files to perform auto-analysis.
	 * NOTE: This method will only be invoked once during the first test setup
	 * for all test binaries found.  This method will not be invoked
	 * during subsequent tests since the analyzed program will be cached.
	 * @param program
	 * @throws Exception
	 */
	protected void analyze(Program program, PCodeTestControlBlock testControlBlock)
			throws Exception {

		setAnalysisOptions(program.getOptions(Program.ANALYSIS_PROPERTIES));

		GhidraProgramUtilities.setAnalyzedFlag(program, true);

		// Remove all single-byte functions created by Elf importer
		// NOTE: This is a known issues with optimized code and symbols marked as ElfSymbol.STT_FUNC
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			if (function.getBody().getNumAddresses() == 1) {
				function.getSymbol().delete();
			}
		}

		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		analysisMgr.cancelQueuedTasks(); // GhidraProject import utility jumped the gun with analysis initialization
		analysisMgr.initializeOptions();

		// ensure that all known functions have been disassembled
		AddressSet disassembleStarts = new AddressSet();

		addFunctionStartDisassemblyPoint(testControlBlock.getBreakOnDoneAddress(), "breakOnDone",
			disassembleStarts, program);
		addFunctionStartDisassemblyPoint(testControlBlock.getBreakOnPassAddress(), "breakOnPass",
			disassembleStarts, program);
		addFunctionStartDisassemblyPoint(testControlBlock.getBreakOnErrorAddress(), "breakOnError",
			disassembleStarts, program);
		addFunctionStartDisassemblyPoint(testControlBlock.getSprintf5Address(), "printf5",
			disassembleStarts, program);

		int functionCnt = testControlBlock.getNumberFunctions();
		for (int i = 0; i < functionCnt; i++) {
			FunctionInfo functionInfo = testControlBlock.getFunctionInfo(i);
			addFunctionStartDisassemblyPoint(functionInfo.functionAddr, functionInfo.functionName,
				disassembleStarts, program);
		}

		for (PCodeTestGroup testGroup : testControlBlock.getTestGroups()) {
			functionCnt = testGroup.controlBlock.getNumberFunctions();
			for (int i = 0; i < functionCnt; i++) {
				FunctionInfo functionInfo = testGroup.controlBlock.getFunctionInfo(i);
				addFunctionStartDisassemblyPoint(functionInfo.functionAddr,
					functionInfo.functionName, disassembleStarts, program);
			}
		}

		new DisassembleCommand(disassembleStarts, null).applyTo(program);

		new CreateFunctionCmd(disassembleStarts).applyTo(program);

		analysisMgr.reAnalyzeAll(null);
		analysisMgr.startAnalysis(TaskMonitor.DUMMY); // method blocks during analysis

		// Apply known function signatures
		// Signatures with Float types have been excluded due to limited calling convention support
		ArrayList<DataTypeManager> dtMgrList = new ArrayList<>();
		dtMgrList.add(archiveDtMgr);
		ApplyFunctionDataTypesCmd cmd =
			new ApplyFunctionDataTypesCmd(dtMgrList, null, SourceType.ANALYSIS, true, false);
		cmd.applyTo(program);

		// Apply various *_main and *_Main test function signatures
		Pointer testInfoStructPtrType = new PointerDataType(testInfoStruct);
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			String name = func.getName();
			if (name.endsWith("_Main")) {
				func.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
			}
			else if (name.endsWith("_main")) {
				func.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
				func.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false,
					SourceType.ANALYSIS, new ParameterImpl("ti", testInfoStructPtrType, program));
			}
		}

	}

	protected void setAnalysisOptions(Options analysisOptions) {
		analysisOptions.setBoolean("Stack", false);
		analysisOptions.setBoolean("DWARF", false);
		analysisOptions.setBoolean("Create Address Tables", false);
	}

	private void addFunctionStartDisassemblyPoint(Address functionAddr, String functionName,
			AddressSet disassembleStarts, Program program) {

		Symbol s = program.getSymbolTable().getPrimarySymbol(functionAddr);
		if (s == null || s.isDynamic() ||
			s.getName().equals(SymbolUtilities.getDefaultFunctionName(functionAddr))) {
			createSymbol(functionAddr, functionName, program);
		}

		Listing listing = program.getListing();

		CodeUnit cu = listing.getCodeUnitAt(functionAddr);
		if (cu instanceof Instruction) {
			return;
		}
		if (cu == null || ((Data) cu).isDefined()) {
			Msg.warn(this, "Unexpected code unit or bad test-group function pointer: " +
				functionName + " at " + functionAddr);
		}

		String processor = program.getLanguage().getProcessor().toString();

		if ("ARM".equals(processor)) {
			Register tReg = program.getRegister("T");
			long offset = functionAddr.getOffset();
			if (tReg != null && (offset & 1) == 1) {
				RegisterValue thumbMode = new RegisterValue(tReg, BigInteger.ONE);
				try {
					program.getProgramContext()
							.setRegisterValue(functionAddr, functionAddr, thumbMode);
				}
				catch (ContextChangeException e) {
					throw new AssertException(e);
				}
			}
		}
		else if ("MIPS".equals(processor)) {
			Register isaModeReg = program.getRegister("ISA_MODE");
			long offset = functionAddr.getOffset();
			if (isaModeReg != null && (offset & 1) == 1) {
				RegisterValue thumbMode = new RegisterValue(isaModeReg, BigInteger.ONE);
				try {
					program.getProgramContext()
							.setRegisterValue(functionAddr, functionAddr, thumbMode);
				}
				catch (ContextChangeException e) {
					throw new AssertException(e);
				}
			}
		}

		functionAddr = alignAddress(functionAddr, program.getLanguage().getInstructionAlignment());

		disassembleStarts.add(functionAddr);
	}

	/**
	 * Create symbol at known function location if missing
	 */
	private void createSymbol(Address functionAddr, String functionName, Program program) {
		SymbolTable symbolTable = program.getSymbolTable();
		try {
			symbolTable.createLabel(functionAddr, functionName, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			// ignore
		}
	}

	/**
	 * Get the loader class which should be used.  A null value should be
	 * return to use the preferred loader.
	 * @return loader class or null
	 */
	protected Class<? extends Loader> getLoaderClass() {
		return null;
	}

	//
	// Private helper methods
	//

	private List<PCodeTestFile> findBinaryTestFiles(File testResourceDir) {

		ArrayList<PCodeTestFile> testFiles = new ArrayList<>();
		ArrayList<String> list = new ArrayList<>();

		String escapedProcessorDesignator = processorDesignator.replace("+", "\\+");
		Pattern pattern = Pattern.compile(escapedProcessorDesignator + PCODE_TEST_FILE_BASE_REGEX,
			Pattern.CASE_INSENSITIVE);

		File[] listFiles = testResourceDir.listFiles();
		if (listFiles == null) {
			return testFiles;
		}

		for (File f : testResourceDir.listFiles()) {
			String name = f.getName();
			Matcher matcher = pattern.matcher(name);
			if (!matcher.matches()) {
				continue;
			}
			if (f.isDirectory()) {
				getFiles(f, list, name + "/");
			}
			else {
				list.add(name);
			}
		}
		Collections.sort(list);
		for (int i = 0; i < list.size(); i++) {
			String relativePath = list.get(i);
			testFiles.add(new PCodeTestFile(new File(testResourceDir, relativePath), relativePath));
		}
		return testFiles;
	}

	private void getFiles(File dir, List<String> list, String pathPrefix) {
		// do not recurse down
		for (File f : dir.listFiles()) {
			if (f.isFile() && !f.getName().startsWith(".")) {
				list.add(pathPrefix + f.getName());
			}
		}
	}

	private Program getGzfProgram(String gzfProgName) throws IOException {
		// It is assumed that program has been added to TestEnv short-term cache before this method
		// is invoked, if not resourcesTestDataDir will be checked for gzfProgName
		return getGzfProgram(resourcesTestDataDir, gzfProgName);
	}

	private Program getGzfProgram(File dir, String gzfProgName) throws IOException {
		if (!gzfProgName.endsWith(GZF_FILE_EXT)) {
			throw new IllegalArgumentException();
		}
		String progName = gzfProgName.substring(0, gzfProgName.length() - GZF_FILE_EXT.length());
		try {
			ProgramDB program = env.getProgram(progName); // ignores .gzf extension
			if (program != null) {
				Msg.info(ProcessorEmulatorTestAdapter.class,
					"Loaded program from TestEnv cache: " + progName);
				program.addConsumer(this);
				env.release(program);
				return program;
			}
			if (dir != null) {
				Msg.info(ProcessorEmulatorTestAdapter.class, "Import program: " + gzfProgName);
				program =
					(ProgramDB) env.getGhidraProject().importProgram(new File(dir, gzfProgName));
				program.addConsumer(this);
				env.getGhidraProject().close(program);
				env.saveToCache(progName, program, true, TaskMonitor.DUMMY); // ignores .gzf extension
				return program;
			}
		}
		catch (Exception e) {
			throw new IOException(e);
		}
		throw new FileNotFoundException("Program file not found: " + gzfProgName);
	}

	/**
	 * @return true if test run should fail up-front if binary contains disassembly errors
	 */
	public boolean failOnDisassemblyErrors() {
		return true;
	}

	/**
	 * @return true if test run should fail up-front if binary contains relocation errors
	 */
	public boolean failOnRelocationErrors() {
		return false;
	}

	private void checkForProgramIssues(Program program, String resourceFilePath,
			PCodeTestControlBlock testControlBlock, PCodeTestResults testResults) {

		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Iterator<Bookmark> iter = bookmarkManager.getBookmarksIterator(BookmarkType.ERROR);

		boolean hasDisassemblyErrors = false;
		boolean hasRelocationErrors = false;
		while (iter.hasNext()) {
			Bookmark bookmark = iter.next();
			if ("Bad Instruction".equals(bookmark.getCategory())) {
				hasDisassemblyErrors = true;
			}
			if ("Relocation".equals(bookmark.getCategory())) {
				hasRelocationErrors = true;
			}
		}
		if (hasDisassemblyErrors) {
			boolean fail = failOnDisassemblyErrors();
			log(null,
				(fail ? "ERROR" : "WARNING") +
					": Program contains one or more Bad Instruction Error bookmarks - " +
					resourceFilePath);
			if (fail) {
				testResults.summaryHasDisassemblyErrors = true;
			}

		}
		if (hasRelocationErrors) {
			boolean fail = failOnRelocationErrors();
			log(null, (fail ? "ERROR" : "WARNING") +
				": Program contains one or more Relocation Error bookmarks - " + resourceFilePath);
			if (fail) {
				testResults.summaryHasRelocationErrors = true;
			}
		}
	}

	private void ingestTestBinaries() throws Exception {

		if (!resourcesCacheDir.exists() && !FileUtilities.mkdirs(resourcesCacheDir)) {
			throw new IOException("Failed to create GZF cache: " + resourcesCacheDir);
		}

		//
		// Use of TestEnv and GhidraProject
		//	 - Since we are not based upon GenericTestCase due to the manner in which test
		//     resources/programs are managed we only rely on it for its program cache
		//     which we must populate directly
		//   - GhidraProject is used for its ability to import programs, unfortunately it
		//     is a little forceful with imposing a open transaction on all programs so we
		//     take control by becoming a consumer and forcing GhidraProject to release it.
		//

		testControlBlocks = new ArrayList<>();

		List<PCodeTestFile> testFiles = null;

		Msg.info(this, "Locating " + processorDesignator + " P-Code test binaries in: " +
			resourcesTestDataDir);
		testFiles = findBinaryTestFiles(resourcesTestDataDir);

		if (testFiles.size() == 0) {
			throw new AssertException("No test binaries found");
		}

		Msg.info(this, "Processing " + testFiles.size() + " P-Code test binaries");

		int txId = -1;
		HashSet<String> duplicateTests = new HashSet<>();
		HashMap<String, PCodeTestGroup> map = new HashMap<>();
		for (PCodeTestFile testFile : testFiles) {
			String fileReferencePath = testFile.fileReferencePath; // relative resource filepath
			Program program = null;
			boolean usingCachedGZF = false;
			try {
				File absoluteGzfFilePath = null;
				boolean analyze = false; // if true program will be analyzed and cached
				if (fileReferencePath.endsWith(GZF_FILE_EXT)) {
					// TODO: this does not benefit from TestEnv DB cache
					absoluteGzfFilePath = new File(outputDir, fileReferencePath);
					program = getGzfProgram(resourcesTestDataDir, fileReferencePath); // gzf assumed to be pre-analyzed
				}
				else if (testFile.fileReferencePath.endsWith(BINARY_FILE_EXT)) {
					// check for gzf in persistent cache
					absoluteGzfFilePath =
						new File(resourcesCacheDir, fileReferencePath + GZF_FILE_EXT); // persistent cache gzf
					String gzfCachePath =
						GZF_CACHEDIR_NAME + "/" + fileReferencePath + GZF_FILE_EXT; //
					if (absoluteGzfFilePath.exists()) {
						program = getGzfProgram(outputDir, gzfCachePath);
						if (program != null && !MD5Utilities.getMD5Hash(testFile.file)
								.equals(program.getExecutableMD5())) {
							// remove obsolete GZF cache file
							env.release(program);
							program = null;
						}
						if (program == null) {
							absoluteGzfFilePath.delete();
							env.removeFromProgramCache(gzfCachePath);
						}
						else {
							usingCachedGZF = true;
						}
					}
					if (program == null) {
						// import binary from scratch - will be stored in persistent cache as gzf when done
						log(null, "Importing and Analyzing " + testFile.file);
						log(null, "Using language/compiler spec: " + language.getLanguageID() +
							" / " + compilerSpec.getCompilerSpecID());
						Class<? extends Loader> loaderClass = getLoaderClass();
						if (loaderClass != null) {
							program =
								env.getGhidraProject().importProgram(testFile.file, loaderClass);
						}
						else {
							program = env.getGhidraProject()
									.importProgram(testFile.file, language, compilerSpec);
						}
						program.addConsumer(this);
						env.getGhidraProject().close(program);
						analyze = true; // must analyze if not a gzf import
					}
					fileReferencePath = gzfCachePath; // use gzf cache when re-opening
				}
				else {
					Msg.warn(this, "Ignoring P-Code test file - unsupported file extension: " +
						fileReferencePath);
					continue;
				}
				if (program == null) {
					throw new IOException("Failed to open program: " + fileReferencePath);
				}

				txId = program.startTransaction("Analyze");

				if (!program.getLanguageID().equals(language.getLanguageID()) ||
					!program.getCompilerSpec()
							.getCompilerSpecID()
							.equals(compilerSpec.getCompilerSpecID())) {
					throw new IOException((usingCachedGZF ? "Cached " : "") +
						"Program has incorrect language/compiler spec (" + program.getLanguageID() +
						"/" + program.getCompilerSpec().getCompilerSpecID() + "): " +
						absoluteGzfFilePath);
				}

				if (analyze) {

					// discard residual ElfLoader segment data which can result in
					// duplication of data
					cleanupResidualSegmentData(program);

					log(null, "Post-Import processing of " + fileReferencePath);
					postImport(program);
				}

				PCodeTestControlBlock testControlBlock = PCodeTestControlBlock.getMainControlBlock(
					program, testFile, getRestrictedSearchSet(program), fileReferencePath,
					testInfoStruct, groupInfoStruct, analyze, logData.testResults);

				for (PCodeTestGroup testGroup : testControlBlock.getTestGroups()) {
					if (map.containsKey(testGroup.testGroupName)) {
						duplicateTests.add(testGroup.testGroupName);
					}
					else {
						map.put(testGroup.testGroupName, testGroup);
					}
				}

				testControlBlocks.add(testControlBlock);

				if (analyze) {
					log(null, "Analyzing " + fileReferencePath);
					preAnalyze(program);
					analyze(program, testControlBlock);
					postAnalyze(program);

					program.endTransaction(txId, true);
					txId = -1;

					// store to persistent cache as gzf
					Msg.info(ProcessorEmulatorTestAdapter.class,
						"Storing analyzed program in persistent cache: " + absoluteGzfFilePath);
					FileUtilities.mkdirs(absoluteGzfFilePath.getParentFile());
					env.getGhidraProject().saveAsPackedFile(program, absoluteGzfFilePath, true);
					if (!absoluteGzfFilePath.exists()) {
						throw new IOException("Failed to cache gzf file: " + absoluteGzfFilePath);
					}

					// store to short-term TestEnv cache
					env.saveToCache(fileReferencePath, (ProgramDB) program, true,
						TaskMonitor.DUMMY); // ignores .gzf extension on file name/path
				}

				// Check for program errors
				checkForProgramIssues(program, fileReferencePath, testControlBlock,
					logData.testResults);

			}
			catch (InvalidControlBlockException e) {
				throw new RuntimeException(
					"Test control block error (TestInfo structure): " + fileReferencePath, e);
			}
			catch (LanguageNotFoundException e) {
				throw new RuntimeException("Unexpected Error", e); // we already found language
			}
			catch (CancelledException e) {
				throw new RuntimeException("Unexpected Error", e); // Cancel not used
			}
			catch (DuplicateNameException e) {
				throw new RuntimeException("Test file naming conflict: " + fileReferencePath, e); // Must be avoided with naming of binary files
			}
			catch (InvalidNameException e) {
				throw new RuntimeException("Unsupported test filename: " + fileReferencePath, e); // Must be avoided with naming of binary files
			}
			catch (VersionException e) {
				throw new RuntimeException(
					"Unsupported Ghidra database version: " + fileReferencePath, e); // Must be avoided with *.gzf compatibility
			}
			catch (IOException e) {
				throw new RuntimeException(
					"IO Error during P-Code test processing: " + fileReferencePath, e);
			}
			finally {
				if (program != null) {
					if (txId != -1) {
						program.endTransaction(txId, false);
					}
					env.release(program);
				}
			}
		}

		// Sort testControlBlocks
		sortTestControlBlocks();

		// Log file digest details
		log(null, buildTestFileDigest(duplicateTests));

		if (!duplicateTests.isEmpty()) {
			log(null, "ERROR! One or more test groups have been duplicated");
			throw new RuntimeException(
				processorDesignator + " Test files contain duplicate test groups");
		}
	}

	private void cleanupResidualSegmentData(Program program) throws LockException {
		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.getName().startsWith("segment_")) {
				log(null,
					"WARNING! Removing residual segment block to avoid possible duplication: " +
						block);
				memory.removeBlock(block, TaskMonitor.DUMMY);
			}
		}
	}

	private void sortTestControlBlocks() {
		Collections.sort(testControlBlocks, (o1, o2) -> {
			String cf1 = o1.testFile.fileReferencePath;
			String cf2 = o2.testFile.fileReferencePath;
			return cf1.compareTo(cf2);
		});
	}

	public Symbol getUniqueGlobalSymbol(Program program, String name) {
		return SymbolUtilities.getLabelOrFunctionSymbol(program, name, err -> Msg.error(this, err));
	}

	private String buildTestFileDigest(HashSet<String> duplicateTests) {

		StringBuilder testFileDigest = new StringBuilder();
		String title = "*** " + getClass().getSimpleName() + " P-Code Test Suite (" +
			processorDesignator + ") ";
		title = StringUtilities.pad(title, '*', -80);
		testFileDigest.append(title);
		testFileDigest.append("\n");
		for (PCodeTestControlBlock controlBlock : testControlBlocks) {
			testFileDigest.append("* ");
			testFileDigest.append(controlBlock.testFile.fileReferencePath);
			testFileDigest.append(" (TestInfo @ ");
			testFileDigest.append(controlBlock.getInfoStructureAddress().toString(true));
			testFileDigest.append(")\n");

			// compute column width for group function name and address
			int paddedLen = 0;
			for (PCodeTestGroup testGroup : controlBlock.getTestGroups()) {
				int len = testGroup.testGroupName.length() +
					testGroup.functionEntryPtr.toString(true).length() + 3;
				if (len > paddedLen) {
					paddedLen = len;
				}
			}

			for (PCodeTestGroup testGroup : controlBlock.getTestGroups()) {
				testFileDigest.append("*   - ");
				String nameAndAddr =
					testGroup.testGroupName + " @ " + testGroup.functionEntryPtr.toString(true);
				nameAndAddr = StringUtilities.pad(nameAndAddr, ' ', -paddedLen);
				testFileDigest.append(nameAndAddr);
				testFileDigest.append(" (GroupInfo @ ");
				testFileDigest
						.append(testGroup.controlBlock.getInfoStructureAddress().toString(true));
				testFileDigest.append(")");
				if (duplicateTests.contains(testGroup.testGroupName)) {
					testFileDigest.append(" *DUPLICATE*");
				}
				testFileDigest.append("\n");
			}
		}
		testFileDigest.append(StringUtilities.pad("", '*', 80));

		return testFileDigest.toString();
	}

	/**
	 * Force proper code address alignment to compensate for address encoding schemes (e.g., Thumb mode)
	 * @param offset
	 * @param alignment
	 * @return
	 */
	static long alignAddressOffset(long offset, int alignment) {
		return (offset / alignment) * alignment;
	}

	/**
	 * Force proper code address alignment to compensate for address encoding schemes (e.g., Thumb mode)
	 * @param addr
	 * @param alignment
	 * @return
	 */
	static Address alignAddress(Address addr, int alignment) {
		Address alignedAddr = addr;
		long offset = addr.getOffset();
		long alignedOffset = alignAddressOffset(offset, alignment);
		if (offset != alignedOffset) {
			alignedAddr = addr.getNewAddress(alignedOffset);
		}
		return alignedAddr;
	}

	//
	// TODO: Eclipse HACK!
	//
	// Dummy Test Methods - these methods are needed to fake-out Eclipse and allow
	// individual tests to be run.  These methods are not needed if running all
	// test groups.
	//
	// All known test group names must be included here and preceded by "test_".
	// For a test group named 'IterativeProcessingDoWhile' (as it appears in
	// the binary test file), an empty test method named 'test_IterativeProcessingDoWhile'
	// must be specified below.
	//
	// All tests are actually performed by the runTest method.
	//
	// The test_asm group is added for experimental assembly-level testing and
	// is not part of normal C source-based p-code testing.
	public final void test_asm() {
		// stub
	}

	public final void test_BIOPS_DOUBLE() {
		// stub
	}

	public final void test_BIOPS_FLOAT() {
		// stub
	}

	public final void test_BIOPS_LONGLONG() {
		// stub
	}

	public final void test_BIOPS() {
		// stub
	}

	public final void test_BIOPS2() {
		// stub
	}

	public final void test_BIOPS4() {
		// stub
	}

	public final void test_BitManipulation() {
		// stub
	}

	public final void test_DecisionMaking() {
		// stub
	}

	public final void test_GlobalVariables() {
		// stub
	}

	public final void test_IterativeProcessingDoWhile() {
		// stub
	}

	public final void test_IterativeProcessingFor() {
		// stub
	}

	public final void test_IterativeProcessingWhile() {
		// stub
	}

	public final void test_misc() {
		// stub
	}

	public final void test_ParameterPassing1() {
		// stub
	}

	public final void test_ParameterPassing2() {
		// stub
	}

	public final void test_ParameterPassing3() {
		// stub
	}

	public final void test_PointerManipulation() {
		// stub
	}

	public final void test_StructUnionManipulation() {
		// stub
	}

}
