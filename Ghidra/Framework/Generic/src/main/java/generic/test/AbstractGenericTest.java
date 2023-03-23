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
package generic.test;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import org.junit.Rule;
import org.junit.rules.*;
import org.junit.runner.Description;

import generic.jar.ResourceFile;
import generic.test.rule.Repeated;
import generic.test.rule.RepeatedTestRule;
import generic.util.WindowUtilities;
import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import utilities.util.FileUtilities;
import utilities.util.reflection.ReflectionUtilities;
import utility.application.ApplicationLayout;

/**
 * Base class for tests that provide some helper methods that are useful for tests that don't
 * require swing/gui support.
 */
public abstract class AbstractGenericTest extends AbstractGTest {

	/** Property that defines the test report output directory */
	private static final String GHIDRA_TEST_PROPERTY_REPORT_DIR = "ghidra.test.property.report.dir";
	private static File debugDirectory;

	public static final String TESTDATA_DIRECTORY_NAME = "testdata";
	public static final String DEFAULT_TOOL_NAME = "CodeBrowser";
	public static final String DEFAULT_TEST_TOOL_NAME = "TestCodeBrowser";

	private static boolean initialized = false;
	private static boolean printedApplicationConflictWaring = false;

	private static ApplicationLayout loadedApplicationLayout;
	private static ApplicationConfiguration loadedApplicationConfiguration;

	private volatile boolean hasFailed;

	public TestWatcher watchman = new TestWatcher() {

		@Override
		protected void starting(Description description) {
			hasFailed = false;
			debugBatch((new Date()) + "\n***** STARTING Test: " +
				AbstractGenericTest.this.getClass().getSimpleName() + " - " +
				testName.getMethodName() + " *****");
		}

		@Override
		protected void failed(Throwable e, Description description) {
			hasFailed = true;
			testFailed(e);
			// \u2716 is an X
			debugBatch(
				"\t\u2716 FAILED Test: " + AbstractGenericTest.this.getClass().getSimpleName() +
					" - " + testName.getMethodName() + " \u2716\t");
		}

		@Override
		protected void succeeded(Description description) {
			// \u2716 is a check mark
			debugBatch(
				"\t\u2713 PASSED Test: " + AbstractGenericTest.this.getClass().getSimpleName() +
					" - " + testName.getMethodName() + " \u2713\t");
		}
	};

	@Rule
	public TestRule concurrentTestExceptionRule =
		(base, description) -> new ConcurrentTestExceptionStatement(base);

	@Rule
	public RuleChain ruleChain = RuleChain.outerRule(testName).around(watchman);// control rule ordering

	/**
	 * This rule handles the {@link Repeated} annotation
	 *
	 * <p>
	 * During batch mode, this rule should never be needed. This rule is included here as a
	 * convenience, in case a developer wants to use the {@link Repeated} annotation to diagnose a
	 * non-deterministic test failure. Without this rule, the annotation would be silently ignored.
	 */
	@Rule
	public TestRule repeatedRule = new RepeatedTestRule();

	private void debugBatch(String message) {
		if (BATCH_MODE) {
			Msg.debug(AbstractGenericTest.class, message);
		}
	}

	private synchronized void initialize(AbstractGenericTest test) {

		initializeSystemProperties();

		ApplicationLayout layout;
		try {
			layout = test.createApplicationLayout();
		}
		catch (Exception e) {
			throw new AssertException(e);
		}

		initializeLayout(layout);
		ApplicationConfiguration configuration = test.createApplicationConfiguration();
		if (initialized) {
			printWarningIfConflictingInitializationConfigs(layout, configuration);
			return;
		}

		if (configuration == null) {
			// null indicates that the test will initialize the application
			return;
		}

		initialized = true;
		loadedApplicationLayout = layout;
		loadedApplicationConfiguration = configuration;

		try {
			Application.initializeApplication(layout, configuration);
		}
		catch (Exception e) {
			throw new AssertException(e);
		}
	}

	/**
	 * A place to initialize and needed static properties
	 */
	protected void initializeSystemProperties() {
		System.setProperty(SystemUtilities.TESTING_PROPERTY, "true");
	}

	/**
	 * A method to update any {@link ApplicationLayout} values
	 *
	 * @param layout the layout to initialize
	 */
	protected void initializeLayout(ApplicationLayout layout) {
		File testDir = new File(getTestDirectoryPath());
		setInstanceField("userCacheDir", layout, testDir);
	}

	private void printWarningIfConflictingInitializationConfigs(ApplicationLayout layout,
			ApplicationConfiguration configuration) {

		if (loadedApplicationLayout.getClass().equals(layout.getClass()) &&
			loadedApplicationConfiguration.getClass().equals(configuration.getClass())) {
			return;
		}

		if (printedApplicationConflictWaring) {
			return; // don't print repeatedly
		}

		//
		// This condition likely happens if we share VMs for tests and they are different test
		// types (like Headless vs Headed).
		//
		printedApplicationConflictWaring = true;
		Msg.error(this,
			"\n\n\n\n\t\t\tWARNING!!\n\nAttempted to run multiple tests with " +
				"different configurations.\nThis prevents the proper initialization of tests\n" +
				"Loaded configurations, in order: " +
				loadedApplicationConfiguration.getClass().getSimpleName() + " and " +
				configuration.getClass().getSimpleName() + "\n",
			ReflectionUtilities.createJavaFilteredThrowable());
	}

	public AbstractGenericTest() {
		initialize(this);
	}

	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new GhidraTestApplicationLayout(new File(getTestDirectoryPath()));
	}

	protected ApplicationConfiguration createApplicationConfiguration() {
		ApplicationConfiguration configuration = new ApplicationConfiguration();
		return configuration;
	}

	/**
	 * Determine if test failure occur (for use within tear down methods)
	 *
	 * @return true if test failure detected
	 */
	protected boolean hasTestFailed() {
		return hasFailed;
	}

	/**
	 * A callback for subclasses when a test has failed. This will be called
	 * <b>after</b> <code>tearDown()</code>.  This means that any diagnostics will have to
	 * take into account items that have already been disposed.
	 *
	 * @param e the exception that happened when the test failed
	 */
	protected void testFailed(Throwable e) {
		// perform diagnostic stuff here when a test has failed
	}

	/**
	 * Returns the window parent of c. If c is a window, then c is returned.
	 *
	 * <P>
	 * Warning: this differs from
	 * {@link SwingUtilities#windowForComponent(Component)} in that the latter
	 * method will not return the given component if it is a window.
	 *
	 * @param c the component
	 * @return the window
	 */
	public static Window windowForComponent(Component c) {
		return WindowUtilities.windowForComponent(c);
	}

	public File getLocalResourceFile(String relativePath) {
		URL resource = getClass().getResource(relativePath);
		try {
			URI uri = resource.toURI();
			return new File(uri);
		}
		catch (URISyntaxException e) {
			Msg.error(this, "Unable to convert URL to URI", e);
		}
		return null;
	}

	/**
	 * Load a text resource file into an ArrayList. Each line of the file is
	 * stored as an item in the list.
	 *
	 * @param cls class where resource exists
	 * @param name resource filename
	 * @return list of lines contained in file
	 * @throws IOException if an exception occurs reading the given resource
	 */
	public static List<String> loadTextResource(Class<?> cls, String name) throws IOException {

		InputStream is = cls.getResourceAsStream(name);
		if (is == null) {
			throw new IOException("Could not find resource: " + name);
		}
		BufferedReader br = new BufferedReader(new InputStreamReader(is));
		ArrayList<String> text = readText(br);
		br.close();
		return text;
	}

	private static ArrayList<String> readText(BufferedReader br) throws IOException {
		ArrayList<String> list = new ArrayList<>();
		String line = "";
		while (line != null) {
			line = br.readLine();
			if (line != null) {
				list.add(line);
			}
		}
		return list;

	}

	public static ArrayList<String> loadTextResource(String name) throws IOException {
		File file = getTestDataFile(name);
		BufferedReader reader = new BufferedReader(new FileReader(file));
		ArrayList<String> text = readText(reader);
		reader.close();
		return text;
	}

	/**
	 * Returns the file within the data directory of the TestResources module
	 * that matches the given relative path
	 * <p>
	 * A {@link FileNotFoundException} is throw if the file does not exist.
	 *
	 * @param path path relative to the data directory of the TestResources
	 *            module.
	 * @return the file within the data directory of the TestResources module
	 *         that matches the given relative path
	 * @throws FileNotFoundException if the given file does not exist
	 */
	public static File getTestDataFile(String path) throws FileNotFoundException {
		ResourceFile resourceFile = Application.getModuleDataFile("TestResources", path);
		return resourceFile.getFile(false);
	}

	/**
	 * Returns a file that points to the location on disk of the given relative
	 * path name. The path is relative to the test resources directory.
	 *
	 * @param relativePath the path of the file
	 * @return a file that points to the location on disk of the relative path.
	 * @throws FileNotFoundException If the directory does not exist
	 * @throws IOException if the given path does not represent a directory
	 */
	public static File getTestDataDir(String relativePath)
			throws FileNotFoundException, IOException {
		ResourceFile resourceFile =
			Application.getModuleDataSubDirectory("TestResources", relativePath);
		return resourceFile.getFile(false);
	}

	/**
	 * Returns the file within the data directory of the TestResources module
	 * that matches the given relative path.
	 * <p>
	 * Null is returned if the file could not be found.
	 *
	 * @param path path relative to the data directory of the TestResources
	 *            module.
	 * @return the file within the data directory of the TestResources module
	 *         that matches the given relative path
	 */
	public static File findTestDataFile(String path) {
		try {
			ResourceFile resourceFile = Application.getModuleDataFile("TestResources", path);
			return resourceFile.getFile(false);
		}
		catch (FileNotFoundException e) {
			// NOTE: TestEnv.getProgram relies on this method to return null if file not found
			Msg.warn(AbstractGenericTest.class, "Test data file not found: " + path);
			return null;
		}
	}

	/**
	 * Returns the data directory containing test programs and data
	 *
	 * @return the data directory containing test programs and data
	 */
	public static File getTestDataDirectory() {
		try {
			return Application.getModuleSubDirectory("TestResources", "data").getFile(false);
		}
		catch (IOException e) {
			// shouldn't happen--this directory should always be there
			throw new AssertException("Unable to find test resources directory 'data' directory");
		}
	}

	/**
	 * Get the first field object contained within object ownerInstance which
	 * has the type classType. This method is only really useful if it is known
	 * that only a single field of classType exists within the ownerInstance.
	 *
	 * @param <T> the type
	 * @param classType the class type of the desired field
	 * @param ownerInstance the object instance that owns the field
	 * @return field object of type classType or null
	 */
	public static <T> T getInstanceFieldByClassType(Class<T> classType, Object ownerInstance) {
		return TestUtils.getInstanceFieldByClassType(classType, ownerInstance);
	}

	/**
	 * Sets the instance field by the given name on the given object instance.
	 * <p>
	 * Note: if the field is static, then the <code>ownerInstance</code> field can
	 * be the class of the object that contains the variable.
	 *
	 * @param fieldName The name of the field to retrieve.
	 * @param ownerInstance The object instance from which to get the variable
	 *            instance.
	 * @param value The value to use when setting the given field
	 * @throws RuntimeException if there is a problem accessing the field using
	 *             reflection. A RuntimeException is used so that calling tests
	 *             can avoid using a try/catch block, but will still fail when
	 *             an error is encountered.
	 * @see Field#set(Object, Object)
	 */
	public static void setInstanceField(String fieldName, Object ownerInstance, Object value)
			throws RuntimeException {
		TestUtils.setInstanceField(fieldName, ownerInstance, value);
	}

	/**
	 * Gets the instance field by the given name on the given object instance.
	 * The value is a primitive wrapper if it is a primitive type.
	 * <p>
	 * Note: if the field is static, then the <code>ownerInstance</code> field can
	 * be the class of the object that contains the variable.
	 *
	 * @param fieldName The name of the field to retrieve.
	 * @param ownerInstance The object instance from which to get the variable
	 *            instance.
	 * @return The field instance.
	 * @throws RuntimeException if there is a problem accessing the field using
	 *             reflection. A RuntimeException is used so that calling tests
	 *             can avoid using a try/catch block, but will still fail when
	 *             an error is encountered.
	 * @see Field#get(java.lang.Object)
	 * @since Tracker Id 267
	 */
	public static Object getInstanceField(String fieldName, Object ownerInstance)
			throws RuntimeException {
		return TestUtils.getInstanceField(fieldName, ownerInstance);
	}

	/**
	 * Uses reflection to execute the constructor for the given class with the
	 * given parameters. The new instance of the given class will be returned.
	 * <p>
	 *
	 * @param containingClass The class that contains the desired constructor.
	 * @param parameterTypes The parameter <b>types</b> that the constructor
	 *            takes. This value can be null or zero length if there are no
	 *            parameters to pass
	 * @param args The parameter values that should be passed to the
	 *            constructor. This value can be null or zero length if there
	 *            are no parameters to pass
	 * @return The new class instance
	 * @throws RuntimeException if there is a problem accessing the constructor
	 *             using reflection. A RuntimeException is used so that calling
	 *             tests can avoid using a try/catch block, but will still fail
	 *             when an error is encountered.
	 */
	public static Object invokeConstructor(Class<?> containingClass, Class<?>[] parameterTypes,
			Object[] args) throws RuntimeException {

		return TestUtils.invokeConstructor(containingClass, parameterTypes, args);
	}

	/**
	 * Uses reflection to execute the method denoted by the given method name.
	 * If any value is returned from the method execution, then it will be
	 * returned from this method. Otherwise, <code>null</code> is returned.
	 * <p>
	 * Note: if the method is static, then the <code>ownerInstance</code> field can
	 * be the class of the object that contains the method.
	 *
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *            executed.
	 * @param parameterTypes The parameter <b>types</b> that the method takes.
	 * @param args The parameter values that should be passed to the method.
	 *            This value can be null or zero length if there are no
	 *            parameters to pass
	 * @return The return value as returned from executing the method.
	 * @see Method#invoke(java.lang.Object, java.lang.Object[])
	 * @throws RuntimeException if there is a problem accessing the field using
	 *             reflection. A RuntimeException is used so that calling tests
	 *             can avoid using a try/catch block, but will still fail when
	 *             an error is encountered.
	 * @since Tracker Id 267
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance,
			Class<?>[] parameterTypes, Object[] args) throws RuntimeException {

		return TestUtils.invokeInstanceMethod(methodName, ownerInstance, parameterTypes, args);
	}

	/**
	 * This method is just a "pass through" method for
	 * {@link #invokeInstanceMethod(String, Object, Class[], Object[])} so that
	 * callers do not need to pass null to that method when the underlying
	 * instance method does not have any parameters.
	 *
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *            executed.
	 * @return The return value as returned from executing the method.
	 * @see Method#invoke(java.lang.Object, java.lang.Object[])
	 * @throws RuntimeException if there is a problem accessing the field using
	 *             reflection. A RuntimeException is used so that calling tests
	 *             can avoid using a try/catch block, but will still fail when
	 *             an error is encountered.
	 * @see #invokeInstanceMethod(String, Object, Class[], Object[])
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance)
			throws RuntimeException {
		return invokeInstanceMethod(methodName, ownerInstance, null, null);
	}

	/**
	 * Returns a string which is a printout of a stack trace for each thread
	 * running in the current JVM
	 *
	 * @return the stack trace string
	 */
	public static String createStackTraceForAllThreads() {
		return TestUtils.createStackTraceForAllThreads();
	}

	/**
	 * Prints the contents of the given collection by way of the
	 * {@link Object#toString()} method.
	 *
	 * @param collection The contents of which to print
	 * @return A string representation of the given collection
	 */
	public static String toString(Collection<?> collection) {
		StringBuffer buffer = new StringBuffer();
		TypeVariable<?>[] typeParameters = collection.getClass().getTypeParameters();
		buffer.append("Collection<");
		for (TypeVariable<?> typeVariable : typeParameters) {
			buffer.append(typeVariable.getName()).append(", ");
		}
		if (typeParameters.length > 0) {// strip off the last comma and space
			int length = buffer.length();
			buffer.delete(length - 2, length);
		}

		buffer.append(">: ");
		for (Object object : collection) {

			buffer.append(object).append(", ");
		}
		return buffer.toString();
	}

	/**
	 * Returns a font metrics for the given font using a generic buffered image graphics context.
	 * @param font the font
	 * @return the font metrics
	 */
	public static FontMetrics getFontMetrics(Font font) {
		BufferedImage image = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB_PRE);
		Graphics g = image.getGraphics();
		FontMetrics fm = g.getFontMetrics(font);
		g.dispose();
		return fm;
	}

	/**
	 * Signals that the client expected the System Under Test (SUT) to report errors.  Use this
	 * when you wish to verify that errors are reported and you do not want those errors to
	 * fail the test.  The default value for this setting is false, which means that any
	 * errors reported will fail the running test.
	 *
	 * @param expected true if errors are expected.
	 */
	public static void setErrorsExpected(boolean expected) {
		if (expected) {
			Msg.error(AbstractGenericTest.class, ">>>>>>>>>>>>>>>> Expected Exception");
			ConcurrentTestExceptionHandler.disable();
		}
		else {
			Msg.error(AbstractGenericTest.class, "<<<<<<<<<<<<<<<< End Expected Exception");
			ConcurrentTestExceptionHandler.enable();
		}
	}

//==================================================================================================
// Temp File Management
//==================================================================================================

	/**
	 * Returns the directory into which tests can write debug files, such as
	 * files containing print statements or image files.
	 *
	 * <P>
	 * This is not a temporary directory that will be deleted between tests,
	 * which is useful in that the debug files will persist after a test run.
	 *
	 * <P>
	 * Examples of this directory:
	 * <UL>
	 * <LI>server: {share dir}/junits.new/JunitTest_version/reports</LI>
	 * <LI>local gradle: {user home}/git/{repo}/ghidra/build/JUnit/reports</LI>
	 * <LI>eclipse: {module}/bin/</LI>
	 * </UL>
	 *
	 * @return the directory
	 */
	public static File getDebugFileDirectory() {

		if (debugDirectory != null) {
			return debugDirectory;
		}

		// ghidra.test.property.report.dir
		// Possible Values:
		// server        {share dir}/reports/{type}/{branch}/{date}/
		// local gradle: {repo}/Ghidra/{module}/build/JUnit/reports
		// eclipse:      {repo}/Ghidra/{module}/bin/
		// build:        unsupported

		// we add to the above directory a single dir value of 'debug'

		String debugDirName = "debug";
		String dirPath = System.getProperty(GHIDRA_TEST_PROPERTY_REPORT_DIR);
		if (dirPath != null) { // running from gradle
			debugDirectory = new File(dirPath, debugDirName);
		}
		else { // running from Eclipse

			// Setup the dir to be something reasonable.  In Eclipse, we do not generate
			// reports, nor do we have a build directory.  'bin' is the closest thing to that.
			ResourceFile moduleDir = Application.getMyModuleRootDirectory();
			ResourceFile binDir = new ResourceFile(moduleDir, "bin");
			debugDirectory = new File(binDir.getFile(false), debugDirName);
		}

		return debugDirectory;
	}

	/**
	 * Creates a <b>sub-directory</b> with the given name as a child of the Java
	 * temp directory. The given name will be the prefix of the new directory
	 * name, with any additional text as created by
	 * {@link Files#createTempDirectory(Path, String, java.nio.file.attribute.FileAttribute...)}.
	 * Any left-over test directories will be cleaned-up before creating the new
	 * directory.
	 *
	 * <p>
	 * Note: you should not call this method multiple times, as each call will
	 * cleanup the previously created directories.
	 *
	 * @param name the name of the directory to create
	 * @return the newly created directory
	 * @throws IOException of there is a problem creating the new directory
	 */
	public static File createTempDirectory(String name) throws IOException {
		String tempTestRootDirname = "generic.test.temp.dir";

		// NOTE: this call is predicated on the fact that each test file that is run will get
		//       a unique test directory when running in parallel mode
		deleteSimilarTempFiles(tempTestRootDirname);

		String testTempDir = getTestDirectoryPath();
		Path tempDirPath = Paths.get(testTempDir);
		Path tempRootDirPath = Files.createTempDirectory(tempDirPath, tempTestRootDirname);
		File tempRootDir = tempRootDirPath.toFile();
		tempRootDir.deleteOnExit();

		FileUtilities.deleteDir(tempRootDir);// clean out any existing data; this should have no data though
		Path userDir = tempRootDirPath.resolve(name);
		Files.createDirectories(userDir);
		File file = userDir.toFile();
		file.deleteOnExit();
		return file;
	}

	/**
	 * Creates a file path with a filename that is under the system temp
	 * directory. The path returned will not point to an existing file. The
	 * suffix of the file will be <code>.tmp</code>.
	 *
	 * @param name the filename
	 * @return a new file path
	 * @throws IOException if there is any problem ensuring that the created
	 *             path is non-existent
	 * @see #createTempFilePath(String, String)
	 */
	public String createTempFilePath(String name) throws IOException {
		String path = createTempFilePath(name, ".tmp");
		return path;
	}

	/**
	 * Creates a file path with a filename that is under the system temp
	 * directory. The path returned will not point to an existing file. This
	 * method is the same as {@link #createTempFilePath(String)}, except that
	 * you must provide the extension.
	 *
	 * @param name the filename
	 * @param extension the file extension
	 * @return a new file path
	 * @throws IOException if there is any problem ensuring that the created
	 *             path is non-existent
	 * @see #createTempFile(String, String)
	 */
	public String createTempFilePath(String name, String extension) throws IOException {
		File file = createTempFile(name, extension);
		file.delete();
		return file.getAbsolutePath();
	}

	/**
	 * Creates a temp file for the current test, using the test name as a prefix
	 * for the filename. This method calls {@link #createTempFile(String)},
	 * which will cleanup any pre-existing temp files whose name pattern matches
	 * this test name. This helps to avoid old temp files from accumulating.
	 *
	 * @return the new temp file
	 * @throws IOException if there is a problem creating the new file
	 */
	public File createTempFileForTest() throws IOException {
		return createTempFile(getName());
	}

	/**
	 * Creates a temp file for the current test, using the test name as a prefix
	 * for the filename. This method calls {@link #createTempFile(String)},
	 * which will cleanup any pre-existing temp files whose name pattern matches
	 * this test name. This helps to avoid old temp files from accumulating.
	 *
	 * @param suffix the suffix to provide for the temp file
	 * @return the new temp file
	 * @throws IOException if there is a problem creating the new file
	 */
	public File createTempFileForTest(String suffix) throws IOException {
		return createTempFile(getName(), suffix);
	}

	/**
	 * Creates a file in the Java temp directory using the given name as a
	 * prefix and the given suffix. The final filename will also include the
	 * current test name, as well as any data added by
	 * {@link File#createTempFile(String, String)}. The file suffix will be
	 * <code>.tmp</code>
	 * <p>
	 * The file will be marked to delete on JVM exit. This will not work if the
	 * JVM is taken down the hard way, as when pressing the stop button in
	 * Eclipse.
	 *
	 * @param name the prefix to put on the file, before the test name
	 * @return the newly created file
	 * @throws IOException if there is a problem creating the new file
	 * @see #createTempFile(String, String)
	 */
	public File createTempFile(String name) throws IOException {
		File file = createTempFile(name, ".tmp");
		return file;
	}

	/**
	 * Creates a file in the Java temp directory using the given name as a
	 * prefix and the given suffix. The final filename will also include the
	 * current test name, as well as any data added by
	 * {@link File#createTempFile(String, String)}.
	 * <p>
	 * The file will be marked to delete on JVM exit. This will not work if the
	 * JVM is taken down the hard way, as when pressing the stop button in
	 * Eclipse.
	 * <p>
	 * Note: This method <b>will</b> create the file on disk! If you need the
	 * file to not exist, then you must delete the file yourself. Alternatively,
	 * you could instead call {@link #createTempFilePath(String, String)}, which
	 * will ensure that the created temp file is deleted.
	 *
	 * <p>
	 * Finally, this method will delete any files that match the given name and
	 * suffix values before creating the given temp file. <b>This is important,
	 * as it will delete any files already created by the test that match this
	 * info.</b>
	 *
	 * @param name the prefix to put on the file, before the test name
	 * @param suffix the file suffix
	 * @return the newly created file
	 * @throws IOException if there is a problem creating the new file
	 * @see #createTempFile(String)
	 */
	public File createTempFile(String name, String suffix) throws IOException {

		String testMethodName = testName.getMethodName();

		// these are the values used by File.createTempFile()
		String prefixName = name != null ? name : "null";
		String suffixName = suffix != null ? suffix : ".tmp";
		deleteMatchingTempFiles(prefixName + ".*" + suffixName);

		String testTempDir = getTestDirectoryPath();
		File dir = new File(testTempDir);
		String filename = prefixName + '.' + testMethodName + '.';
		File tempFile = File.createTempFile(filename, suffixName, dir);
		tempFile.deleteOnExit();

		return tempFile;
	}

	/**
	 * Delete any files under the Java temp directory that have the given text
	 * in their name.
	 *
	 * @param nameText the partial name text to match against the files
	 * @see #deleteMatchingTempFiles(String)
	 */
	public static void deleteSimilarTempFiles(String nameText) {

		String literalNamePattern = Pattern.quote(nameText);
		String contains = ".*" + literalNamePattern + ".*";
		deleteMatchingTempFiles(contains);
	}

	/**
	 * Delete any files under the this test case's specific temp directory that
	 * match the give regex {@link Pattern}
	 *
	 * @param namePattern the pattern to match against the files
	 * @see #deleteSimilarTempFiles(String)
	 */
	public static void deleteMatchingTempFiles(String namePattern) {

		Pattern pattern = Pattern.compile(namePattern);

		String tempPath = getTestDirectoryPath();
		File testTempDir = new File(tempPath);
		File[] oldFiles = testTempDir.listFiles((dir, filename) -> {
			boolean matches = pattern.matcher(filename).matches();
			return matches;
		});

		for (File file : oldFiles) {
			// deleteDir will also delete files
			FileUtilities.deleteDir(file);
		}
	}

}
