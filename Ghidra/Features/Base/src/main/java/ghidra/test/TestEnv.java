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
package ghidra.test;

import java.awt.Dialog;
import java.awt.Window;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.jdom.Element;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.test.AbstractDockingTest;
import docking.tool.ToolConstants;
import generic.jar.ResourceFile;
import generic.test.*;
import ghidra.app.events.CloseProgramPluginEvent;
import ghidra.app.events.OpenProgramPluginEvent;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.JavaScriptProvider;
import ghidra.app.services.ProgramManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ToolUtils;
import ghidra.framework.main.*;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.*;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.*;
import ghidra.util.task.*;
import utilities.util.FileUtilities;

public class TestEnv {

	private static final int FIVE_MINUTES = 5;

	private static int toolID = 2;

	/**
	 * Used to perform emergency cleanup.  Tests are expected to call {@link #dispose()} in
	 * their <code>tearDown</code> method.  This is here to catch the case where the is some fatal
	 * error that prevents that from taking place.
	 */
	private static Set<TestEnv> instances = new HashSet<>();

	private FrontEndTool frontEndTool;
	private PluginTool tool;

	private static TestProgramManager programManager = new TestProgramManager();

	private GhidraProject gp;

	/**
	* A list of tools that have been created by instances of this class that will be
	* disposed of at cleanup time.
	*/
	private List<PluginTool> extraTools = new ArrayList<>();

	/**
	 * Constructor for Ghidra
	 * A new test project is established.
	 * If it already exists it will first be deleted.
	 *
	 * @throws IOException if there is an issue creating a test project
	 */
	public TestEnv() throws IOException {
		this(FIVE_MINUTES, AbstractGhidraHeadlessIntegrationTest.PROJECT_NAME);
	}

	/**
	 * Constructor for Ghidra
	 * A new test project is established using the specified projectName.
	 * If it already exists it will first be deleted.
	 * If the test environment is not disposed within 1 minute the tests iwll be aborted
	 *
	 * @param projectName the name of the project
	 * @throws IOException if there is an issue creating a test project
	 */
	public TestEnv(String projectName) throws IOException {
		this(FIVE_MINUTES, projectName);
	}

	/**
	 * Constructor for Ghidra
	 * A new test project is established using the specified projectName.
	 * If it already exists it will first be deleted.
	 * @param abortTimeout number of minutes within which this test environment must be
	 * 		  disposed.  If not disposed in a timely manner, System.exit will be invoked.
	 * @param projectName the name of the project
	 * @throws IOException if there is an issue creating a test project
	 */
	public TestEnv(long abortTimeout, String projectName) throws IOException {

		if (!Application.isInitialized()) {
			throw new AssertException("The TestEnv requires the system to be " +
				"initialized before usage.  JUnit test should be an instance of " +
				"GhidraHeadedIntegrationTest or GhidraHeadlessIntegrationTest");
		}

		cleanupOldInstances();

		this.gp = createGhidraTestProject(projectName);

		instances.add(this);
	}

	/**
	 * This constructor allows clients to manage their own projects.  Also, this constructor
	 * will not enforce having only a single env instance running, which allows for multi-project
	 * testing.  All other constructors will enforce that a single instance of TestEnv can
	 * be running at one time, closing any previously opened instances before finishing
	 * construction.
	 *
	 * <P>Note: this constructor is meant for subclasses.
	 *
	 * @param project the initialized project
	 */
	protected TestEnv(GhidraProject project) {
		if (!Application.isInitialized()) {
			throw new AssertException("The TestEnv requires the system to be " +
				"initialized before usage.  JUnit test should be an instance of " +
				"GhidraHeadedIntegrationTest or GhidraHeadlessIntegrationTest");
		}

		this.gp = Objects.requireNonNull(project);
	}

	private void cleanupOldInstances() {
		if (instances.isEmpty()) {
			return;
		}

		Msg.error(this,
			"\n\tFound non-disposed() TestEnv instances.  Please examine this test!\n\n");
		Set<TestEnv> copy = new HashSet<>(instances);
		copy.forEach(env -> env.dispose());
	}

	/**
	 * Get the tool associated with this test environment.
	 * @return the default test tool for this environment
	 */
	public PluginTool getTool() {
		return lazyTool();
	}

	/**
	 * Closes the TestEnv's default tool.  This method is asynchronous, so you
	 * must wait for the Swing thread to perform the work yourself.
	 * Watch out for modal dialogs.
	 */
	public void closeTool() {
		if (tool == null) {
			Msg.info(this, "Test Env tool does not exist; cannot close");
			return;
		}

		closeAllProgramsFor(tool);

		// don't want to prompt for saving
		AbstractGenericTest.runSwing(() -> {
			tool.setConfigChanged(false);

		});
		AbstractGenericTest.runSwing(() -> tool.close(), false);
		AbstractGenericTest.waitForSwing();

		tool = null;
	}

	private void closeAllProgramsFor(PluginTool theTool) {
		List<Program> programs = getOpenProgamsFor(theTool);
		programs.forEach(p -> close(p));
	}

	private List<Program> getOpenProgamsFor(PluginTool theTool) {
		//@formatter:off
		List<Program> toolPrograms = programManager.getOpenPrograms()
			.stream()
			.filter(p -> p.getConsumerList().contains(theTool))
			.collect(Collectors.toList())
			;
		//@formatter:on

		return toolPrograms;
	}

	/**
	 * Closes the given tool.  This method is asynchronous, so you must wait for the Swing thread
	 * to perform the work yourself.  Watch out for modal dialogs.
	 * @param toolToClose The tool to close.
	 */
	public void closeTool(final PluginTool toolToClose) {
		closeTool(toolToClose, true);
	}

	public void closeTool(PluginTool toolToClose, boolean ignoreChanges) {
		if (toolToClose == tool) {
			tool = null;
		}

		extraTools.remove(toolToClose);
		AbstractGenericTest.executeOnSwingWithoutBlocking(() -> {
			if (ignoreChanges) {
				toolToClose.setConfigChanged(false);
			}
			toolToClose.close();
		});
	}

	protected void disposeFrontEndTool() {
		if (frontEndTool == null) {
			return;
		}

		AbstractGenericTest.runSwing(() -> frontEndTool.close());
		frontEndTool = null;
		removeFrontEndFromSystem();
	}

	private void dipsoseTestTools() {
		AbstractGenericTest.runSwing(() -> {
			disposeSingleTool(tool);

			Iterator<PluginTool> it = extraTools.iterator();
			while (it.hasNext()) {
				PluginTool pt = it.next();
				disposeSingleTool(pt);
			}
			extraTools.clear();
		});
	}

	private void disposeSingleTool(final PluginTool pluginTool) {
		if (pluginTool == null) {
			return; // can happen if the default tool is not initialized
		}

		String toolName = pluginTool.getName();
		try {
			pluginTool.setConfigChanged(false); // don't want to prompt for saving
			pluginTool.close();
			cleanupAutoAnalysisManagers(pluginTool);
		}
		catch (Throwable t) {
			Msg.error(TestEnv.class, "Unexpected exception closing tool: " + toolName, t);
		}
	}

	public void saveRestoreToolState() {
		AbstractGenericTest.runSwing(() -> {
			Element element = lazyTool().saveDataStateToXml(true);
			lazyTool().restoreDataStateFromXml(element);
		});
	}

	public <T extends Plugin> T getPlugin(Class<T> c) {
		return AbstractGhidraHeadlessIntegrationTest.getPlugin(lazyTool(), c);
	}

	/**
	 * Adds and returns the plugin to this env's tool for the given class.   
	 * 
	 * <P>If you have not created a tool using this env, then the default 
	 * tool from {@link #lazyTool()} is used.  If you have launched a tool, then that tool
	 * is used.   In the following example, the given plugin is added to the default tool:
	 * <pre>
	 * 		TestEnv env = new TestEnv();
	 * 		env.launchDefaultTool();
	 * 		FooPlugin foo = env.addPlugin(FooPlugin.class);
	 * </pre> 
	 * 
	 * 
	 * @param c the plugin class
	 * @return the plugin instance
	 * @throws PluginException if there is an exception adding the given tool 
	 */
	public <T extends Plugin> T addPlugin(Class<T> c) throws PluginException {
		PluginTool defaultTool = lazyTool();
		defaultTool.addPlugin(c.getName());
		return AbstractGhidraHeadlessIntegrationTest.getPlugin(defaultTool, c);
	}

	/**
	 * Shows any previously created tool, creating a simple empty tool if not tool has yet 
	 * been created.  
	 * 
	 * <P>This method is considered sub-standard and users should prefer instead 
	 * {@link #launchDefaultTool()} or {@link #launchDefaultTool(Program)}.
	 * 
	 * @return the newly shown tool
	 */
	public PluginTool showTool() {
		return AbstractGhidraHeadedIntegrationTest.showTool(lazyTool());
	}

	/**
	 * Shows any previously created tool, creating a simple empty tool if not tool has yet 
	 * been created.  The given program will be opened in the tool.
	 * 
	 * <P>This method is considered sub-standard and users should prefer instead 
	 * {@link #launchDefaultTool()} or {@link #launchDefaultTool(Program)}.
	 * 
	 * @param p the program
	 * @return the newly shown tool
	 */
	public PluginTool showTool(Program p) {

		open(p); // this call lazyTool()
		PluginTool t = AbstractGhidraHeadedIntegrationTest.showTool(lazyTool());
		removeAllConsumersExceptTool(p, t);
		return t;
	}

	private void removeAllConsumersExceptTool(Program p, PluginTool t) {
		p.getConsumerList().forEach(c -> {
			if (c != t) {
				p.release(c);
			}
		});
	}

	@Deprecated // use DockingTestCase.waitForWindow(String title) instead
	public Window waitForWindow(String title, int timeoutMS) {
		return AbstractDockingTest.waitForWindow(title, timeoutMS);
	}

	/**
	 * Waits for the first window of the given class.  This method is the same as
	 * {@link #waitForDialogComponent(Class, int)} with the exception that the parent
	 * window is assumed to be this instance's tool frame.
	 *
	 * @param ghidraClass The class of the dialog the user desires
	 * @param maxTimeMS The max amount of time in milliseconds to wait for the requested dialog
	 *        to appear.
	 * @return The first occurrence of a dialog that extends the given <code>ghirdraClass</code>
	 * @deprecated use instead {@link AbstractDockingTest#waitForDialogComponent(Class)}
	 */
	@Deprecated
	public <T extends DialogComponentProvider> T waitForDialogComponent(Class<T> ghidraClass,
			int maxTimeMS) {
		return AbstractDockingTest.waitForDialogComponent(ghidraClass);
	}

	private static GhidraProject createGhidraTestProject(String projectName) throws IOException {

		// delete this content before creating the project, as the project may try to use
		// these files when initializing
		deleteOldTestTools();
		deleteSavedFrontEndTool();

		String projectDirectoryName = AbstractGTest.getTestDirectoryPath();
		GhidraProject gp = GhidraProject.createProject(projectDirectoryName, projectName, true);

		installDefaultTool(gp);

		return gp;
	}

	private static void deleteOldTestTools() {
		// this fixes tool loading from previous tests that have classes not in current classpath
		String toolDirPath = ToolUtils.getApplicationToolDirPath();
		FileUtilities.deleteDir(new File(toolDirPath));
	}

	private static void deleteSavedFrontEndTool() {
		String frontEndFilename =
			(String) TestUtils.getInstanceField("FRONT_END_FILE_NAME", FrontEndTool.class);
		File frontEndFile = new File(Application.getUserSettingsDirectory(), frontEndFilename);
		if (frontEndFile.exists()) {
			frontEndFile.delete();
		}
	}

	private static void installDefaultTool(GhidraProject gp) {
		// 
		// Unusual Code Alert: The default tool is not always found in the testing environment,  
		// depending upon where the test lives.   This code maps the test tool to that tool name
		// so that tests will have the default tool as needed.
		// 
		Project project = gp.getProject();
		ToolChest toolChest = project.getLocalToolChest();
		ToolTemplate template = getToolTemplate(AbstractGenericTest.DEFAULT_TEST_TOOL_NAME);
		template.setName(AbstractGenericTest.DEFAULT_TOOL_NAME);
		AbstractGenericTest.runSwing(() -> toolChest.replaceToolTemplate(template));
	}

	private void initializeSimpleTool() {

		if (tool != null) {
			throw new AssertException("Tool already exists--you are doing something wrong!");
		}

		AbstractGenericTest.runSwing(() -> {

			Project project = gp.getProject();
			tool = new TestTool(project);

			try {
				tool.addPlugin(ProgramManagerPlugin.class.getName());
			}
			catch (PluginException e) {
				e.printStackTrace();
			}
		}, true);

		getFrontEndTool(); // initialize the Front End
	}

	private PluginTool lazyTool() {
		if (tool != null) {
			return tool;
		}

		initializeSimpleTool();
		return tool;
	}

	public FrontEndTool getFrontEndTool() {
		if (frontEndTool != null) {
			return frontEndTool;
		}

		AbstractGenericTest.runSwing(() -> {
			frontEndTool = new TestFrontEndTool(gp.getProjectManager());
			frontEndTool.setActiveProject(getProject());

			// turn off auto-saving so tests don't affect other tests
			setAutoSaveEnabled(frontEndTool, false);
			frontEndTool.setConfigChanged(false);
		});

		return frontEndTool;
	}

	public ComponentProvider getFrontEndProvider() {
		ComponentProvider provider =
			(ComponentProvider) TestUtils.invokeInstanceMethod("getProvider", getFrontEndTool());
		return provider;
	}

	private void removeFrontEndFromSystem() {
		TestUtils.setInstanceField("tool", AppInfo.class, null);
	}

	public FrontEndTool showFrontEndTool() {
		getFrontEndTool();
		AbstractGhidraHeadedIntegrationTest.showTool(frontEndTool);
		return frontEndTool;
	}

	/**
	 * This method differs from {@link #launchDefaultTool()} in that this method does not set the
	 * <code>tool</code> variable in of this <code>TestEnv</code> instance.
	 * @return the tool
	 */
	public PluginTool createDefaultTool() {
		PluginTool newTool = launchDefaultToolByName(AbstractGenericTest.DEFAULT_TEST_TOOL_NAME);
		return newTool;
	}

	/**
	 * Launches the default tool of the test system ("CodeBrowser").
	 * This method will load the tool from resources and <b>not from the
	 * user's Ghidra settings</b>.
	 * <p>
	 * <b>Note:</b> Calling this method also changes the tool that this
	 * instance of the TestEnv is using, which is the reason for the existence
	 * of this method.
	 * @return the tool that is launched
	 */
	public PluginTool launchDefaultTool() {

		if (tool != null) {
			Msg.error(this, "Tool already exists--you are doing something wrong!");
		}

		tool = launchDefaultToolByName(AbstractGenericTest.DEFAULT_TEST_TOOL_NAME);
		if (tool == null) {
			throw new NullPointerException(
				"Unable to launch the default tool: " + AbstractGenericTest.DEFAULT_TEST_TOOL_NAME);
		}

		return tool;
	}

	protected PluginTool launchDefaultToolByName(String toolName) {

		return AbstractGenericTest.runSwing(() -> {

			ToolTemplate toolTemplate = getToolTemplate(toolName);
			if (toolTemplate == null) {
				Msg.debug(this, "Unable to find tool: " + toolName);
				return null;
			}

			boolean wasErrorGUIEnabled = AbstractDockingTest.isUseErrorGUI();
			AbstractDockingTest.setErrorGUIEnabled(false); // disable the error GUI while launching the tool
			FrontEndTool frontEndToolInstance = getFrontEndTool();

			Project project = frontEndToolInstance.getProject();
			ToolManager toolManager = project.getToolManager();
			Workspace workspace = toolManager.getActiveWorkspace();

			AbstractDockingTest.setErrorGUIEnabled(wasErrorGUIEnabled);
			return workspace.runTool(toolTemplate);
		});
	}

	private static ToolTemplate getToolTemplate(String toolName) {

		return AbstractGenericTest.runSwing(() -> {
			ToolTemplate toolTemplate =
				ToolUtils.readToolTemplate("defaultTools/" + toolName + ToolUtils.TOOL_EXTENSION);
			if (toolTemplate == null) {
				Msg.debug(TestEnv.class, "Unable to find tool: " + toolName);
				return null;
			}
			return toolTemplate;
		});
	}

	public ScriptTaskListener runScript(File scriptFile) throws PluginException {
		GhidraScriptMgrPlugin scriptManagerPlugin = getPlugin(GhidraScriptMgrPlugin.class);
		if (scriptManagerPlugin == null) {
			lazyTool().addPlugin(GhidraScriptMgrPlugin.class.getName());
			scriptManagerPlugin = getPlugin(GhidraScriptMgrPlugin.class);
		}

		JavaScriptProvider scriptProvider = new JavaScriptProvider();
		PrintWriter writer = new PrintWriter(System.out);
		ResourceFile resourceFile = new ResourceFile(scriptFile);
		GhidraScript script = null;
		try {
			script = scriptProvider.getScriptInstance(resourceFile, writer);
		}
		catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
			e.printStackTrace();

		}
		if (script == null) {
			writer.flush();
			throw new RuntimeException("Failed to compile script " + scriptFile.getAbsolutePath());
		}

		String scriptName = scriptFile.getName();
		ScriptTaskListener listener = new ScriptTaskListener(scriptName);
		scriptManagerPlugin.runScript(scriptName, listener);
		return listener;
	}

	/**
	 * Returns GhidraProject associated with this environment
	 * @return the project
	 */
	public GhidraProject getGhidraProject() {
		return gp;
	}

	/**
	 * A convenience method to close and then reopen the default project created by this TestEnv
	 * instance.  This will not delete the project between opening and closing and will restore
	 * the project to its previous state.
	 * @throws IOException if any exception occurs while saving and reopening
	 */
	public void closeAndReopenProject() throws IOException {
		gp.setDeleteOnClose(false);
		Project project = gp.getProject();
		ProjectLocator projectLocator = project.getProjectLocator();
		gp.close();

		extraTools.clear();

		gp = GhidraProject.openProject(
			projectLocator.getProjectDir().getParentFile().getAbsolutePath(),
			projectLocator.getName(), true /* restore the project */);
		gp.setDeleteOnClose(true);
		initializeSimpleTool();
	}

	public ProjectManager getProjectManager() {
		return gp.getProjectManager();
	}

	public Project getProject() {
		return gp.getProject();
	}

	public PluginTool restartTool() {
		closeTool();

		AbstractGenericTest.waitForSwing();

		tool = null;
		initializeSimpleTool();

		return tool;
	}

	/**
	 * Launches another default tool, not overwriting this env's current tool.
	 * @return the new tool
	 */
	public PluginTool launchAnotherDefaultTool() {
		PluginTool newTool = createDefaultTool();
		AbstractGenericTest.runSwing(() -> newTool.setToolName(newTool.getToolName() + toolID++));
		extraTools.add(newTool);
		return newTool;

	}

	/**
	 * Returns an array of tools spawned by the Ghidra environment.
	 * NOTE: This array will not contain any of the TestTools!
	 * @return an array of tools spawned by the Ghidra environment
	 */
	public PluginTool[] getGhidraCreatedTools() {
		return gp.getProject().getToolManager().getRunningTools();
	}

	public ToolConnection connectTools(PluginTool producer, PluginTool consumer) {
		ToolConnection tc = gp.getProject().getToolManager().getConnection(producer, consumer);
		String[] events = tc.getEvents();
		for (String element : events) {
			tc.connect(element);
		}
		return tc;
	}

	public void disconnectTools(PluginTool producer, PluginTool consumer) {

		if (producer == null || consumer == null) {
			return; // can happen if the default tool was never initialized
		}

		ToolConnection tc = gp.getProject().getToolManager().getConnection(producer, consumer);
		String[] events = tc.getEvents();
		for (String element : events) {
			tc.disconnect(element);
		}
	}

	/**
	 * Copies the specified program zip file to the JUnit test project's root folder. <b>This
	 * means that the program will appear in the FrontEndTool as part of the project.</b>  That is
	 * the only reason to use this method vice openProgram().
	 *
	 * @param programName the name of the program zip file without the ".gzf" extension.
	 * @return the restored domain file
	 * @throws FileNotFoundException if the program file cannot be found
	 */
	public DomainFile restoreProgram(String programName) throws FileNotFoundException {
		DomainFile df = programManager.addProgramToProject(getProject(), programName);
		return df;
	}

	public static ResourceFile findProvidedDataTypeArchive(String relativePathName) {
		relativePathName = relativePathName.replace('\\', '/');
		String suffix = FileDataTypeManager.SUFFIX;
		if (!relativePathName.endsWith(suffix)) {
			relativePathName = relativePathName + suffix;
		}
		for (ResourceFile file : Application.findFilesByExtensionInApplication(suffix)) {
			String path = file.getAbsolutePath().replace('\\', '/');
			if (path.endsWith(relativePathName)) {
				return file;
			}
		}
		return null;
	}

	/**
	 * Creates a project data type archive in the indicated test project folder from the ".gdt"
	 * file indicated by the relative pathname.
	 *
	 * @param relativePathName This should be a pathname relative to the "test_resources/testdata"
	 * 		  director or relative to the "typeinfo" directory. The name should
	 *        include the ".gdt" suffix.
	 * @param domainFolder the folder in the test project where the archive should be created
	 * @return the domain file  that was created in the project
	 * @throws Exception if an exception occurs
	 */
	public DomainFile restoreDataTypeArchive(String relativePathName, DomainFolder domainFolder)
			throws Exception {

		File gdtFile;
		try {
			gdtFile = AbstractGenericTest.getTestDataFile(relativePathName);
		}
		catch (FileNotFoundException e) {
			gdtFile = findProvidedDataTypeArchive(relativePathName).getFile(true);
		}

		if (gdtFile == null || !gdtFile.exists()) {
			throw new RuntimeException("Data type archive not found: " + relativePathName);
		}

		String baseName = relativePathName;
		String suffix = FileDataTypeManager.SUFFIX;
		if (relativePathName.toLowerCase().endsWith(suffix)) {
			baseName = baseName.substring(0, baseName.length() - suffix.length());
		}

		int lastIndex = baseName.lastIndexOf('/');
		if (lastIndex >= 0) {
			baseName = baseName.substring(lastIndex + 1);
		}

		lastIndex = baseName.lastIndexOf('\\');
		if (lastIndex >= 0) {
			baseName = baseName.substring(lastIndex + 1);
		}

		String name = baseName;
		DomainObject domainObject = null;
		DomainFile domainFile = null;
		try {
			TaskMonitor monitor = TaskMonitor.DUMMY;
			domainFile = domainFolder.createFile(name, gdtFile, monitor);
			domainObject = domainFile.getDomainObject(this, true, false, monitor);
			if (domainObject.canSave()) {
				domainObject.save("Saving " + gdtFile.getName() + " GDT to project", monitor);
			}
		}
		catch (CancelledException e) {
			// can't happen; dummy monitor
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}
		return domainFile;
	}

	/**
	 * Save a program to the cached program store.  A SaveAs will be performed on the
	 * program to its cached storage location.
	 * @param progName program name
	 * @param program program object
	 * @param replace if true any existing cached database with the same name will be replaced
	 * @param monitor task monitor
	 * @throws Exception if already cached
	 */
	public void saveToCache(String progName, ProgramDB program, boolean replace,
			TaskMonitor monitor) throws Exception {

		programManager.saveToCache(progName, program, replace, monitor);
	}

	/**
	 * Determine if specified program already exists with the program cache
	 * @param programName the name
	 * @return true if specified program already exists with the program cache
	 */
	public boolean isProgramCached(String programName) {
		return programManager.isProgramCached(programName);
	}

	/**
	 * Remove specified program from cache
	 * @param programName the name
	 */
	public void removeFromProgramCache(String programName) {
		programManager.removeFromProgramCache(programName);
	}

	public ProgramDB loadAnalyzedNotepad() {
		return getProgram("pe/w2krtm/NOTEPAD.EXE.analyzed.dont.edit");
	}

	/**
	 * Open a read-only test program from the test data directory.
	 * This program must be released prior to disposing this test environment.
	 * NOTE: Some tests rely on this method returning null when file does
	 * not yet exist within the resource area (e.g., test binaries for P-Code Tests)
	 *
	 * @param programName name of program database within the test data directory.
	 * @return program or null if program file not found
	 */

	public ProgramDB getProgram(String programName) {
		ProgramDB p = programManager.getProgram(programName);
		return p;
	}

	/**
	 * Launches the default tool of the test system ("CodeBrowser") using the
	 * given program.   This method will load the tool from resources and <b>not from the
	 * user's Ghidra settings</b>.
	 * <p>
	 * <b>Note:</b> Calling this method also changes the tool that this
	 * instance of the TestEnv is using, which is the reason for the existence
	 * of this method.
	 *
	 * @param program The program to load into the default tool; may be null
	 * @return the tool that is launched
	 */
	public PluginTool launchDefaultTool(Program program) {

		if (tool != null) {
			throw new AssertException("Tool already exists--you are doing something wrong!");
		}

		AbstractGenericTest.runSwing(() -> {
			tool = launchDefaultTool();
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});

		if (tool == null) {
			throw new NullPointerException(
				"Unable to launch the default tool: " + ToolServices.DEFAULT_TOOLNAME);
		}

		AbstractGenericTest.waitForSwing();

		removeAllConsumersExceptTool(program, tool);

		if (program != null) {
			programManager.add(program);
		}

		return tool;
	}

	/**
	 * Launches a tool of the given name using the given domain file.
	 * <p>
	 * Note: the tool returned will have auto save disabled by default.
	 * 
	 * @param toolName the tool's name
	 * @return the tool that is launched
	 */
	public PluginTool launchTool(String toolName) {
		return launchTool(toolName, null);
	}

	/**
	 * Launches a tool of the given name using the given domain file.
	 * <p>
	 * Note: the tool returned will have auto save disabled by default.
	 *
	 * @param toolName the name of the tool to launch
	 * @param domainFile The domain file used to launch the tool; may be null
	 * @return the tool that is launched
	 */
	public PluginTool launchTool(final String toolName, final DomainFile domainFile) {
		AtomicReference<PluginTool> ref = new AtomicReference<>();

		AbstractGenericTest.runSwing(() -> {
			boolean wasErrorGUIEnabled = AbstractDockingTest.isUseErrorGUI();
			AbstractDockingTest.setErrorGUIEnabled(false); // disable the error GUI while launching the tool
			FrontEndTool frontEndToolInstance = getFrontEndTool();

			Project project = frontEndToolInstance.getProject();
			ToolServices toolServices = project.getToolServices();
			PluginTool newTool = toolServices.launchTool(toolName, null);
			if (newTool == null) {
				// couldn't find the tool in the workspace...check the test area
				newTool = launchDefaultToolByName(toolName);
			}

			ref.set(newTool);

			AbstractDockingTest.setErrorGUIEnabled(wasErrorGUIEnabled);
			newTool.acceptDomainFiles(new DomainFile[] { domainFile });
		});

		PluginTool launchedTool = ref.get();
		if (launchedTool == null) {
			throw new NullPointerException("Unable to launch the tool: " + toolName);
		}

		// this will make sure that our tool is closed during disposal
		extraTools.add(launchedTool);
		return launchedTool;
	}

	/**
	 * Sets the auto-save feature for all tool instances running under the {@link FrontEndTool}
	 * created by this TestEnv instance.  Auto-save is off by default when testing.
	 *
	 * @param enabled true enables auto-save
	 */
	public void setAutoSaveEnabled(boolean enabled) {
		FrontEndTool frontEndToolInstance = getFrontEndTool();
		setAutoSaveEnabled(frontEndToolInstance, enabled);
	}

	protected void setAutoSaveEnabled(final FrontEndTool frontEndToolInstance,
			final boolean enabled) {
		AbstractGenericTest.runSwing(() -> {
			Options options = frontEndToolInstance.getOptions(ToolConstants.TOOL_OPTIONS);
			options.setBoolean(FrontEndTool.AUTOMATICALLY_SAVE_TOOLS, enabled);
		});
	}

	public Program loadResourceProgramAsBinary(String programName, Language language,
			CompilerSpec compilerSpec) throws LanguageNotFoundException, IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {
		File file = AbstractGenericTest.getTestDataFile(programName);
		if (file == null || !file.exists()) {
			throw new FileNotFoundException("Can not find test program: " + programName);
		}
		return gp.importProgram(file, language, compilerSpec);
	}

	public Program loadResourceProgramAsBinary(String programName, Processor processor)
			throws CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, IOException {
		Language language =
			DefaultLanguageService.getLanguageService().getDefaultLanguage(processor);
		CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
		return loadResourceProgramAsBinary(programName, language, compilerSpec);
	}

	/**
	 * Release a program which was obtained from this test environment.
	 * @param program the program
	 */
	public void release(Program program) {
		programManager.release(program);
	}

	/**
	 * Special code to make sure that the tool used by an AutoAnalysis manager instance is
	 * removed.  This prevents the accidental re-use of the wrong tool between test runs.
	 * (Why?  Well, the AA manager has a static map of tools and it sometimes picks tools to
	 * use based upon which GUI window is active, which when the current window is not active,
	 * can cause the wrong tool to be used for a test, which means that a disposed tool can
	 * be used, which prevents AA from running).
	 * <p>
	 * This code is our use of inside knowledge to cleanup testing artifacts.
	 * <p>
	 * Note: if each test fired a 'program closed' event, then this wouldn't be an issue, but
	 * they don't.  Further, doing that here has ramifications with threading and timely
	 * closing of the test environment.  So, rather than fire an event here, we will just
	 * do our magic.
	 */
	private void cleanupAutoAnalysisManagers(PluginTool t) {

		@SuppressWarnings("unchecked")
		Map<Program, AutoAnalysisManager> map =
			(Map<Program, AutoAnalysisManager>) TestUtils.getInstanceField("managerMap",
				AutoAnalysisManager.class);
		Collection<AutoAnalysisManager> managers = map.values();
		for (AutoAnalysisManager manager : managers) {
			@SuppressWarnings("unchecked")
			Map<Program, WeakSet<PluginTool>> toolMap =
				(Map<Program, WeakSet<PluginTool>>) TestUtils.getInstanceField("toolMap", manager);

			Collection<WeakSet<PluginTool>> values = toolMap.values();
			for (WeakSet<PluginTool> toolSet : values) {
				Iterator<PluginTool> iterator = toolSet.iterator();
				while (iterator.hasNext()) {
					PluginTool aaTool = iterator.next();
					manager.removeTool(aaTool);
				}
			}
		}
	}

	/**
	 * Opens the given program in the test tool.
	 *
	 * @param program the program to open
	 */
	public void open(Program program) {
		lazyTool().firePluginEvent(new OpenProgramPluginEvent("Test", program));
		programManager.add(program);
	}

	/**
	 * Closes the given program, ignoring all changes, for each tool known to this TestEnv.
	 *
	 * @param p the program to close
	 */
	public void close(Program p) {

		release(p);

		boolean ignoreChanges = true;
		lazyTool().firePluginEvent(new CloseProgramPluginEvent("Test", p, ignoreChanges));

		extraTools.forEach(
			t -> t.firePluginEvent(new CloseProgramPluginEvent("Test", p, ignoreChanges)));
	}

	// we are a framework method, so we know it is OK to call the deprecated Swing wait methods
	public void dispose() {

		instances.remove(this);

		AbstractDockingTest.disposeErrorGUI();

		printOpenModalDialogs();

		try {
			disconnectConnectedTools();
		}
		catch (Throwable t) {
			Msg.error(TestEnv.class, "Problem disconnecting tools", t);
		}

		disposeAllTasks();

		markAllProgramsAsUnchanged();

		disposeTestTools();

		privateWaitForSwingRunnables();
		programManager.disposeOpenPrograms();

		if (gp.getProject() == null) {
			throw new IllegalStateException("The TestEnv's GhidraProject has already been closed!");
		}

		Project project = gp.getProject();
		String projectName = project.getName();
		try {
			AbstractGenericTest.runSwing(() -> gp.close());
		}
		catch (Throwable t) {
			Msg.error(TestEnv.class, "Problem disposing the test project", t);
		}

		privateWaitForSwingRunnables();

		disposeFrontEndTool();

		AbstractDockingTest.closeAllWindows(true);

		disposeAllSwingUpdateManagers();

		deleteTestProject(projectName);
	}

	private void deleteTestProject(String projectName) {
		boolean deletedProject = AbstractGhidraHeadlessIntegrationTest.deleteProject(
			AbstractGTest.getTestDirectoryPath(), projectName);

		if (!deletedProject) {
			Msg.error(TestEnv.class, "dispose() - Open programs after disposing project: ");
			Iterator<Program> iterator = ProgramUtilities.getSystemPrograms();
			while (iterator.hasNext()) {
				Program program = iterator.next();
				if (program.isClosed()) {
					continue;
				}
				System.err.println("->" + projectName + " " + program.getName());
				printProgramConsumers(program);
			}

			// signal a potential issue by printing out a throwable--we don't throw the exception
			// so that the tests may limp along if this is not a serious issue--throwing the
			// exception my prevent other cleanup from taking place.
			Msg.error(TestEnv.class, "Unable to delete project: " + projectName +
				" in directory: " + AbstractGTest.getTestDirectoryPath(), new RuntimeException());
		}
	}

	private void disposeAllTasks() {

		// Note: background tool tasks are disposed by the tool

		@SuppressWarnings("unchecked")
		Map<Task, TaskMonitor> tasks =
			(Map<Task, TaskMonitor>) TestUtils.getInstanceField("runningTasks",
				TaskUtilities.class);
		for (TaskMonitor tm : tasks.values()) {
			tm.cancel();
		}

		// wait just a bit for the tasks to finish; we don't really care at this point, since
		// we are disposing
		AbstractGTest.waitForConditionWithoutFailing(() -> !TaskUtilities.isExecutingTasks());
		privateWaitForSwingRunnables();
	}

	private void printOpenModalDialogs() {
		boolean hasModal = false;
		Set<Window> windows = AbstractGenericTest.getAllWindows();
		for (Window window : windows) {
			if (window instanceof Dialog) {
				if (((Dialog) window).isModal() && window.isShowing()) {
					hasModal = true;
					break;
				}
			}
		}

		if (!hasModal) {
			return;
		}

		String windowInfo = AbstractDockingTest.getOpenWindowsAsString();
		if (!windowInfo.isEmpty()) {
			Msg.error(TestEnv.class, "Open modal dialogs - all windows: " + windowInfo);
		}

	}

	private void disposeTestTools() {
		AbstractGenericTest.runSwing(() -> {
			try {
				dipsoseTestTools();
			}
			catch (Throwable t) {
				Msg.error(TestEnv.class, "Problem disposing the test tool", t);
			}
		}, false);

		privateWaitForSwingRunnables();
	}

	// the deprecation is OK--we are a framework method and we know we can use it
	@SuppressWarnings("deprecation")
	private void privateWaitForSwingRunnables() {
		AbstractGenericTest.privateWaitForPostedSwingRunnables_SwingSafe();
	}

	private void disposeAllSwingUpdateManagers() {
		//
		// Cleanup all statically tracked SwingUpdateManagers.  If we do not do this, then as 
		// tools are launched, the number of tracked managers increases, as not all clients of
		// the managers will dispose the managers.
		//
		@SuppressWarnings("unchecked")
		WeakSet<SwingUpdateManager> s =
			(WeakSet<SwingUpdateManager>) TestUtils.getInstanceField("instances",
				SwingUpdateManager.class);

		/* Debug for undisposed SwingUpdateManagers
			Msg.out("complete update manager list: ");
			List<SwingUpdateManager> list = new ArrayList<>(s.values());
			Collections.sort(list, (v1, v2) -> {
		
				return v1.toString().compareTo(v2.toString());
			});
			Msg.out(StringUtils.join(list, ",\n"));
		*/

		AbstractGenericTest.runSwing(() -> s.clear());
	}

	private void markAllProgramsAsUnchanged() {
		programManager.markAllProgramsAsUnchanged();
	}

	private void disconnectConnectedTools() {

		if (extraTools.isEmpty()) {
			return;
		}

		PluginTool[] tools = new PluginTool[extraTools.size()];
		extraTools.toArray(tools);
		for (PluginTool otherTool : tools) {
			disconnectTools(tool, otherTool);
			disconnectTools(otherTool, tool);
		}

		for (int i = 0; i < tools.length; i++) {
			PluginTool tool1 = tools[i];
			for (int j = 0; j < tools.length; j++) {
				if (i == j) {
					continue;
				}
				PluginTool tool2 = tools[j];
				disconnectTools(tool1, tool2);
				disconnectTools(tool2, tool1);
			}
		}
	}

	protected void printProgramConsumers(Program program) {
		List<?> consumerList = (List<?>) AbstractGenericTest.getInstanceField("consumers", program);
		System.err.println("\tConsumers for: " + program.getName());
		for (Object name : consumerList) {
			System.err.println("\t->" + name);
		}
	}

	public void resetDefaultTools() {
		ToolChest tc = gp.getProject().getLocalToolChest();
		// reset default tools in tool chest
		if (tc.getToolCount() > 0) {
			ToolTemplate[] templates = tc.getToolTemplates();
			for (ToolTemplate element : templates) {
				tc.remove(element.getName());
			}
		}

		DefaultProjectManager pm = gp.getProjectManager();
		pm.addDefaultTools(tc);

		installDefaultTool(gp);
	}
}
