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
package ghidra.framework.main.datatree;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import docking.tool.ToolConstants;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for opening files.
 */
public class FrontEndPluginOpenProgramActionsTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;
	private DataTree tree;
	private DomainFolder rootFolder;
	private GTreeNode rootNode;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		env.resetDefaultTools();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();
		setErrorGUIEnabled(false);

		tree = findComponent(frontEndTool.getToolFrame(), DataTree.class);
		rootFolder = env.getProject().getProjectData().getRootFolder();
		Program p = ToyProgramBuilder.buildSimpleProgram("sample", this);
		rootFolder.createFile("sample", p, TaskMonitor.DUMMY);
		p.release(this);

		p = ToyProgramBuilder.buildSimpleProgram("x", this);
		rootFolder.createFile("X", p, TaskMonitor.DUMMY);
		p.release(this);

		rootNode = tree.getViewRoot();

		waitForSwing();
		tree.expandPath(rootNode.getTreePath());
		waitForTree();
	}

	@After
	public void tearDown() throws Exception {
		waitForTree();
		env.dispose();
	}

	@Test
	public void testOpenActionsEnabled() throws Exception {
		setSelectionPath(rootNode.getTreePath());
		DockingActionIf openAction = getAction("Open File");
		assertTrue(!openAction.isEnabledForContext(getDomainFileActionContext(rootNode)));

		ToolChest tc = env.getProject().getLocalToolChest();
		ToolTemplate[] configs = tc.getToolTemplates();
		for (ToolTemplate config : configs) {
			DockingActionIf action = getAction("Open" + config.getName());
			assertTrue(!action.isEnabledForContext(getDomainFileActionContext(rootNode)));
			assertTrue(!openAction.isEnabledForContext(getDomainFileActionContext(rootNode)));
		}
	}

	@Test
	public void testOpenInDefaultTool() throws Exception {
		//Open File 
		GTreeNode npNode = rootNode.getChild("sample");
		setSelectionPath(npNode.getTreePath());
		waitForTree();
		DockingActionIf openAction = getAction("Open File");
		performAction(openAction, getFrontEndContext(), true);
		verifyToolExistsAndCloseTool();
	}

	@Test
	public void testOpenInDefaultToolMultipleNewTool() throws Exception {

		ToolOptions options = frontEndTool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.setEnum(FrontEndTool.DEFAULT_TOOL_LAUNCH_MODE, DefaultLaunchMode.NEW_TOOL);

		//Open 1st File 
		DomainFile sampleDf = openInDefaultTool("sample");
		PluginTool[] runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);
		assertOpenFiles(runningTools[0], sampleDf);

		//Open 2nd File in new tool
		DomainFile xDf = openInDefaultTool("X");

		// NOTE: runningTools order may vary
		runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(2, runningTools.length);
		DomainFile[] domainFiles0 = runningTools[0].getDomainFiles();
		assertEquals(1, domainFiles0.length);
		DomainFile[] domainFiles1 = runningTools[1].getDomainFiles();
		assertEquals(1, domainFiles1.length);
		if (sampleDf.equals(domainFiles0[0])) {
			assertEquals(xDf, domainFiles1[0]);
		}
		else if (sampleDf.equals(domainFiles1[0])) {
			assertEquals(xDf, domainFiles0[0]);
		}
		else {
			fail("Unexpected open domain files");
		}

		exitTools(runningTools);
	}

	@Test
	public void testOpenInDefaultToolMultipleReuseTool() throws Exception {

		ToolOptions options = frontEndTool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.setEnum(FrontEndTool.DEFAULT_TOOL_LAUNCH_MODE, DefaultLaunchMode.REUSE_TOOL);

		//Open 1st File 
		DomainFile sampleDf = openInDefaultTool("sample");
		PluginTool[] runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);
		assertOpenFiles(runningTools[0], sampleDf);

		//Open 2nd File in same tool
		DomainFile xDf = openInDefaultTool("X");
		runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);
		assertOpenFiles(runningTools[0], sampleDf, xDf);

		exitTools(runningTools);
	}

	@Test
	public void testOpenMultipleNewTool() throws Exception {

		Program p = ToyProgramBuilder.buildSimpleProgram("y", this);
		rootFolder.createFile("Y", p, TaskMonitor.DUMMY);
		p.release(this);

		ToolOptions options = frontEndTool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.setEnum(FrontEndTool.DEFAULT_TOOL_LAUNCH_MODE, DefaultLaunchMode.NEW_TOOL);

		//Open 1st File 
		DomainFile sampleDf = openInDefaultTool("sample");
		PluginTool[] runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);
		assertOpenFiles(runningTools[0], sampleDf);

		String toolName = runningTools[0].getName();

		//Open two additional files in new tool
		openInTool(toolName, "X", "Y");

		// NOTE: runningTools order may vary
		runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(2, runningTools.length);

		DomainFile[] domainFiles0 = runningTools[0].getDomainFiles();
		DomainFile[] domainFiles1 = runningTools[1].getDomainFiles();
		assertEquals(3, domainFiles0.length + domainFiles1.length);

		exitTools(runningTools);
	}

	@Test
	public void testOpenMultipleReuseTool() throws Exception {

		Program p = ToyProgramBuilder.buildSimpleProgram("y", this);
		rootFolder.createFile("Y", p, TaskMonitor.DUMMY);
		p.release(this);

		ToolOptions options = frontEndTool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.setEnum(FrontEndTool.DEFAULT_TOOL_LAUNCH_MODE, DefaultLaunchMode.REUSE_TOOL);

		//Open 1st File 
		DomainFile sampleDf = openInDefaultTool("sample");
		PluginTool[] runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);
		assertOpenFiles(runningTools[0], sampleDf);

		String toolName = runningTools[0].getName();

		//Open two additional files in same tool
		openInTool(toolName, "X", "Y");

		runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);

		DomainFile[] domainFiles0 = runningTools[0].getDomainFiles();
		assertEquals(3, domainFiles0.length);

		exitTools(runningTools);
	}

	@Test
	public void testOpenWith() throws Exception {

		GTreeNode npNode = rootNode.getChild("sample");
		setSelectionPath(npNode.getTreePath());
		waitForTree();

		ToolChest tc = env.getProject().getLocalToolChest();
		ToolTemplate[] configs = tc.getToolTemplates();

		DockingActionIf action = getAction("Open" + configs[0].getName());
		performAction(action, getFrontEndContext(), true);
		verifyToolExistsAndCloseTool();
	}

	@Test
	public void testOpenWithDoubleClick() throws Exception {
		// make sure that the Code Browser tool is the default
		ToolChest tc = env.getProject().getLocalToolChest();
		ToolTemplate[] configs = tc.getToolTemplates();
		ToolTemplate codeBrowserConfig = null;
		for (ToolTemplate config : configs) {
			if ("CodeBrowser".equals(config.getName())) {
				codeBrowserConfig = config;
			}
		}

		if (codeBrowserConfig == null) {
			Assert.fail("Unable to find the Code Browser config file.");
		}

		// double click on the program node
		GTreeNode npNode = rootNode.getChild("sample");
		JTree jTree = (JTree) invokeInstanceMethod("getJTree", tree);
		Rectangle rect = jTree.getPathBounds(npNode.getTreePath());
		setSelectionPath(npNode.getTreePath());
		waitForTree();

		clickMouse(jTree, MouseEvent.BUTTON1, rect.x, rect.y, 2, 0);

		// make sure that the tool is loaded and processes all of the tasks it launches
		Window window = waitForToolLaunch();

		// DEBUG:
		if (window == null) {
			// see if any tools have been launched
			PluginTool[] runningTools = frontEndTool.getToolServices().getRunningTools();
			for (PluginTool tool : runningTools) {
				System.err.println("\t\"" + tool.getName() + "\"");
				JFrame toolFrame = tool.getToolFrame();
				System.err.println("\t\twith window: " + toolFrame.getTitle());
			}

			System.err.println("Open Windows: ");
			System.err.println(getOpenWindowsAsString());
		}

		assertNotNull(window);
		waitForBusyTool(env.getProject().getToolManager().getRunningTools()[0]);
		waitForTasks();

		verifyToolExistsAndCloseTool();
	}

	private Window waitForToolLaunch() {

		waitForSwing();

		long start = System.currentTimeMillis();
		int tryCount = 0;
		Window window = null;
		while (window == null && tryCount < 5) {
			++tryCount;
			window = waitForValueWithoutFailing(() -> {
				return getWindowByTitleContaining(null,
					"CodeBrowser: " + PROJECT_NAME + ":/sample");
			});
		}

		long total = System.currentTimeMillis() - start;
		assertNotNull("Timed-out waiting for tool - " + total + " ms", window);
		return window;
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ActionContext getFrontEndContext() {
		ComponentProvider provider = env.getFrontEndProvider();
		return runSwing(() -> provider.getActionContext(null));
	}

	private DomainFile openInDefaultTool(String fileName) throws Exception {
		GTreeNode node = rootNode.getChild(fileName);
		assertTrue("Expected domain file node", node instanceof DomainFileNode);
		DomainFileNode fileNode = (DomainFileNode) node;
		DomainFile domainFile = fileNode.getDomainFile();
		setSelectionPath(fileNode.getTreePath());
		waitForTree();
		DockingActionIf openAction = getAction("Open File");
		performAction(openAction, getFrontEndContext(), true);
		return domainFile;
	}

	private List<DomainFile> openInTool(String toolName, String... fileNames) throws Exception {

		ToolServices toolServices = env.getProject().getToolServices();

		ArrayList<DomainFile> domainFiles = new ArrayList<>();
		for (String fileName : fileNames) {
			DomainFile df = rootFolder.getFile(fileName);
			assertNotNull(df);
			domainFiles.add(df);
		}

		runSwing(() -> toolServices.launchTool(toolName, domainFiles));
		waitForSwing();
		return domainFiles;
	}

	private void assertOpenFiles(PluginTool tool, DomainFile... expectedDomainFiles) {
		DomainFile[] domainFiles = tool.getDomainFiles();
		assertArrayEquals(expectedDomainFiles, domainFiles);
	}

	private void exitTools(PluginTool... tools) {
		runSwing(() -> {
			for (PluginTool t : tools) {
				t.close();
			}
		});
	}

	private void verifyToolExistsAndCloseTool() {
		PluginTool[] runningTools = env.getProject().getToolManager().getRunningTools();
		assertEquals(1, runningTools.length);
		exitTools(runningTools[0]);
	}

	private ActionContext getDomainFileActionContext(GTreeNode... nodes) {
		List<DomainFile> fileList = new ArrayList<>();
		List<DomainFolder> folderList = new ArrayList<>();
		for (GTreeNode node : nodes) {
			if (node instanceof DomainFileNode fileNode) {
				fileList.add(fileNode.getDomainFile());
			}
			else if (node instanceof DomainFolderNode folderNode) {
				folderList.add(folderNode.getDomainFolder());
			}
		}

		return new ProjectDataContext(null, null, nodes[0], folderList, fileList, tree, true);

	}

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action =
			AbstractDockingTest.getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private void setSelectionPath(final TreePath path) throws Exception {
		SwingUtilities.invokeAndWait(() -> tree.setSelectionPath(path));
	}

	private void waitForTree() {
		waitForSwing();
		while (tree.isBusy()) {
			try {
				Thread.sleep(10);
			}
			catch (InterruptedException e) {
				// don't care
			}
		}
		waitForSwing();
	}
}
