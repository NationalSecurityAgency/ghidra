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
package ghidra.framework.main;

import static org.junit.Assert.*;

import java.io.File;
import java.net.URL;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.test.AbstractDockingTest;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.protocol.ghidra.Handler;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class LaunchUrlInToolTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private ProgramDB program;

	private File serverRoot;

	private static final String FILENAME = "Test";
	private static final String FOLDER = "/";
	private static final String FILEPATH = FOLDER + FILENAME;
	private static final String NAMESPACE_NAME = "foo";
	private static final String SYMBOL_NAME = "xyz";
	private static final String REF = NAMESPACE_NAME + Namespace.DELIMITER + SYMBOL_NAME;
	private static final String SYMBOL_ADDR = "0x1001030";
	private static final String REPO_NAME = "Test";

	private URL remoteFileUrl;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		// NOTE: Use of tool templates requires active front-end  tool
		env.getFrontEndTool();

		program = (ProgramDB) buildProgram();
		Project project = env.getProject();
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		rootFolder.createFile("Test", program, TaskMonitor.DUMMY);
	}

	@After
	public void tearDown() {
		killServer();
		env.dispose();
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder(FILENAME, true, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0xb000);
		builder.addBytesFallthrough("0x1001010");
		builder.addBytesFallthrough("0x1001020");
		builder.addBytesFallthrough("0x1001030");
		builder.addBytesFallthrough("0x1001040");
		builder.disassemble("0x1001010", 1);
		builder.disassemble("0x1001020", 1);
		builder.disassemble("0x1001030", 1);
		builder.disassemble("0x1001040", 1);
		Program p = builder.getProgram();

		int txId = p.startTransaction("Add Label");
		try {
			AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();
			Address addr = space.getAddress(SYMBOL_ADDR);
			SymbolTable symbolTable = p.getSymbolTable();
			Namespace ns =
				symbolTable.createNameSpace(null, NAMESPACE_NAME, SourceType.USER_DEFINED);
			symbolTable.createLabel(addr, SYMBOL_NAME, ns, SourceType.USER_DEFINED);
		}
		catch (Exception e) {
			throw new AssertException(e);
		}
		finally {
			p.endTransaction(txId, true);
		}

		return p;
	}

	@Test
	public void testLocalLaunchDefaultTool() throws Exception {

		Project project = env.getProject();
		setupDefaultTestTool(project);

		ProjectLocator projectLocator = env.getProject().getProjectLocator();

		URL url = GhidraURL.makeURL(projectLocator, FILEPATH, REF);

		AtomicReference<PluginTool> ref = new AtomicReference<>();
		runSwing(() -> {
			boolean wasErrorGUIEnabled = AbstractDockingTest.isUseErrorGUI();
			ToolServices toolServices = project.getToolServices();
			ref.set(toolServices.launchDefaultToolWithURL(url));
			AbstractDockingTest.setErrorGUIEnabled(wasErrorGUIEnabled);
		});

		verifyLaunch(ref.get());
	}

	@Test
	public void testLocalLaunchNamedTool() throws Exception {

		Project project = env.getProject();
		ProjectLocator projectLocator = project.getProjectLocator();

		URL url = GhidraURL.makeURL(projectLocator, FILEPATH, REF);

		AtomicReference<PluginTool> ref = new AtomicReference<>();
		runSwing(() -> {
			boolean wasErrorGUIEnabled = AbstractDockingTest.isUseErrorGUI();
			ToolServices toolServices = project.getToolServices();
			ref.set(toolServices.launchToolWithURL(DEFAULT_TEST_TOOL_NAME, url));
			AbstractDockingTest.setErrorGUIEnabled(wasErrorGUIEnabled);
		});

		verifyLaunch(ref.get());
	}

	@Test
	public void testBad1LocalLaunchDefaultTool() throws Exception {

		Project project = env.getProject();
		setupDefaultTestTool(project);

		ProjectLocator projectLocator = env.getProject().getProjectLocator();

		URL url = GhidraURL.makeURL(projectLocator, FOLDER, null);

		ToolServices toolServices = project.getToolServices();
		PluginTool tool = toolServices.launchDefaultToolWithURL(url);
		assertNull(tool);

		DialogComponentProvider dlg = waitForDialogComponent("Unsupported Content");
		assertNotNull("Error dialog expected", dlg);
		runSwing(() -> dlg.close());
	}

	@Test
	public void testBad2LocalLaunchDefaultTool() throws Exception {

		Project project = env.getProject();
		setupDefaultTestTool(project);

		ProjectLocator projectLocator = env.getProject().getProjectLocator();

		URL url = GhidraURL.makeURL(projectLocator, "/x/y", null);

		ToolServices toolServices = project.getToolServices();
		PluginTool tool = toolServices.launchDefaultToolWithURL(url);
		assertNull(tool);

		DialogComponentProvider dlg = waitForDialogComponent("Content Not Found");
		assertNotNull("Error dialog expected", dlg);
		runSwing(() -> dlg.close());
	}

	@Test
	public void testRemoteLaunchDefaultTool() throws Exception {
		startServer(); // also changes user's identity

		Project project = env.getProject();
		setupDefaultTestTool(project);

		AtomicReference<PluginTool> ref = new AtomicReference<>();
		runSwing(() -> {
			boolean wasErrorGUIEnabled = AbstractDockingTest.isUseErrorGUI();
			ToolServices toolServices = project.getToolServices();
			ref.set(toolServices.launchDefaultToolWithURL(remoteFileUrl));
			AbstractDockingTest.setErrorGUIEnabled(wasErrorGUIEnabled);
		});

		verifyLaunch(ref.get());
	}

	@Test
	public void testRemoteLaunchNamedTool() throws Exception {
		startServer(); // also changes user's identity

		Project project = env.getProject();
		setupDefaultTestTool(project);

		AtomicReference<PluginTool> ref = new AtomicReference<>();
		runSwing(() -> {
			boolean wasErrorGUIEnabled = AbstractDockingTest.isUseErrorGUI();
			ToolServices toolServices = project.getToolServices();
			ref.set(toolServices.launchToolWithURL(DEFAULT_TEST_TOOL_NAME, remoteFileUrl));
			AbstractDockingTest.setErrorGUIEnabled(wasErrorGUIEnabled);
		});

		verifyLaunch(ref.get());
	}

	@Test
	public void testRemoteBad1LaunchDefaultTool() throws Exception {
		startServer(); // also changes user's identity

		Project project = env.getProject();
		setupDefaultTestTool(project);

		URL badUrl = GhidraURL.makeURL(ServerTestUtil.LOCALHOST,
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, REPO_NAME, FOLDER, null, null);

		ToolServices toolServices = project.getToolServices();
		PluginTool tool = toolServices.launchDefaultToolWithURL(badUrl);
		assertNull(tool);

		DialogComponentProvider dlg = waitForDialogComponent("Unsupported Content");
		assertNotNull("Error dialog expected", dlg);
		runSwing(() -> dlg.close());
	}

	@Test
	public void testRemoteBad2LaunchDefaultTool() throws Exception {
		startServer(); // also changes user's identity

		Project project = env.getProject();
		setupDefaultTestTool(project);

		URL badUrl = GhidraURL.makeURL(ServerTestUtil.LOCALHOST,
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, REPO_NAME, FOLDER, "x", REF);

		ToolServices toolServices = project.getToolServices();
		PluginTool tool = toolServices.launchDefaultToolWithURL(badUrl);
		assertNull(tool);

		DialogComponentProvider dlg = waitForDialogComponent("Content Not Found");
		assertNotNull("Error dialog expected", dlg);
		runSwing(() -> dlg.close());
	}

	private void verifyLaunch(PluginTool tool) throws Exception {
		assertNotNull("tool failed to launch", tool);

		ProgramManager pm = tool.getService(ProgramManager.class);
		assertNotNull("ProgramManager not found", pm);

		CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
		assertNotNull("CodeViewerService not found", codeViewer);

		ProgramLocation currentLocation = codeViewer.getCurrentLocation();
		assertNotNull("Failed to determine current location", currentLocation);

		Program p = currentLocation.getProgram();

		// Verify that it was not directly opened via active Project
		assertTrue(p.getDomainFile() instanceof DomainFileProxy);

		AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();
		Address addr = space.getAddress("0x1001030");
		assertEquals(addr, currentLocation.getAddress());
	}

	private void setupDefaultTestTool(Project project) {
		ToolServices toolServices = project.getToolServices();
		ProgramContentHandler handler = new ProgramContentHandler();
		ToolTemplate toolTemplate =
			project.getLocalToolChest().getToolTemplate(DEFAULT_TEST_TOOL_NAME);
		assertNotNull(toolTemplate);
		ToolAssociationInfo info =
			new ToolAssociationInfo(handler, DEFAULT_TEST_TOOL_NAME, toolTemplate, toolTemplate);
		toolServices.setContentTypeToolAssociations(Set.of(info));
	}

	private void killServer() {

		if (serverRoot == null) {
			return;
		}

		ServerTestUtil.disposeServer();

		FileUtilities.deleteDir(serverRoot);
	}

	private void startServer() throws Exception {
		
		// register ghidra protocol and define remote URL to access Test file
		Handler.registerHandler();
		remoteFileUrl = GhidraURL.makeURL(ServerTestUtil.LOCALHOST,
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, REPO_NAME, FOLDER, FILENAME, REF);

		// Create server instance
		serverRoot = new File(getTestDirectoryPath(), "TestServer");
		FileUtilities.deleteDir(serverRoot);

		// Authorized admin user "test" is predefined by ServerTestUtil.createPopulatedTestServer
		ServerTestUtil.setLocalUser(ServerTestUtil.ADMIN_USER);

		ServerTestUtil.createPopulatedTestServer(serverRoot.getAbsolutePath(),
			REPO_NAME, fs -> {
				try {
					ServerTestUtil.createRepositoryItem(fs, FILENAME, FOLDER, program);
				}
				catch (Exception e) {
					failWithException("Failed added server content", e);
				}
			});

		ServerTestUtil.startServer(serverRoot.getAbsolutePath(),
			ServerTestUtil.GHIDRA_TEST_SERVER_PORT, -1, false, false, false);

	}

}
