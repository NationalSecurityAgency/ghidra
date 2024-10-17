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
package help.screenshot;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import docking.DockingWindowManager;
import docking.action.DockingActionIf;
import ghidra.app.services.ProgramManager;
import ghidra.features.bsim.gui.*;
import ghidra.features.bsim.gui.overview.BSimOverviewProvider;
import ghidra.features.bsim.gui.overview.BSimOverviewTestHelper;
import ghidra.features.bsim.gui.search.dialog.*;
import ghidra.features.bsim.gui.search.results.*;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.facade.*;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Msg;

/**
 * Captures screenshots for the BSim help pages. Note that this class does not 
 * generate ALL images used in the BSim help. The following are generated
 * by hand, but should be addressed to be created here at some point:
 * 
 * 		functionmatch.png
 * 		toolbar.png
 * 		client.png
 *
 */
public class BSimSearchPluginScreenShots extends GhidraScreenShotGenerator {
	protected static final String FUN1_ADDR = "0x01001100";
	protected static final String FUN2_ADDR = "0x01001200";
	protected static final String FUN3_ADDR = "0x01001300";
	protected static final String FUN4_ADDR = "0x01001400";

	private BSimSearchPlugin plugin;

	public BSimSearchPluginScreenShots() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		tool.addPlugin(BSimSearchPlugin.class.getName());

		plugin = getPlugin(tool, BSimSearchPlugin.class);
		goTo(tool, program, FUN1_ADDR);
		removeAllServers();
	}

	@Override
	public void loadProgram() throws Exception {
		program = buildProgram();
		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});
	}

	@Override
	public void dockingSetUp() {
		// We get an error dialog about default tools, since this test is not in the
		// Integration Test project.  Disable the error dialogs.
		setErrorGUIEnabled(false);
	}

	@Test
	public void testManageServersDialog() {
		addTestServer(new BSimServerInfo(DBType.postgres, "100.50.123.5", 123, "testDB"));
		addTestServer(new BSimServerInfo(DBType.postgres, "100.50.123.5", 134, "anotherDB"));
		addTestServer(new BSimServerInfo(DBType.file, "100.50.123.5", 134, "/bsim/database1"));

		DockingActionIf action = getAction(plugin, "Manage BSim Servers");
		performAction(action, false);
		BSimServerDialog dialog = waitForDialogComponent(BSimServerDialog.class);

		captureDialog(dialog);
		dialog.close();
	}

	@Test
	public void testAddServerDialog() {
		CreateBsimServerInfoDialog dialog = new CreateBsimServerInfoDialog();
		runSwingLater(() -> DockingWindowManager.showDialog(dialog));
		waitForSwing();
		captureDialog(dialog);
		dialog.close();
	}

	@Test
	public void testBSimOverviewDialog() {

		DockingActionIf action = getAction(plugin, "BSim Overview");
		performAction(action, false);

		BSimOverviewDialog dialog = waitForDialogComponent(BSimOverviewDialog.class);

		captureDialog(dialog);
		dialog.close();
	}

	@Test
	public void testBSimOverviewResults() {
		DockingActionIf action = getAction(plugin, "BSim Overview");
		performAction(action, false);

		BSimOverviewDialog dialog = waitForDialogComponent(BSimOverviewDialog.class);

		FunctionDatabaseTestDouble database = createTestDoubleWithOverviewResults();
		BSimOverviewTestHelper.setBSimOVerviewTestServer(plugin, dialog, database);

		pressButtonByText(dialog, "Overview");
		waitForComponentProvider(BSimOverviewProvider.class);
		captureIsolatedProvider(BSimOverviewProvider.class, 600, 300);
	}

	@Test
	public void testBSimSearchDialog() {

		goTo(tool, program, FUN1_ADDR);

		DockingActionIf action = getAction(plugin, "BSim Search Functions");
		performAction(action, false);

		BSimSearchDialog dialog = waitForDialogComponent(BSimSearchDialog.class);

//		urlEntryField = (JTextField) getInstanceField("bsimFilterPanel", bsimSearchDialog);
//		urlEntryField.setText(DB_URL);

//		BSimFilterPanel filterPanel = getInstanceField("bsimFilterPanel", bsimSearchDialog);
//
//		filterPanel = (DatabaseFilterPanel) getInstanceField("filterPanel", bsimSearchDialog);
//		filterPanel.setSpecificFilter("archequals", "x86:LE:32:default");

		captureDialog(dialog);
		dialog.close();
	}

	@Test
	public void testBSimResultsProvider() {
		goTo(tool, program, FUN1_ADDR);

		DockingActionIf action = getAction(plugin, "BSim Search Functions");
		performAction(action, false);

		BSimSearchDialog dialog = waitForDialogComponent(BSimSearchDialog.class);

		FunctionDatabaseTestDouble database = createTestFunctionDatabaseTestDouble();
		BSimSearchDialogTestHelper.setBSimSearchTestServer(plugin, dialog, database);

		pressButtonByText(dialog, "Search");

		waitForComponentProvider(BSimSearchResultsProvider.class);
		captureIsolatedProvider(BSimSearchResultsProvider.class, 800, 500);

	}

	/*
	 * Showing the results pane using a normal workflow is a bit tricky, and ultimately not
	 * worth the effort. To generate this panel we can just fake out the data and show
	 * the window directly.
	 */
	@Test
	public void testApplyResultsPanel() throws Exception {

		List<BSimApplyResult> results = new ArrayList<>();
		BSimApplyResult r1 = new BSimApplyResult("fun_0001", "foo1", BSimResultStatus.ERROR,
			addr("01001100"), "ERROR: Attempting to apply multiple names to the same function.");
		BSimApplyResult r2 = new BSimApplyResult("fun_0001", "foo2", BSimResultStatus.ERROR,
			addr("0x01001100"), "ERROR: Attempting to apply multiple names to the same function.");
		BSimApplyResult r3 = new BSimApplyResult("set_string", "_set_string",
			BSimResultStatus.NAME_APPLIED, addr("0x01001100"), "");
		BSimApplyResult r4 = new BSimApplyResult("add_code", "addcode2",
			BSimResultStatus.SIGNATURE_APPLIED, addr("0x01001100"), "");
		BSimApplyResult r5 = new BSimApplyResult("__libc_csu_fini", "__libc_csu_fini",
			BSimResultStatus.IGNORED, addr("0x01001100"), "INFO: No change. Names are the same.");
		results.add(r1);
		results.add(r2);
		results.add(r3);
		results.add(r4);
		results.add(r5);

		BSimApplyResultsDisplayDialog resultsPanel =
			runSwing(() -> new BSimApplyResultsDisplayDialog(plugin.getTool(), results, program));

		resultsPanel.setPreferredSize(900, 300);

		tool.showDialog(resultsPanel);
		waitForDialogComponent(BSimApplyResultsDisplayDialog.class);
		captureDialog(resultsPanel);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Address addr(String address) {
		try {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		}
		catch (AddressFormatException e) {
			Msg.error(this, "Error converting " + address + " to an Address", e);
		}

		return null;
	}

	protected void initializeTool() throws Exception {

		plugin = env.getPlugin(BSimSearchPlugin.class);

		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		showTool(tool);

	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Sample Program", true);

		builder.createMemory(".text", "0x1001000", 0x10000);
		builder.createReturnInstruction(FUN1_ADDR);
		builder.createEmptyFunction(null, FUN1_ADDR, 10, null);
		builder.createReturnInstruction(FUN2_ADDR);
		builder.createEmptyFunction(null, FUN2_ADDR, 10, null);
		builder.createReturnInstruction(FUN3_ADDR);
		builder.createEmptyFunction(null, FUN3_ADDR, 10, null);
		builder.createReturnInstruction(FUN4_ADDR);
		builder.createEmptyFunction(null, FUN4_ADDR, 10, null);
		return builder.getProgram();
	}

	private FunctionDatabaseTestDouble createTestFunctionDatabaseTestDouble() {
		FunctionDatabaseTestDouble database = new FunctionDatabaseTestDouble();

		// create some canned data
		ResponseNearest response = new ResponseNearest(null);
		response.result.add(new TestSimilarityResult("queryFunction", "exec1", "matchFunction1",
			0, 0x01001100, 0.9d, 15.0d));
		response.result.add(new TestSimilarityResult("queryFunction", "exec2", "matchFunction2",
			0, 0x01001100, 0.9d, 15.0d));
		response.result.add(new TestSimilarityResult("queryFunction", "exec1", "matchFunction3",
			0, 0x01001100, 0.9d, 15.0d));
		response.result.add(new TestSimilarityResult("queryFunction", "exec1", "matchFunction4",
			0, 0x01001100, 0.9d, 15.0d));

		database.setQueryResponse(response); // set a valid response to be returned on query
		database.setCanInitialize(true); // initialize may be called--this is OK

		return database;
	}

	private FunctionDatabaseTestDouble createTestDoubleWithOverviewResults() {
		FunctionDatabaseTestDouble database = new FunctionDatabaseTestDouble();
		// create some canned data
		ResponseNearestVector response = new ResponseNearestVector(null);
		response.result.add(new TestNearestVectorResult("function1", "exec1", 12, 0.9d));
		response.result.add(new TestNearestVectorResult("function1", "exec2", 8, .9d));
		response.result.add(new TestNearestVectorResult("function2", "exec3", 32, .9d));
		response.result.add(new TestNearestVectorResult("function3", "exec4", 4, 9d));

		database.setQueryResponse(response); // set a valid response to be returned on query
		database.setCanInitialize(true); // initialize may be called--this is OK

		return database;
	}

	private void addTestServer(BSimServerInfo serverInfo) {
		runSwing(() -> {
			BSimServerManager serverManager = BSimSearchPluginTestHelper.getServerManager(plugin);
			serverManager.addServer(serverInfo);
		});

	}

	private void removeAllServers() {
		runSwing(() -> {
			BSimServerManager serverManager = BSimSearchPluginTestHelper.getServerManager(plugin);
			Set<BSimServerInfo> serverInfos = serverManager.getServerInfos();
			for (BSimServerInfo info : serverInfos) {
				serverManager.removeServer(info, true);
			}
		});

	}
}
