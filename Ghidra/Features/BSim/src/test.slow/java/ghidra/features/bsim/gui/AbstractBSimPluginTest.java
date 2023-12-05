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
package ghidra.features.bsim.gui;

import org.junit.After;
import org.junit.Before;

import docking.DockingErrorDisplay;
import docking.action.DockingActionIf;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.features.bsim.gui.overview.*;
import ghidra.features.bsim.gui.search.dialog.BSimOverviewDialog;
import ghidra.features.bsim.gui.search.dialog.BSimSearchDialog;
import ghidra.features.bsim.gui.search.results.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.Msg;

public class AbstractBSimPluginTest extends AbstractGhidraHeadedIntegrationTest {

	protected static final String FUN1_ADDR = "0x01001100";
	protected static final String FUN2_ADDR = "0x01001200";
	protected static final String FUN3_ADDR = "0x01001300";
	protected TestEnv env;
	protected PluginTool tool;
	protected ProgramDB program;

	protected BSimSearchPlugin searchPlugin;
	protected BSimSearchDialog searchDialog;
	protected DockingActionIf searchAction;
	protected DockingActionIf overviewAction;
	protected BSimSearchResultsProvider resultsProvider;
	protected BSimOverviewDialog overviewDialog;
	private BSimOverviewProvider overviewProvider;

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);

		env = new TestEnv();
		tool = env.getTool();

		initializeTool();

		// this will allow our expected warning dialogs to display
		Msg.setErrorDisplay(new DockingErrorDisplay());
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	protected void initializeTool() throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(BSimSearchPlugin.class.getName());

		searchPlugin = env.getPlugin(BSimSearchPlugin.class);

		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		showTool(tool);

		searchAction = getAction(searchPlugin, "BSim Search Functions");
		overviewAction = getAction(searchPlugin, "BSim Overview");
	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);

		builder.createMemory(".text", "0x1001000", 0x10000);
		builder.createReturnInstruction(FUN1_ADDR);
		builder.createEmptyFunction(null, FUN1_ADDR, 10, null);
		builder.createReturnInstruction(FUN2_ADDR);
		builder.createEmptyFunction(null, FUN2_ADDR, 10, null);
		builder.createReturnInstruction(FUN3_ADDR);
		builder.createEmptyFunction(null, FUN3_ADDR, 10, null);
		return builder.getProgram();
	}

	protected void doSearch() {
		pressButtonByText(searchDialog, "Search");
		resultsProvider = waitForComponentProvider(BSimSearchResultsProvider.class);
		BSimMatchResultsModel matchesModel = getMatchesModel();
		waitForTableModel(matchesModel);
	}

	protected void doOverview() {
		pressButtonByText(overviewDialog, "Overview");
		overviewProvider = waitForComponentProvider(BSimOverviewProvider.class);
		BSimOverviewModel overviewModel = getOverviewModel();
		waitForTableModel(overviewModel);
	}

	protected void invokeBSimSearchAction() {
		performAction(searchAction, false);

		searchDialog = waitForDialogComponent(BSimSearchDialog.class);

	}

	protected void invokeBSimOverviewAction() {
		performAction(overviewAction, false);

		overviewDialog = waitForDialogComponent(BSimOverviewDialog.class);

	}

	protected Address addr(String addressString) {
		AddressFactory factory = program.getAddressFactory();
		return factory.getAddress(addressString);
	}

	protected void goTo(String addr) {
		ProgramLocation location = new ProgramLocation(program, addr(addr));
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", location, program));
		waitForSwing();
		program.flushEvents();
		waitForSwing();
	}

	protected BSimMatchResultsModel getMatchesModel() {
		return BSimSearchResultsTestHelper.getSearchResultsModel(resultsProvider);
	}

	protected BSimOverviewModel getOverviewModel() {
		return BSimOverviewTestHelper.getOverviewModel(overviewProvider);
	}

	protected BSimExecutablesSummaryModel getExecutablesModel() {
		return BSimSearchResultsTestHelper.getExecutablesModel(resultsProvider);
	}

}
