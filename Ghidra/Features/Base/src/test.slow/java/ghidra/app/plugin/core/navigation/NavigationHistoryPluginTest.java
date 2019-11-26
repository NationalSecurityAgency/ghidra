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
package ghidra.app.plugin.core.navigation;

import static org.junit.Assert.*;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.QueryData;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.app.util.viewer.field.VariableXRefFieldFactory;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Tests for tool state history plugin.
 */
public class NavigationHistoryPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private NextPrevAddressPlugin nextPrevPlugin;
	private NavigationHistoryPlugin plugin;
	private CodeBrowserPlugin cb;
	private GoToService goToService;
	private DockingActionIf prevAction;
	private DockingActionIf nextAction;
	private Navigatable navigatable;
	private CodeViewerProvider provider;
	private DockingActionIf undoAction;
	private DockingActionIf redoAction;

	@Before
	public void setUp() throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		nextPrevPlugin = env.getPlugin(NextPrevAddressPlugin.class);
		plugin = env.getPlugin(NavigationHistoryPlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		goToService = tool.getService(GoToService.class);
		navigatable = goToService.getDefaultNavigatable();
		prevAction = getAction(nextPrevPlugin, "Previous Location in History");
		nextAction = getAction(nextPrevPlugin, "Next Location in History");
		ProgramManagerPlugin pmp = env.getPlugin(ProgramManagerPlugin.class);
		undoAction = getAction(pmp, "Undo");
		redoAction = getAction(pmp, "Redo");
		provider = cb.getProvider();

		builder.dispose();
	}

	@After
	public void tearDown() throws Exception {
		waitForPostedSwingRunnables();
		env.dispose();
	}

	@Test
	public void testPrevious() throws Exception {
		// go to sscanf
		QueryData queryData = new QueryData("sscanf", false);
		goToService.goToQuery(program.getMinAddress(), queryData, null,
			TaskMonitorAdapter.DUMMY_MONITOR);

		assertTrue(plugin.hasPrevious(navigatable));

		assertNotNull(prevAction);
		assertTrue(prevAction.isEnabledForContext(provider.getActionContext(null)));

		ProgramLocation loc = cb.getCurrentLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);
		Function function = program.getFunctionManager().getFunctionAt(loc.getAddress());

		Parameter param0 = function.getParameter(0);
		Reference[] vrefs = program.getReferenceManager().getReferencesTo(param0);
		Address fromAddr = vrefs[0].getFromAddress();
		VariableXRefFieldLocation xrefLoc =
			new VariableXRefFieldLocation(program, param0, fromAddr, 0, 0);

		goToService.goTo(xrefLoc);
		assertTrue(plugin.hasPrevious(navigatable));
		assertEquals(xrefLoc, cb.getCurrentLocation());

		performAction(prevAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(loc, cb.getCurrentLocation());
		assertTrue(prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(nextAction.isEnabledForContext(provider.getActionContext(null)));

		performAction(prevAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(program.getMinAddress(), cb.getCurrentAddress());
		assertTrue(!prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(nextAction.isEnabledForContext(provider.getActionContext(null)));
	}

	@Test
	public void testNext() throws Exception {
		QueryData queryData = new QueryData("sscanf", false);
		goToService.goToQuery(program.getMinAddress(), queryData, null,
			TaskMonitorAdapter.DUMMY_MONITOR);

		assertTrue(plugin.hasPrevious(navigatable));

		assertNotNull(prevAction);
		assertTrue(prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(!nextAction.isEnabledForContext(provider.getActionContext(null)));

		ProgramLocation loc = cb.getCurrentLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);
		Function function = program.getFunctionManager().getFunctionAt(loc.getAddress());

		Parameter param0 = function.getParameter(0);
		Reference[] vrefs = program.getReferenceManager().getReferencesTo(param0);
		Address fromAddr = vrefs[0].getFromAddress();
		VariableXRefFieldLocation xrefLoc =
			new VariableXRefFieldLocation(program, param0, fromAddr, 0, 0);

		goToService.goTo(xrefLoc);
		assertTrue(plugin.hasPrevious(navigatable));
		assertEquals(xrefLoc, cb.getCurrentLocation());

		OperandFieldLocation opLoc = new OperandFieldLocation(program, getAddr(0x01004176),
			(VariableOffset) null, getAddr(0x01004192), "LAB_01004192", 0, 0, 2);
		goToService.goTo(opLoc);
		assertTrue(plugin.hasPrevious(navigatable));

		OperandFieldLocation opLoc2 = new OperandFieldLocation(program, getAddr(0x0100419a),
			(VariableOffset) null, getAddr(0x010041a1), "LAB_010041a1", 0, 0, 0);
		goToService.goTo(opLoc2);

		ProgramLocation[] locations = new ProgramLocation[] { loc, xrefLoc, opLoc, opLoc2 };

		assertTrue(plugin.hasPrevious(navigatable));
		assertEquals(opLoc2, cb.getCurrentLocation());

		performAction(prevAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(opLoc, cb.getCurrentLocation());

		performAction(prevAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(xrefLoc, cb.getCurrentLocation());

		performAction(prevAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(loc, cb.getCurrentLocation());

		assertTrue(prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(nextAction.isEnabledForContext(provider.getActionContext(null)));

		performAction(prevAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(program.getMinAddress(), cb.getCurrentAddress());
		assertTrue(!prevAction.isEnabledForContext(provider.getActionContext(null)));

		performAction(nextAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(loc, cb.getCurrentLocation());

		performAction(nextAction, provider, true);
		cb.updateNow();
		waitForPostedSwingRunnables();
		assertEquals(xrefLoc, cb.getCurrentLocation());

		assertTrue(prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(nextAction.isEnabledForContext(provider.getActionContext(null)));

		performAction(prevAction, provider, true);
		performAction(prevAction, provider, true);
		assertTrue(!prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(nextAction.isEnabledForContext(provider.getActionContext(null)));

		for (ProgramLocation element : locations) {
			performAction(nextAction, provider, true);
			cb.updateNow();
			waitForPostedSwingRunnables();
			assertEquals(element, cb.getCurrentLocation());
		}
		assertTrue(!nextAction.isEnabledForContext(provider.getActionContext(null)));
	}

	@Test
	public void testNavigationInCodeBrowser() throws Exception {
		QueryData queryData = new QueryData("sscanf", false);

		goToService.goToQuery(program.getMinAddress(), queryData, null,
			TaskMonitorAdapter.DUMMY_MONITOR);

		ProgramLocation loc = cb.getCurrentLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);

		assertTrue(cb.goToField(loc.getAddress(), VariableXRefFieldFactory.FIELD_NAME, 0, 0));
		click(cb, 2);

		assertTrue(cb.goToField(getAddr(0x1004176), OperandFieldFactory.FIELD_NAME, 0, 0));
		click(cb, 2);

		assertTrue(cb.goToField(getAddr(0x1004194), OperandFieldFactory.FIELD_NAME, 0, 0));
		click(cb, 2);

		performAction(prevAction, provider, true);
		cb.updateNow();
		assertEquals(cb.getCurrentAddress(), getAddr(0x01004194));
		assertTrue(cb.getCurrentLocation() instanceof OperandFieldLocation);

		performAction(prevAction, provider, true);
		cb.updateNow();
		assertEquals(cb.getCurrentAddress(), getAddr(0x01004192));
		assertTrue(cb.getCurrentLocation() instanceof LabelFieldLocation);

		performAction(prevAction, provider, true);
		cb.updateNow();
		assertEquals(cb.getCurrentAddress(), getAddr(0x01004176));
		assertTrue(cb.getCurrentLocation() instanceof OperandFieldLocation);

		performAction(prevAction, provider, true);
		cb.updateNow();
		assertEquals(cb.getCurrentAddress(), getAddr(0x0100416c));
		assertTrue(cb.getCurrentLocation() instanceof AddressFieldLocation);

		performAction(prevAction, provider, true);
		cb.updateNow();
		assertTrue(cb.getCurrentLocation() instanceof VariableXRefFieldLocation);

		performAction(prevAction, provider, true);
		cb.updateNow();
		assertTrue(cb.getCurrentLocation() instanceof FunctionReturnTypeFieldLocation);

		performAction(prevAction, provider, true);
		assertEquals(program.getMinAddress(), cb.getCurrentAddress());
	}

	@Test
	public void testClearHistory() throws Exception {
		DockingActionIf clearAction = getAction(nextPrevPlugin, "Clear History Buffer");

		QueryData queryData = new QueryData("sscanf", false);
		goToService.goToQuery(program.getMinAddress(), queryData, null,
			TaskMonitorAdapter.DUMMY_MONITOR);

		ProgramLocation loc = cb.getCurrentLocation();

		assertTrue(cb.goToField(loc.getAddress(), VariableXRefFieldFactory.FIELD_NAME, 0, 0));
		click(cb, 2);

		assertTrue(cb.goToField(getAddr(0x1004176), OperandFieldFactory.FIELD_NAME, 0, 0));
		click(cb, 2);

		assertTrue(cb.goToField(getAddr(0x1004194), OperandFieldFactory.FIELD_NAME, 0, 0));
		click(cb, 2);

		performAction(clearAction, provider, true);
		assertTrue(!plugin.hasNext(navigatable));
		assertTrue(!plugin.hasPrevious(navigatable));
	}

	@Test
	public void testSaveToolHistoryState() throws Exception {
		ProgramLocation initialLoc = cb.getCurrentLocation();

		QueryData queryData = new QueryData("sscanf", false);
		goToService.goToQuery(program.getMinAddress(), queryData, null,
			TaskMonitorAdapter.DUMMY_MONITOR);

		assertTrue(plugin.hasPrevious(navigatable));

		assertNotNull(prevAction);
		assertTrue(prevAction.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(!nextAction.isEnabledForContext(provider.getActionContext(null)));

		ProgramLocation loc = cb.getCurrentLocation();
		assertTrue(loc instanceof FunctionSignatureFieldLocation);
		Function function = program.getFunctionManager().getFunctionAt(loc.getAddress());

		Parameter param0 = function.getParameter(0);
		Reference[] vrefs = program.getReferenceManager().getReferencesTo(param0);
		Address fromAddr = vrefs[0].getFromAddress();
		VariableXRefFieldLocation xrefLoc =
			new VariableXRefFieldLocation(program, param0, fromAddr, 0, 0);

		goToService.goTo(xrefLoc);
		assertTrue(plugin.hasPrevious(navigatable));
		assertEquals(xrefLoc, cb.getCurrentLocation());

		OperandFieldLocation opLoc = new OperandFieldLocation(program, getAddr(0x01004176),
			(int[]) null, getAddr(0x01004192), "LAB_01004192", 0, 0, 2);
		goToService.goTo(opLoc);
		assertTrue(plugin.hasPrevious(navigatable));

		OperandFieldLocation opLoc2 = new OperandFieldLocation(program, getAddr(0x0100419a),
			(int[]) null, getAddr(0x010041a1), "LAB_010041a1", 0, 0, 0);
		goToService.goTo(opLoc2);

		ProgramLocation[] locations = new ProgramLocation[] { initialLoc, loc, xrefLoc, opLoc };

		SaveState ss = new SaveState("test");
		plugin.writeDataState(ss);

		plugin.readDataState(ss);

		assertTrue(plugin.hasPrevious(navigatable));

		for (int i = locations.length - 1; i >= 0; i--) {
			performAction(prevAction, provider, true);
			cb.updateNow();
			waitForPostedSwingRunnables();
			assertEquals(locations[i], cb.getCurrentLocation());
		}
		assertTrue(!prevAction.isEnabledForContext(provider.getActionContext(null)));
	}

	@Test
	public void testMaxHistorySize() {

		int count = 0;
		SymbolIterator iter = program.getSymbolTable().getAllSymbols(true);
		Address currentAddr = program.getMinAddress();
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			if (symbol.isExternal()) {
				continue;// avoid the 'create association' dialog
			}

			++count;

			goToService.goTo(currentAddr, symbol.getAddress());
			cb.updateNow();
			currentAddr = symbol.getAddress();
			if (count > NavigationHistoryPlugin.MAX_HISTORY_SIZE) {
				for (int i = 0; i < NavigationHistoryPlugin.MAX_HISTORY_SIZE - 1; i++) {
					assertTrue(plugin.hasPrevious(navigatable));
					plugin.previous(navigatable);
					cb.updateNow();
				}
				assertTrue(!plugin.hasPrevious(navigatable));
				break;
			}
		}

	}

	@Test
	public void testMaxHistoryToSave() {

		int count = 0;
		SymbolIterator iter = program.getSymbolTable().getAllSymbols(true);
		Address currentAddr = program.getMinAddress();
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			if (symbol.isExternal()) {
				continue;// avoid the 'create association' dialog
			}

			++count;
			goToService.goTo(currentAddr, symbol.getAddress());
			cb.updateNow();
			currentAddr = symbol.getAddress();
			if (count > 2 * NavigationHistoryPlugin.MAX_HISTORY_SIZE) {
				break;
			}
		}
		SaveState ss = new SaveState("test");
		plugin.writeDataState(ss);

		plugin.clear(navigatable);

		plugin.readDataState(ss);
		plugin.dataStateRestoreCompleted();

		for (int i = 0; i < NavigationHistoryPlugin.MAX_HISTORY_SIZE - 1; i++) {
			assertTrue(plugin.hasPrevious(navigatable));
			plugin.previous(navigatable);
			cb.updateNow();
		}
		assertTrue(!plugin.hasPrevious(navigatable));
	}

	@Test
	public void testNextAfterUndoRedo() throws Exception {
		//
		// Note: the addresses used here are arbitrary, except that there is an undefined are 
		//       we can use to create data
		//

		Address addr = getAddr(0x01001010);
		goToService.goTo(addr);

		// Create a data to later delete
		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		int id = program.startTransaction("TEST");
		cmd.applyTo(program);
		program.endTransaction(id, true);
		cb.updateNow();

		// move the cursor
		Address addr2 = getAddr(0x01001020);
		goToService.goTo(addr2);

		// do the undo (must use the action as its the one that updates nav history)
		performAction(undoAction, provider, true);
		cb.updateNow();

		// verify the address went back to spot where data was created.
		ProgramLocation loc = cb.getCurrentLocation();
		assertEquals(addr, loc.getAddress());

		// do the next action and make sure it went to 1001020, which is 
		// where we were before the undo
		performAction(prevAction, provider, true);
		cb.updateNow();
		loc = cb.getCurrentLocation();
		assertEquals(addr2, loc.getAddress());

		// now go to a new location to test redo
		Address addr3 = getAddr(0x1001030);
		goToService.goTo(addr3);

		// do the redo and verify we are back to 1001020,  which is 
		// where we were when we did the undo
		performAction(redoAction, provider, true);
		cb.updateNow();
		loc = cb.getCurrentLocation();
		assertEquals(addr2, loc.getAddress());

		// now check that the previous history has the location we were at when we did redo
		performAction(prevAction, provider, true);
		cb.updateNow();
		loc = cb.getCurrentLocation();
		assertEquals(addr3, loc.getAddress());

	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

}
