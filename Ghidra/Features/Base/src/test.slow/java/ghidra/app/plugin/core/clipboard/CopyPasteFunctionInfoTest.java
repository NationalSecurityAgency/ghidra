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
package ghidra.app.plugin.core.clipboard;

import static org.junit.Assert.*;

import java.awt.Point;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.cmd.function.SetVariableCommentCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

/**
 * Test copy/paste function information
 */
public class CopyPasteFunctionInfoTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool toolOne;
	private PluginTool toolTwo;
	private Program programOne;
	private Program programTwo;
	private ProgramManager pmOne;
	private ProgramManager pmTwo;
	private FieldPanel fieldPanel1;
	private FieldPanel fieldPanel2;
	private Options fieldOptions2;
	private CodeBrowserPlugin cb1;

	private Program buildNotepad(String name) throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder(name, true, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x01001000", 0x8000);
		builder.createEntryPoint("0x1006420", "entry");
		DataType dt = DataType.DEFAULT;
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction("ghidra", "0x1004600", 1, dt, p, p, p, p, p, p, p, p, p, p, p,
			p, p);
		return builder.getProgram();
	}

	private Program buildTaskman(String name) throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder(name, true, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x01001000", 0x8000);
		builder.createFunction("0x1006420");
		builder.createEntryPoint("0x1006420", "entry");
		builder.createFunction("0x1004700");
		builder.createComment("0x1006420", "FUNCTION", CodeUnit.PLATE_COMMENT);
		DataType dt = DataType.DEFAULT;
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction("BOB", "0x1004260", 1, dt, p, p, p, p, p, p, p, p, p, p, p, p,
			p);
		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		toolOne = env.getTool();
		setupTool(toolOne);
		cb1 = getPlugin(toolOne, CodeBrowserPlugin.class);
		fieldPanel1 = cb1.getFieldPanel();
		env.showTool();

		toolTwo = env.launchAnotherDefaultTool();
		setupTool(toolTwo);
		CodeBrowserPlugin cb2 = getPlugin(toolTwo, CodeBrowserPlugin.class);
		fieldPanel2 = cb2.getFieldPanel();
		fieldOptions2 = cb2.getFormatManager().getFieldOptions();

		programOne = buildNotepad("notepad");
		programTwo = buildTaskman("taskman");

		pmOne = toolOne.getService(ProgramManager.class);
		SwingUtilities.invokeAndWait(() -> pmOne.openProgram(programOne.getDomainFile()));

		pmTwo = toolTwo.getService(ProgramManager.class);
		SwingUtilities.invokeAndWait(() -> pmTwo.openProgram(programTwo.getDomainFile()));
		// create function at "entry" (taskman has been analyzed)
		setupNotepad();
		resetOptions();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private void click1() {
		Point p = fieldPanel1.getCursorPoint();
		clickMouse(fieldPanel1, MouseEvent.BUTTON1, p.x, p.y, 1, 0);
		waitForSwing();
	}

	private void click2() {
		Point p = fieldPanel2.getCursorPoint();
		clickMouse(fieldPanel2, MouseEvent.BUTTON1, p.x, p.y, 1, 0);
		waitForSwing();
	}

	@Test
	public void testPasteFunctionName() throws Exception {

		// in notepad (Browser(1)) copy ghidra function to
		// taskman (Browser(2) at address 1004700
		Symbol symbol = getUniqueSymbol(programOne, "ghidra");
		Address addr = symbol.getAddress();
		goToAddr(toolOne, addr);
		click1();
		toolOne.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(addr, addr), programOne));

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getCodeBrowserClipboardContentProviderService(plugin);
		plugin.copySpecial(service, CodeBrowserClipboardProvider.LABELS_COMMENTS_TYPE);

		// go to address 01004700 in Browser(2)
		goToAddr(toolTwo, 0x1004700);
		click2();

		paste(toolTwo);

		// function FUN_01004700 should be renamed to "ghidra"
		CodeBrowserPlugin cb = getPlugin(toolTwo, CodeBrowserPlugin.class);
		cb.goToField(getAddr(programTwo, 0x01004700), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("ghidra", f.getText());

		undo(programTwo);
		cb.goToField(getAddr(programTwo, 0x01004700), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("FUN_01004700", f.getText());

		redo(programTwo);
		cb.goToField(getAddr(programTwo, 0x01004700), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("ghidra", f.getText());
	}

	@Test
	public void testPasteFunctionComment() throws Exception {

		// in Browser(1) select the entry address
		Address addr = getAddr(programOne, 0x01006420);
		goToAddr(toolOne, addr);
		click1();
		toolOne.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(addr, addr), programOne));

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getCodeBrowserClipboardContentProviderService(plugin);
		plugin.copySpecial(service, CodeBrowserClipboardProvider.LABELS_COMMENTS_TYPE);

		// in Browser(2) go to entry in taskman
		Symbol symbol = getUniqueSymbol(programTwo, "entry");
		Address entryAddr = symbol.getAddress();
		goToAddr(toolTwo, entryAddr);
		click2();

		paste(toolTwo);

		CodeBrowserPlugin cb = getPlugin(toolTwo, CodeBrowserPlugin.class);
		cb.goToField(entryAddr, PlateFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(4, f.getNumRows());
		assertTrue(f.getText().indexOf("FUNCTION") > 0);
		assertTrue(f.getText().indexOf("My function comments for entry") > 0);

		undo(programTwo);
		cb.goToField(entryAddr, PlateFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(3, f.getNumRows());
		assertTrue(f.getText().indexOf("FUNCTION") > 0);

		redo(programTwo);
		cb.goToField(entryAddr, PlateFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(4, f.getNumRows());
		assertTrue(f.getText().indexOf("FUNCTION") > 0);
		assertTrue(f.getText().indexOf("My function comments for entry") > 0);

	}

	@Test
	public void testPasteStackVariableComment() throws Exception {

		// create a stack variable comment
		Function func = getFunction("ghidra");
		Address addr = func.getEntryPoint();
		goToAddr(toolOne, addr);
		click1();

		Parameter[] vars = func.getParameters();
		for (Parameter element : vars) {
			String varName = element.getName();
			if (varName.equals("param_7") || varName.equals("param_9")) {
				toolOne.execute(
					new SetVariableCommentCmd(element, "my stack comment for " + varName),
					programOne);

			}
		}
		// select the ghidra address
		toolOne.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(addr, addr), programOne));

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getCodeBrowserClipboardContentProviderService(plugin);
		plugin.copySpecial(service, CodeBrowserClipboardProvider.LABELS_COMMENTS_TYPE);

		// paste at FUN_01004260 in taskman in Browser(2) (need a function that
		// has the same offsets in the stack in order for the comments to be
		// pasted).
		addr = getAddr(programTwo, 0x01004260);
		goToAddr(toolTwo, addr);
		click2();

		paste(toolTwo);

		// verify the code browser field shows the comment
		func = programTwo.getListing().getFunctionAt(addr);
		vars = func.getParameters();
		CodeBrowserPlugin cb = getPlugin(toolTwo, CodeBrowserPlugin.class);

		int occ = 0;
		for (Parameter var : vars) {
			String varName = var.getName();
			if (varName.equals("param_7") || varName.equals("param_9")) {
				assertTrue(cb.goToField(addr, VariableCommentFieldFactory.FIELD_NAME, occ++, 0, 0));
				ListingTextField f = (ListingTextField) cb.getCurrentField();
				assertEquals(var.getComment(), f.getText());
			}
		}
	}

	@Test
	public void testPasteStackVariableName() throws Exception {
		// change  a stack variable name
		Function func = getFunction("ghidra");
		Address addr = func.getEntryPoint();
		goToAddr(toolOne, addr);
		click1();
		Variable[] vars = func.getVariables(VariableFilter.PARAMETER_FILTER);
		for (Variable element : vars) {
			String varName = element.getName();
			if (varName.equals("param_1") || varName.equals("param_3")) {
				toolOne.execute(
					new SetVariableNameCmd(element, "my_" + varName, SourceType.USER_DEFINED),
					programOne);

			}
		}
		// select the ghidra address
		toolOne.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(addr, addr), programOne));

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getCodeBrowserClipboardContentProviderService(plugin);
		plugin.copySpecial(service, CodeBrowserClipboardProvider.LABELS_COMMENTS_TYPE);

		// paste at FUN_01004260 in taskman in Browser(2) (need a function that
		// has the same offsets in the stack in order for the names to be
		// pasted).
		addr = getAddr(programTwo, 0x01004260);
		goToAddr(toolTwo, addr);
		click2();

		paste(toolTwo);

		// verify the code browser field shows the comment
		func = programTwo.getListing().getFunctionAt(addr);
		vars = func.getVariables(VariableFilter.PARAMETER_FILTER);
		CodeBrowserPlugin cb = getPlugin(toolTwo, CodeBrowserPlugin.class);

		for (int i = 0; i < vars.length; i++) {
			String varName = vars[i].getName();
			assertTrue(cb.goToField(addr, VariableNameFieldFactory.FIELD_NAME, i + 1, 0, 0));
			ListingTextField f = (ListingTextField) cb.getCurrentField();
			assertEquals(varName, f.getText());
		}

		undo(programOne);

		func = programTwo.getListing().getFunctionAt(addr);
		vars = func.getVariables(VariableFilter.PARAMETER_FILTER);

		for (int i = 0; i < vars.length; i++) {
			String varName = vars[i].getName();
			assertTrue(cb.goToField(addr, VariableNameFieldFactory.FIELD_NAME, i + 1, 0, 0));
			ListingTextField f = (ListingTextField) cb.getCurrentField();

			assertEquals(varName, f.getText());
		}

		redo(programOne);

		func = programTwo.getListing().getFunctionAt(addr);
		vars = func.getVariables(VariableFilter.PARAMETER_FILTER);

		for (int i = 0; i < vars.length; i++) {
			String varName = vars[i].getName();
			assertTrue(cb.goToField(addr, VariableNameFieldFactory.FIELD_NAME, i + 1, 0, 0));
			ListingTextField f = (ListingTextField) cb.getCurrentField();
			assertEquals(varName, f.getText());
		}

	}

	@Test
	public void testPasteAtNoFunction() {
		// pasting stack info where there is no function should do nothing;
		// label and comments should get pasted
		Function func = getFunction("ghidra");
		Address addr = func.getEntryPoint();
		goToAddr(toolOne, addr);
		click1();

		Parameter[] vars = func.getParameters();
		for (Parameter element : vars) {
			String varName = element.getName();
			if (varName.equals("param_10") || varName.equals("param_18")) {
				toolOne.execute(
					new SetVariableCommentCmd(element, "my stack comment for " + varName),
					programOne);

			}
		}

		toolOne.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(addr, addr), programOne));

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getCodeBrowserClipboardContentProviderService(plugin);
		plugin.copySpecial(service, CodeBrowserClipboardProvider.LABELS_COMMENTS_TYPE);

		// in Browser(2) go to a location where there is no function defined
		goToAddr(toolTwo, 0x0100176f);
		click2();

		paste(toolTwo);

		addr = getAddr(programTwo, 0x0100176f);
		// nothing should happen with the stack variable comments
		CodeBrowserPlugin cb = getPlugin(toolTwo, CodeBrowserPlugin.class);
		assertTrue(!cb.goToField(addr, VariableNameFieldFactory.FIELD_NAME, 0, 0));

		assertTrue(cb.goToField(addr, LabelFieldFactory.FIELD_NAME, 0, 0));
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(1, f.getNumRows());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void paste(PluginTool tool) {

		ClipboardPlugin plugin = getPlugin(tool, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getCodeBrowserClipboardContentProviderService(plugin);
		DockingActionIf pasteAction = getClipboardAction(plugin, service, "Paste");
		assertEnabled(pasteAction);
		performAction(pasteAction, true);
		waitForSwing();
	}

	private DockingActionIf getClipboardAction(ClipboardPlugin plugin,
			ClipboardContentProviderService service, String actionName) {

		@SuppressWarnings("unchecked")
		Map<ClipboardContentProviderService, List<DockingAction>> map =
			(Map<ClipboardContentProviderService, List<DockingAction>>) getInstanceField(
				"serviceActionMap", plugin);
		List<DockingAction> list = map.get(service);
		for (DockingAction pluginAction : list) {
			if (pluginAction.getName().equals(actionName)) {
				return pluginAction;
			}
		}
		return null;
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(ClipboardPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
	}

	private void goToAddr(PluginTool tool, Address addr) {
		Program p = programOne;
		if (tool == toolTwo) {
			p = programTwo;
		}
		tool.firePluginEvent(
			new ProgramLocationPluginEvent("test", new AddressFieldLocation(p, addr), p));

		waitForSwing();
	}

	private void goToAddr(PluginTool tool, long offset) {
		Program p = programOne;
		if (tool == toolTwo) {
			p = programTwo;
		}
		goToAddr(tool, getAddr(p, offset));
	}

	private Address getAddr(Program program, long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private void setupNotepad() {
		// in notepad, (Browser(1)) create a function at entry
		goToAddr(toolOne, 0x01006420);

		Plugin p = getPlugin(toolOne, FunctionPlugin.class);
		DockingActionIf action = getAction(p, "Create Function");
		performAction(action, cb1.getProvider(), true);

		waitForSwing();
		waitForBusyTool(toolOne);

		// change the function comment
		int transactionID = programOne.startTransaction("test");
		try {
			Function func = getFunction("entry");
			func.setComment("My function comments for entry");
		}
		finally {
			programOne.endTransaction(transactionID, true);
		}
	}

	private void resetOptions() {
		List<String> names = fieldOptions2.getOptionNames();
		for (int i = 0; i < names.size(); i++) {
			String name = names.get(i);
			if (!name.startsWith("Format Code")) {
				continue;
			}
			if (name.indexOf("Show ") >= 0 || name.indexOf("Flag ") >= 0) {
				fieldOptions2.setBoolean(name, false);
			}
			else if (name.indexOf("Lines") >= 0) {
				fieldOptions2.setInt(name, 0);
			}
		}
		waitForSwing();
		CodeBrowserPlugin cb = getPlugin(toolTwo, CodeBrowserPlugin.class);
		cb.updateNow();
	}

	private ClipboardContentProviderService getCodeBrowserClipboardContentProviderService(
			ClipboardPlugin clipboardPlugin) {
		Map<?, ?> serviceMap = (Map<?, ?>) getInstanceField("serviceActionMap", clipboardPlugin);
		Set<?> keySet = serviceMap.keySet();
		for (Object service : keySet) {
			if (service.getClass().equals(CodeBrowserClipboardProvider.class)) {
				return (ClipboardContentProviderService) service;
			}
		}
		return null;
	}

	private void assertEnabled(DockingActionIf action) {
		action.isEnabledForContext(cb1.getProvider().getActionContext(null));// required to trigger enablement
		assertTrue(action.isEnabled());
	}

	private Function getFunction(String name) {
		List<Function> functions = programOne.getListing().getGlobalFunctions(name);
		assertEquals(1, functions.size());
		return functions.get(0);
	}
}
