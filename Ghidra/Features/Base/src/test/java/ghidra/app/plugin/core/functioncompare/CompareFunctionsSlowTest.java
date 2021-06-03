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
package ghidra.app.plugin.core.functioncompare;

import static org.junit.Assert.*;

import java.awt.Window;
import java.util.Date;
import java.util.Set;

import javax.swing.JPanel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.TableChooserDialog;
import docking.widgets.table.GFilterTable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.functionwindow.FunctionRowObject;
import ghidra.app.plugin.core.functionwindow.FunctionTableModel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the {@link FunctionComparisonPlugin function comparison plugin} 
 * that involve the GUI
 */
public class CompareFunctionsSlowTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program1;
	private Program program2;
	private Function foo;
	private Function bar;
	private Function bat;
	private FunctionComparisonPlugin plugin;
	private FunctionComparisonProvider provider;
	private FunctionPlugin functionPlugin;
	private CodeBrowserPlugin cbPlugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		plugin = env.addPlugin(FunctionComparisonPlugin.class);
		functionPlugin = env.addPlugin(FunctionPlugin.class);
		cbPlugin = env.addPlugin(CodeBrowserPlugin.class);
		buildTestProgram1();
		buildTestProgram2();
		showTool(plugin.getTool());
		env.open(program1);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testRemoveLastItem() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo);
		provider = compareFunctions(functions);
		runSwing(() -> plugin.removeFunction(foo, provider));
		assertFalse(provider.isVisible());
	}

	@Test
	public void testCloseProgram() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compareFunctions(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);

		runSwing(() -> plugin.programClosed(program1));

		CompareFunctionsTestUtility.checkSourceFunctions(provider, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, bar);

		runSwing(() -> plugin.programClosed(program2));

		CompareFunctionsTestUtility.checkSourceFunctions(provider);
	}

	@Test
	public void testNextPreviousAction() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compareFunctions(functions);

		// Must do this or there will be no "active" provider in the actions
		// initiated below
		clickComponentProvider(provider);

		DockingActionIf nextAction = getAction(plugin, "Compare Next Function");
		DockingActionIf prevAction = getAction(plugin, "Compare Previous Function");

		ActionContext context = provider.getActionContext(null);
		assertTrue(nextAction.isEnabledForContext(context));
		assertFalse(prevAction.isEnabledForContext(context));

		performAction(nextAction);

		context = provider.getActionContext(null);
		assertFalse(nextAction.isEnabledForContext(context));
		assertTrue(prevAction.isEnabledForContext(context));
	}

	@Test
	public void testNextPreviousActionSwitchPanelFocus() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compareFunctions(functions);

		// Must do this or there will be no "active" provider in the actions
		// initiated below
		clickComponentProvider(provider);

		DockingActionIf nextAction = getAction(plugin, "Compare Next Function");
		DockingActionIf prevAction = getAction(plugin, "Compare Previous Function");

		ActionContext context = provider.getActionContext(null);
		assertTrue(nextAction.isEnabledForContext(context));
		assertFalse(prevAction.isEnabledForContext(context));

		performAction(nextAction);

		context = provider.getActionContext(null);
		assertFalse(nextAction.isEnabledForContext(context));
		assertTrue(prevAction.isEnabledForContext(context));

		JPanel rightPanel =
			provider.getComponent().getDualListingPanel().getRightPanel().getFieldPanel();
		clickMouse(rightPanel, 1, 30, 30, 1, 0);
		waitForSwing();
		provider.getComponent().updateActionEnablement();

		context = provider.getActionContext(null);
		assertTrue(nextAction.isEnabledForContext(context));
		assertFalse(prevAction.isEnabledForContext(context));
	}

	@Test
	public void testOpenFunctionTableActionForAdd() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compareFunctions(functions);

		// Must do this or the context for the action initiated below will be
		// for the listing, not the comparison provider
		clickComponentProvider(provider);

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction, false);

		Window selectWindow = waitForWindowByTitleContaining("Select Functions");
		assertNotNull(selectWindow);
		selectWindow.setVisible(false);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testAddFunctionToExistingCompare() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo);
		provider = compareFunctions(functions);

		// Must do this or there will be no "active" provider in the actions
		// initiated below
		clickComponentProvider(provider);

		assertEquals(provider.getModel().getSourceFunctions().size(), 1);
		assertTrue(provider.getModel().getSourceFunctions().contains(foo));

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction, false);

		TableChooserDialog<FunctionTableModel> chooser =
			waitForDialogComponent(TableChooserDialog.class);
		GFilterTable<FunctionRowObject> table =
			(GFilterTable<FunctionRowObject>) getInstanceField("gFilterTable", chooser);
		assertEquals(table.getModel().getRowCount(), 2);
		clickTableCell(table.getTable(), 1, 0, 1);

		pressButtonByText(chooser, "OK");
		waitForSwing();
		assertEquals(provider.getModel().getSourceFunctions().size(), 2);
		assertTrue(provider.getModel().getSourceFunctions().contains(foo));
		assertTrue(provider.getModel().getSourceFunctions().contains(bat));
	}

	/**
	 * Verifies that if we delete a function from the listing that is currently
	 * being shown in a comparison provider, it will be removed from that
	 * comparison provider
	 */
	@Test
	public void testDeleteFunctionFromListing() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = compareFunctions(functions);

		assertEquals(provider.getModel().getSourceFunctions().size(), 2);
		assertTrue(provider.getModel().getSourceFunctions().contains(foo));
		assertTrue(provider.getModel().getSourceFunctions().contains(bar));

		Address addr = program1.getAddressFactory().getAddress("10018cf");
		ProgramLocation loc = new ProgramLocation(program1, addr);
		cbPlugin.goTo(loc);
		DockingActionIf deleteAction = getAction(functionPlugin, "Delete Function");
		performAction(deleteAction, cbPlugin.getProvider().getActionContext(null), true);
		waitForSwing();

		assertEquals(provider.getModel().getSourceFunctions().size(), 1);
		assertTrue(provider.getModel().getSourceFunctions().contains(bar));
	}

	private FunctionComparisonProvider compareFunctions(Set<Function> functions) {
		provider = runSwing(() -> plugin.compareFunctions(functions));
		provider.setVisible(true);
		waitForSwing();
		return provider;
	}

	/**
	 * Builds a program with 2 functions
	 */
	private ProgramBuilder buildTestProgram1() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestPgm1", ProgramBuilder._TOY_BE);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		foo = builder.createEmptyFunction("Foo", "10018cf", 10, null, p);
		bat = builder.createEmptyFunction("Bat", "100299e", 130, null, p, p, p);

		program1 = builder.getProgram();
		return builder;
	}

	/**
	 * Builds a program with 1 function
	 */
	private ProgramBuilder buildTestProgram2() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestPgm1", ProgramBuilder._TOY_BE);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		bar = builder.createEmptyFunction("Bar", "10018cf", 10, null, p);

		program2 = builder.getProgram();
		return builder;
	}
}
