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

import static org.junit.Assert.assertNotNull;

import java.awt.Window;
import java.util.Date;
import java.util.Set;

import javax.swing.JPanel;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.dialogs.TableChooserDialog;
import docking.widgets.table.GFilterTable;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.functionwindow.FunctionRowObject;
import ghidra.app.plugin.core.functionwindow.FunctionTableModel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the {@link FunctionComparisonPlugin function comparison plugin} 
 * that involve the GUI
 */
public class CompareFunctionsTestSlow extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program1;
	private Program program2;
	private Function foo;
	private Function bar;
	private Function bat;
	private FunctionComparisonPlugin plugin;
	private FunctionComparisonProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		plugin = env.addPlugin(FunctionComparisonPlugin.class);
		assertNotNull(plugin);
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
		provider = plugin.compareFunctions(functions);
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		plugin.removeFunction(foo, provider);
		assert (!provider.isVisible());
	}

	@Test
	public void testCloseProgram() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = plugin.compareFunctions(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, foo, foo, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, foo, bar);

		plugin.programClosed(program1);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, bar);
		CompareFunctionsTestUtility.checkTargetFunctions(provider, bar, bar);

		plugin.programClosed(program2);

		CompareFunctionsTestUtility.checkSourceFunctions(provider);
	}

	@Test
	public void testNextPreviousAction() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = plugin.compareFunctions(functions);
		provider.setVisible(true);

		waitForSwing();

		// Must do this or there will be no "active" provider in the actions
		// initiated below
		clickComponentProvider(provider);

		DockingActionIf nextAction = getAction(plugin, "Compare Next Function");
		DockingActionIf prevAction = getAction(plugin, "Compare Previous Function");

		assert (nextAction.isEnabled());
		assert (!prevAction.isEnabled());
		performAction(nextAction);
		assert (!nextAction.isEnabled());
		assert (prevAction.isEnabled());
	}

	@Test
	public void testNextPreviousActionSwitchPanelFocus() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = plugin.compareFunctions(functions);
		provider.setVisible(true);

		waitForSwing();

		// Must do this or there will be no "active" provider in the actions
		// initiated below
		clickComponentProvider(provider);

		DockingActionIf nextAction = getAction(plugin, "Compare Next Function");
		DockingActionIf prevAction = getAction(plugin, "Compare Previous Function");

		assert (nextAction.isEnabled());
		assert (!prevAction.isEnabled());
		performAction(nextAction);
		assert (!nextAction.isEnabled());
		assert (prevAction.isEnabled());

		JPanel rightPanel =
			provider.getComponent().getDualListingPanel().getRightPanel().getFieldPanel();
		clickMouse(rightPanel, 1, 30, 30, 1, 0);
		waitForSwing();
		provider.getComponent().updateActionEnablement();

		assert (nextAction.isEnabled());
		assert (!prevAction.isEnabled());
	}

	@Test
	public void testOpenFunctionTableActionForAdd() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo, bar);
		provider = plugin.compareFunctions(functions);
		provider.setVisible(true);

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction);

		Window selectWindow = waitForWindowByTitleContaining("Select Functions");
		assert (selectWindow != null);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testAddFunctionToExistingCompare() {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(foo);
		provider = plugin.compareFunctions(functions);
		provider.setVisible(true);

		waitForSwing();

		// Must do this or there will be no "active" provider in the actions
		// initiated below
		clickComponentProvider(provider);

		assert (provider.getModel().getSourceFunctions().size() == 1);

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction);

		TableChooserDialog<FunctionTableModel> chooser =
			waitForDialogComponent(TableChooserDialog.class);
		assert (chooser != null);

		GFilterTable<FunctionRowObject> table =
			(GFilterTable<FunctionRowObject>) getInstanceField("gFilterTable", chooser);
		assert (table.getModel().getRowCount() == 2);
		clickTableCell(table.getTable(), 1, 0, 1);

		pressButtonByText(chooser, "OK");
		waitForSwing();
		assert (provider.getModel().getSourceFunctions().size() == 2);
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
		bat = builder.createEmptyFunction("Bar", "100299e", 130, null, p, p, p);

		program1 = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program1, Boolean.TRUE);
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
		AbstractGenericTest.setInstanceField("recordChanges", program2, Boolean.TRUE);
		return builder;
	}
}
