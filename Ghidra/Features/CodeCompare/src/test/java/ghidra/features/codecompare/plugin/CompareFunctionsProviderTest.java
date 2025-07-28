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
package ghidra.features.codecompare.plugin;

import static ghidra.util.datastruct.Duo.Side.*;
import static org.junit.Assert.*;

import java.awt.Window;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JComboBox;
import javax.swing.JPanel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.TableSelectionDialog;
import docking.widgets.table.GFilterTable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.features.base.codecompare.model.FunctionComparisonModel;
import ghidra.features.base.codecompare.model.MatchedFunctionComparisonModel;
import ghidra.features.base.codecompare.panel.CodeComparisonPanel;
import ghidra.features.base.codecompare.panel.FunctionComparisonPanel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.datastruct.Duo.Side;

/**
 * Tests for the {@link FunctionComparisonPlugin function comparison plugin}
 * that involve the GUI
 */
public class CompareFunctionsProviderTest extends AbstractGhidraHeadedIntegrationTest {

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
		provider = compareFunctions(Set.of(foo));
		assertTrue(provider.isVisible());
		plugin.removeFunction(foo);
		waitForSwing();
		assertFalse(provider.isVisible());
	}

	@Test
	public void testCloseProgram() throws Exception {
		Set<Function> functions = Set.of(foo, bar);
		provider = compareFunctions(functions);

		checkFunctions(LEFT, foo, foo, bar);
		checkFunctions(RIGHT, bar, foo, bar);

		runSwing(() -> plugin.programClosed(program1));
		waitForSwing();

		checkFunctions(LEFT, bar, bar);
		checkFunctions(RIGHT, bar, bar);

		runSwing(() -> plugin.programClosed(program2));
		waitForSwing();
		assertFalse(provider.isVisible());
		assertFalse(provider.isInTool());
	}

	@Test
	public void testNextPreviousAction() {
		Set<Function> functions = Set.of(foo, bar);
		provider = compareFunctions(functions);

		DockingActionIf nextAction = getAction(plugin, "Compare Next Function");
		DockingActionIf previousAction = getAction(plugin, "Compare Previous Function");

		ActionContext context = provider.getActionContext(null);
		assertEnabled(nextAction, context);
		assertNotEnabled(previousAction, context);

		performAction(nextAction);

		context = provider.getActionContext(null);
		assertNotEnabled(nextAction, context);
		assertEnabled(previousAction, context);
	}

	@Test
	public void testNextPreviousActionSwitchPanelFocus() throws Exception {
		Set<Function> functions = Set.of(foo, bar);
		provider = compareFunctions(functions);
		DockingActionIf nextAction = getAction(plugin, "Compare Next Function");
		DockingActionIf previousAction = getAction(plugin, "Compare Previous Function");

		// since we are clicking the listing panel, bring that to the front first
		setActivePanel(provider, provider.getComponent().getDualListingPanel());

		// left panel has focus, so nextAction should be enabled and previous should be disabled
		ActionContext context = provider.getActionContext(null);
		assertEnabled(nextAction, context);
		assertNotEnabled(previousAction, context);

		JPanel rightPanel =
			provider.getComponent().getDualListingPanel().getListingPanel(RIGHT).getFieldPanel();
		clickMouse(rightPanel, 1, 30, 30, 1, 0);
		waitForSwing();
		provider.getComponent().updateActionEnablement();

		// right panel has focus, so nextAction should be disabled and previous should be enabled
		context = provider.getActionContext(null);
		assertNotEnabled(nextAction, context);
		assertEnabled(previousAction, context);
	}

	@Test
	public void testOpenFunctionTableActionForAdd() {
		Set<Function> functions = Set.of(foo, bar);
		provider = compareFunctions(functions);

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction, provider, false);

		Window selectWindow = waitForWindowByTitleContaining("Select Functions");
		assertNotNull(selectWindow);
		selectWindow.setVisible(false);
	}

	@Test
	public void testAddFunctionToExistingCompare() {
		Set<Function> functions = Set.of(foo);
		provider = compareFunctions(functions);

		assertEquals(provider.getModel().getFunctions(LEFT).size(), 1);
		assertTrue(provider.getModel().getFunctions(LEFT).contains(foo));

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction, provider, false);

		TableSelectionDialog<?> chooser =
			waitForDialogComponent(TableSelectionDialog.class);

		GFilterTable<?> table = (GFilterTable<?>) getInstanceField("gFilterTable", chooser);

		waitForCondition(() -> table.getModel().getRowCount() == 2);
		clickTableCell(table.getTable(), 1, 0, 1);

		pressButtonByText(chooser, "OK");
		waitForSwing();
		assertEquals(provider.getModel().getFunctions(LEFT).size(), 2);
		assertTrue(provider.getModel().getFunctions(LEFT).contains(foo));
		assertTrue(provider.getModel().getFunctions(LEFT).contains(bat));
	}

	/**
	 * Verifies that if we delete a function from the listing that is currently
	 * being shown in a comparison provider, it will be removed from that
	 * comparison provider
	 */
	@Test
	public void testDeleteFunctionFromListing() {
		Set<Function> functions = Set.of(foo, bar);
		provider = compareFunctions(functions);

		assertEquals(provider.getModel().getFunctions(LEFT).size(), 2);
		assertTrue(provider.getModel().getFunctions(LEFT).contains(foo));
		assertTrue(provider.getModel().getFunctions(LEFT).contains(bar));

		Address address = program1.getAddressFactory().getAddress("10018cf");
		ProgramLocation loc = new ProgramLocation(program1, address);
		cbPlugin.goTo(loc);
		DockingActionIf deleteAction = getAction(functionPlugin, "Delete Function");
		performAction(deleteAction, cbPlugin.getProvider().getActionContext(null), true);
		waitForSwing();

		assertEquals(provider.getModel().getFunctions(LEFT).size(), 1);
		assertTrue(provider.getModel().getFunctions(LEFT).contains(bar));
	}

	@Test
	public void testCustomComparison() {
		MatchedFunctionComparisonModel model = new MatchedFunctionComparisonModel();
		model.addMatch(foo, bar);
		model.addMatch(bar, bat);
		plugin.createCustomComparison(model, null);
		waitForSwing();
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		assertEquals(model, provider.getModel());

		setLeftFunction(foo);

		assertEquals(model.getFunctions(LEFT).size(), 2);
		assertTrue(model.getFunctions(LEFT).contains(foo));
		assertTrue(model.getFunctions(LEFT).contains(bar));
		assertEquals(model.getFunctions(RIGHT).size(), 1);
		assertTrue(model.getFunctions(RIGHT).contains(bar));

		setLeftFunction(bar);

		assertEquals(model.getFunctions(RIGHT).size(), 1);
		assertTrue(model.getFunctions(RIGHT).contains(bat));
	}

	private void setLeftFunction(Function function) {
		FunctionComparisonPanel component = provider.getComponent();
		JComboBox<?> combo = (JComboBox<?>) findComponentByName(component, "LEFTFunctionComboBox");
		runSwing(() -> combo.setSelectedItem(function));
	}

	@Test
	public void testCustomComparitorCloseCallack() {
		final AtomicBoolean closed = new AtomicBoolean(false);
		MatchedFunctionComparisonModel model = new MatchedFunctionComparisonModel();
		model.addMatch(foo, bar);
		model.addMatch(bar, bat);
		plugin.createCustomComparison(model, () -> closed.set(true));
		waitForSwing();
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		assertEquals(model, provider.getModel());

		assertFalse(closed.get());
		runSwing(() -> provider.closeComponent());
		waitForSwing();
		assertTrue(closed.get());

	}

	@Test
	public void testAddToComparison() {
		Set<Function> functions = Set.of(foo, bar);
		provider = compareFunctions(functions);

		checkFunctions(LEFT, foo, foo, bar);
		checkFunctions(RIGHT, bar, foo, bar);

		runSwing(() -> plugin.addToComparison(bat));
		waitForSwing();

		checkFunctions(LEFT, foo, foo, bar, bat);
		checkFunctions(RIGHT, bat, foo, bar, bat);
	}

	private void assertEnabled(DockingActionIf action, ActionContext context) {
		assertTrue(runSwing(() -> action.isEnabledForContext(context)));
	}

	private void assertNotEnabled(DockingActionIf action, ActionContext context) {
		assertFalse(runSwing(() -> action.isEnabledForContext(context)));
	}

	private void setActivePanel(FunctionComparisonProvider provider, CodeComparisonPanel panel) {
		runSwing(() -> provider.getComponent().setCurrentTabbedComponent(panel.getName()));
		waitForSwing();
	}

	private FunctionComparisonProvider compareFunctions(Set<Function> functions) {
		runSwing(() -> plugin.createComparison(functions));
		waitForSwing();
		return waitForComponentProvider(FunctionComparisonProvider.class);
	}

	/**
	 * Builds a program with 2 functions
	 */
	private ProgramBuilder buildTestProgram1() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Program 1", ProgramBuilder._TOY_BE);
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

	private void checkFunctions(Side side, Function activeFunction, Function... functions) {
		Set<Function> funcs = Set.of(functions);

		FunctionComparisonModel model = provider.getModel();
		assertEquals(activeFunction, model.getActiveFunction(side));

		List<Function> fcs = model.getFunctions(side);
		assertEquals(fcs.size(), funcs.size());
		assertTrue(fcs.containsAll(funcs));
	}

	/**
	 * Builds a program with 1 function
	 */
	private ProgramBuilder buildTestProgram2() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Program 2", ProgramBuilder._TOY_BE);
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
