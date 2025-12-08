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
package ghidra.app.plugin.compare;

import static ghidra.util.datastruct.Duo.Side.*;
import static org.junit.Assert.*;

import java.util.*;

import javax.swing.JButton;

import org.junit.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.dialogs.ObjectChooserDialog;
import ghidra.app.plugin.core.functiongraph.SetFormatDialogComponentProvider;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FgEnv;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.format.actions.AddFieldAction;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.features.base.codecompare.model.FunctionComparisonModel;
import ghidra.features.codecompare.functiongraph.FgDisplay;
import ghidra.features.codecompare.functiongraph.FunctionGraphCodeComparisonView;
import ghidra.features.codecompare.plugin.FunctionComparisonPlugin;
import ghidra.features.codecompare.plugin.FunctionComparisonProvider;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.test.*;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

public class CompareFunctionsFunctionGraphViewTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private Function fun1;
	private Function fun2;
	private FunctionComparisonPlugin plugin;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		showTool();
	}

	private void showTool() throws Exception {
		program = buildTestProgram();
		env.launchDefaultTool(program);
		plugin = env.addPlugin(FunctionComparisonPlugin.class);

		FunctionManager functionManager = program.getFunctionManager();
		fun1 = functionManager.getFunctionAt(addr(0x01002cf5));
		fun2 = functionManager.getFunctionAt(addr(0x0100415a));
	}

	private Program buildTestProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder("Test", false);
		return builder.getProgram();
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testFunctionGraphDiffView() throws Exception {

		Set<Function> functions = Set.of(fun1, fun2);
		compareFunctions(functions);

		FunctionComparisonProvider provider =
			waitForComponentProvider(FunctionComparisonProvider.class);

		selectFgPanel(provider);

		checkFunctions(provider, LEFT, fun1, fun1, fun2);
		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);

		waitForFunctionGraph(fgProvider);

		assertEachFunctionIsGraphed(fgProvider, fun1, fun2);
	}

	@Test
	public void testChangeFormat() throws Exception {

		Set<Function> functions = Set.of(fun1, fun2);
		compareFunctions(functions);

		FunctionComparisonProvider provider =
			waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);
		waitForFunctionGraph(fgProvider);

		FormatDescription currentFormat = getFormat(fgProvider);

		FormatDescription newFormat = changeFormat(provider);
		assertNotEquals(currentFormat, newFormat);

		close(provider);
		env.saveRestoreToolState();

		compareFunctions(functions);
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		fgProvider = getFgComparisonProvider(provider);
		FormatDescription restoredFormat = getFormat(fgProvider);
		assertEquals(newFormat, restoredFormat);
	}

	@Test
	public void testChangeShowPopups() {

		Set<Function> functions = Set.of(fun1, fun2);
		compareFunctions(functions);

		FunctionComparisonProvider provider =
			waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);
		waitForFunctionGraph(fgProvider);

		boolean isShowingPopups = isShowingPopups(fgProvider);
		setShowingPopups(provider, !isShowingPopups);

		close(provider);
		env.saveRestoreToolState();

		compareFunctions(functions);
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		fgProvider = getFgComparisonProvider(provider);
		boolean restoredIsShowingPopups = isShowingPopups(fgProvider);
		assertEquals(!isShowingPopups, restoredIsShowingPopups);
	}

	@Test
	public void testChangeLayout() {

		Set<Function> functions = Set.of(fun1, fun2);
		compareFunctions(functions);

		FunctionComparisonProvider provider =
			waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);
		waitForFunctionGraph(fgProvider);

		FGLayoutProvider currentLayout = getLayout(fgProvider);
		FGLayoutProvider newLayout = changeLayout(provider);
		assertNotEquals(currentLayout, newLayout);

		close(provider);
		env.saveRestoreToolState();

		compareFunctions(functions);
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		fgProvider = getFgComparisonProvider(provider);
		FGLayoutProvider updatedLayout = getLayout(fgProvider);
		assertEquals(newLayout.getLayoutName(), updatedLayout.getLayoutName());
	}

	@Test
	public void testHideSatellite() {

		Set<Function> functions = Set.of(fun1, fun2);
		compareFunctions(functions);

		FunctionComparisonProvider provider =
			waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);
		waitForFunctionGraph(fgProvider);

		boolean isShowingSatellite = isShowingSatellite(fgProvider);
		setShowingSatellite(provider, !isShowingSatellite);

		close(provider);
		env.saveRestoreToolState();

		compareFunctions(functions);
		provider = waitForComponentProvider(FunctionComparisonProvider.class);
		selectFgPanel(provider);
		fgProvider = getFgComparisonProvider(provider);
		boolean restoredIsShowingSatellite = isShowingSatellite(fgProvider);
		assertEquals(!isShowingSatellite, restoredIsShowingSatellite);
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void assertEachFunctionIsGraphed(FunctionGraphCodeComparisonView panel,
			Function leftFunction, Function rightFunction) {

		Duo<FgDisplay> displays = panel.getDisplays();
		FgDisplay leftFgDisplay = displays.get(LEFT);
		FgDisplay rightFgDisplay = displays.get(RIGHT);
		FGController leftController = leftFgDisplay.getController();
		FGController rightController = rightFgDisplay.getController();
		assertTrue(leftController.hasResults());
		assertTrue(rightController.hasResults());

		Function leftControllerFunction = leftController.getGraphedFunction();
		assertEquals(leftFunction, leftControllerFunction);

		Function rightControllerFunction = rightController.getGraphedFunction();
		assertEquals(rightFunction, rightControllerFunction);
	}

	private FGLayoutProvider getLayout(FunctionGraphCodeComparisonView panel) {

		Duo<FgDisplay> displays = panel.getDisplays();
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		FGLayoutProvider leftLayout = leftController.getLayoutProvider();

		FgDisplay rightDisplay = displays.get(RIGHT);
		FGController rightController = rightDisplay.getController();
		FGLayoutProvider rightLayout = rightController.getLayoutProvider();
		assertEquals(leftLayout.getLayoutName(), rightLayout.getLayoutName());

		return leftLayout;
	}

	private FGLayoutProvider changeLayout(FunctionComparisonProvider provider) {

		FunctionGraphCodeComparisonView panel = getFgComparisonProvider(provider);
		DockingAction action = getAction(panel, "Relayout Graph");
		performAction(action, provider, false);

		@SuppressWarnings("unchecked")
		ObjectChooserDialog<FGLayoutProvider> dialog =
			waitForDialogComponent(ObjectChooserDialog.class);

		FGLayoutProvider newProvider = getLayout(panel, "Nested Code Layout");
		runSwing(() -> dialog.setSelectedObject(newProvider));

		pressButtonByText(dialog, "OK", true);

		FGLayoutProvider dialogProvider = dialog.getSelectedObject();
		assertEquals(newProvider, dialogProvider);
		return newProvider;
	}

	private FGLayoutProvider getLayout(FunctionGraphCodeComparisonView panel, String name) {
		Duo<FgDisplay> displays = panel.getDisplays();
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		FgEnv leftEnv = leftController.getEnv();
		List<FGLayoutProvider> providers = leftEnv.getLayoutProviders();
		for (FGLayoutProvider provider : providers) {
			String layoutName = provider.getLayoutName();
			if (layoutName.equals(name)) {
				return provider;
			}
		}

		fail("Unable to find graph layout by name: " + name);
		return null;
	}

	private boolean isShowingPopups(FunctionGraphCodeComparisonView fgProvider) {

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		boolean leftVisible = leftController.arePopupsVisible();

		FgDisplay rightDisplay = displays.get(RIGHT);
		FGController rightController = rightDisplay.getController();
		boolean rightVisible = rightController.arePopupsVisible();

		assertEquals(leftVisible, rightVisible);
		return leftVisible;
	}

	private void setShowingPopups(FunctionComparisonProvider provider, boolean shouldBeVisible) {

		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(fgProvider, "Display Popup Windows");
		boolean currentlyVisible = runSwing(() -> action.isSelected());
		if (currentlyVisible != shouldBeVisible) {
			performAction(action, provider, true);
		}
	}

	private boolean isShowingSatellite(FunctionGraphCodeComparisonView fgProvider) {

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		boolean leftShowing = leftController.isSatelliteVisible();

		FgDisplay rightDisplay = displays.get(RIGHT);
		FGController rightController = rightDisplay.getController();
		boolean rightShowing = rightController.isSatelliteVisible();

		assertEquals(leftShowing, rightShowing);
		return leftShowing;
	}

	private void setShowingSatellite(FunctionComparisonProvider provider, boolean shouldBeVisible) {

		FunctionGraphCodeComparisonView panel = getFgComparisonProvider(provider);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(panel, "Display Satellite View");

		boolean currentlyVisible = runSwing(() -> action.isSelected());
		if (currentlyVisible != shouldBeVisible) {
			performAction(action, provider, true);
		}
	}

	private FormatDescription getFormat(FunctionGraphCodeComparisonView fgProvider) {

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		FormatManager leftFormat = leftController.getMinimalFormatManager();
		FormatDescription leftFd = new FormatDescription(leftFormat);

		FgDisplay rightDisplay = displays.get(RIGHT);
		FGController rightController = rightDisplay.getController();
		FormatManager rightFormat = rightController.getMinimalFormatManager();
		FormatDescription rightFd = new FormatDescription(rightFormat);

		assertEquals(leftFd, rightFd);

		return leftFd;
	}

	private FormatDescription changeFormat(FunctionComparisonProvider provider) {

		FunctionGraphCodeComparisonView fgProvider = getFgComparisonProvider(provider);
		DockingAction action = getAction(fgProvider, "Edit Code Block Fields");
		performAction(action, provider, false);

		SetFormatDialogComponentProvider dialog =
			waitForDialogComponent(SetFormatDialogComponentProvider.class);

		String tabName = "Instruction/Data";
		String actionName = "Bytes";
		selectFormatTab(dialog, tabName);

		assertField(dialog, actionName, false);

		FieldHeaderLocation fhLoc = createFieldHeaderLocation(dialog);
		ActionContext context = createContext(fhLoc);
		DockingActionIf addFieldAction = getFormatAction(dialog, tabName, actionName);
		performAction(addFieldAction, context, true);

		waitForConditionWithoutFailing(() -> fieldIsVisible(dialog, actionName));

		assertTrue(actionName + " field was not added to the model",
			fieldIsVisible(dialog, actionName));

		JButton OKButton = findButtonByText(dialog, "OK");
		pressButton(OKButton);
		waitForSwing();

		return getFormat(fgProvider);
	}

	private DockingActionIf getFormatAction(SetFormatDialogComponentProvider provider,
			String formatName, String actionName) {

		Set<DockingActionIf> actions = provider.getActions();
		for (DockingActionIf action : actions) {
			if (!action.getName().equals(actionName)) {
				continue;
			}

			if (!(action instanceof AddFieldAction)) {
				continue;
			}

			FieldFormatModel formatModel =
				(FieldFormatModel) getInstanceField("formatModel", action);
			String name = formatModel.getName();
			if (name.equals(formatName)) {
				return action;
			}
		}

		fail("Unable to find action '" + actionName + "' in format model '" + formatName + "'");
		return null;
	}

	private void selectFormatTab(SetFormatDialogComponentProvider provider, String tabName) {

		ListingPanel listingPanel = (ListingPanel) getInstanceField("listingPanel", provider);
		FieldHeader header = (FieldHeader) getInstanceField("headerPanel", listingPanel);

		FieldFormatModel model = null;
		FormatManager manager = (FormatManager) getInstanceField("formatManager", listingPanel);
		for (int i = 0; i < manager.getNumModels(); i++) {
			FieldFormatModel formatModel = manager.getModel(i);
			String name = formatModel.getName();
			if (name.equals(tabName)) {
				model = formatModel;
				break;
			}
		}
		assertNotNull("Could not find format '" + tabName + "'", model);

		int index = header.indexOfTab(tabName);
		runSwing(() -> header.setSelectedIndex(index));

		waitForCondition(() -> header.getSelectedIndex() == index);
	}

	private FieldHeaderLocation createFieldHeaderLocation(
			SetFormatDialogComponentProvider provider) {
		FieldHeader headerPanel = provider.getFieldHeader();
		FieldHeaderComp fieldHeaderComp = headerPanel.getHeaderTab();
		FieldFormatModel model = fieldHeaderComp.getModel();

		int row = 1;
		int col = 0;
		FieldFactory factory = model.getFactorys(row)[col];
		return new FieldHeaderLocation(model, factory, row, col);
	}

	private void assertField(SetFormatDialogComponentProvider provider, String name,
			boolean shouldExist) {

		if (shouldExist) {
			assertTrue("Field '" + name + "' is not in the model, but it should be",
				fieldIsVisible(provider, name));
		}
		else {
			assertFalse("Field '" + name + "' is in the model, but it should not be",
				fieldIsVisible(provider, name));
		}
	}

	private boolean fieldIsVisible(SetFormatDialogComponentProvider provider, String name) {
		FieldHeader headerPanel = provider.getFieldHeader();
		FieldHeaderComp fieldHeaderComp = headerPanel.getHeaderTab();
		FieldFormatModel model = fieldHeaderComp.getModel();

		FieldFactory[] unused = model.getUnusedFactories();
		for (FieldFactory ff : unused) {
			if (ff.getFieldName().equals(name)) {
				return false; // field is hidden/unused
			}
		}

		// sanity check
		FieldFactory[] visible = model.getAllFactories();
		for (FieldFactory ff : visible) {
			if (ff.getFieldName().equals(name)) {
				return true; // visible
			}
		}

		fail("Field '" + name + "' + is not in the model at all, hidden or visible!");
		return false; // can't get here
	}

	private DockingAction getAction(FunctionGraphCodeComparisonView panel, String actionName) {
		List<DockingAction> actions = panel.getActions();
		for (DockingAction action : actions) {
			String name = action.getName();
			if (name.equals(actionName)) {
				return action;
			}
		}

		fail("Could not find action '%s'".formatted(actionName));
		return null;
	}

	private void selectFgPanel(FunctionComparisonProvider provider) {
		runSwing(() -> provider.selectComparisonView(FunctionGraphCodeComparisonView.NAME));
	}

	private FunctionGraphCodeComparisonView getFgComparisonProvider(
			FunctionComparisonProvider provider) {
		return runSwing(() -> (FunctionGraphCodeComparisonView) provider
				.getCodeComparisonView(FunctionGraphCodeComparisonView.NAME));
	}

	private void waitForFunctionGraph(FunctionGraphCodeComparisonView panel) {
		waitForSwing();
		waitForCondition(() -> !panel.isBusy());
		waitForSwing();
	}

	private void compareFunctions(Set<Function> functions) {
		runSwing(() -> plugin.createComparison(functions));
		waitForSwing();
	}

	private void checkFunctions(FunctionComparisonProvider provider, Side side,
			Function activeFunction, Function... functions) {
		Set<Function> funcs = Set.of(functions);

		FunctionComparisonModel model = provider.getModel();
		assertEquals(activeFunction, model.getActiveFunction(side));

		List<Function> fcs = model.getFunctions(side);
		assertEquals(fcs.size(), funcs.size());
		assertTrue(fcs.containsAll(funcs));
	}

	private void close(FunctionComparisonProvider provider) {
		runSwing(() -> provider.closeComponent());
	}

	private class FormatDescription {

		private String string;

		FormatDescription(FormatManager fm) {
			SaveState ss = new SaveState();
			fm.saveState(ss);
			string = ss.toString();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getEnclosingInstance().hashCode();
			result = prime * result + Objects.hash(string);
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			FormatDescription other = (FormatDescription) obj;
			if (!getEnclosingInstance().equals(other.getEnclosingInstance())) {
				return false;
			}
			return Objects.equals(string, other.string);
		}

		@Override
		public String toString() {
			return string;
		}

		private CompareFunctionsFunctionGraphViewTest getEnclosingInstance() {
			return CompareFunctionsFunctionGraphViewTest.this;
		}
	}
}
