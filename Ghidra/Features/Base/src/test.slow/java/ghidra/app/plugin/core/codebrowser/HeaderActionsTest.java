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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.*;

import java.awt.Window;
import java.util.List;

import javax.swing.text.JTextComponent;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.InputDialog;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class HeaderActionsTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private FieldHeader header;
	private CodeViewerProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setUpCodeBrowserTool(tool);

		env.showTool();

		runSwing(() -> cb.getListingPanel().showHeader(true));
		header = cb.getListingPanel().getFieldHeader();
		provider = cb.getProvider();

		initializeOptions();
	}

	private void initializeOptions() {
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		String optionsName = "Address Field" + Options.DELIMITER + "Address Display Options";
		AddressFieldOptionsWrappedOption afowo =
			(AddressFieldOptionsWrappedOption) options.getCustomOption(optionsName, null);
		afowo.setRightJustify(false);
		options.setCustomOption(optionsName, afowo);
	}

	private void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testResetFormatAction() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factorys = functionFormat.getFactorys(0);
		selectHeaderField(factorys[0]);

		removeAllFactories(functionFormat);
		assertEquals(0, functionFormat.getNumFactorys(0));
		DockingAction headerAction = getHeaderAction("Reset Format");
		performAction(headerAction, false);
		pressContinueOnResetFormatDialog("Reset Format?");

		functionFormat = formatManager.getFunctionFormat();
		assertEquals(3, functionFormat.getNumFactorys(0));

	}

	@Test
	public void testResetAllFormatAction() {
		FormatManager formatManager = header.getFormatManager();
		int numModels = formatManager.getNumModels();
		for (int i = 0; i < numModels; i++) {
			FieldFormatModel model = formatManager.getModel(i);
			model.removeAllFactories();
			assertTrue(model.getFactorys(0).length == 0);
		}

		DockingAction headerAction = getHeaderAction("Reset All Formats");
		performAction(headerAction, false);
		pressContinueOnResetFormatDialog("Reset All Formats?");

		for (int i = 0; i < numModels; i++) {
			FieldFormatModel model = formatManager.getModel(i);
			assertTrue(model.getFactorys(0).length > 0);
		}

	}

	@Test
	public void testRemoveAllFieldsAction() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factorys = functionFormat.getFactorys(0);
		assertEquals(3, factorys.length);

		selectHeaderField(factorys[0]);

		DockingAction headerAction = getHeaderAction("Remove All Fields");
		FieldHeaderLocation loc = new FieldHeaderLocation(functionFormat, factorys[0], 0, 0);
		ActionContext context = createContext(provider, loc);
		performAction(headerAction, context, false);
		pressContinueOnResetFormatDialog("Remove All Fields?");

		functionFormat = formatManager.getFunctionFormat();
		assertEquals(0, functionFormat.getNumFactorys(0));

	}

	@Test
	public void testAddSpacerAction() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factories = functionFormat.getFactorys(0);
		assertTrue(factories[0] instanceof SpacerFieldFactory);
		assertTrue(factories[1] instanceof FunctionSignatureFieldFactory);
		assertEquals(200, factories[1].getStartX());

		selectHeaderField(factories[0]);
		FieldHeaderLocation loc = new FieldHeaderLocation(functionFormat, factories[0], 0, 0);
		ActionContext context = createContext(provider, loc);

		DockingAction headerAction = getHeaderAction("Add Spacer Field");
		performAction(headerAction, context, true);

		functionFormat = formatManager.getFunctionFormat();
		factories = functionFormat.getFactorys(0);
		assertTrue(factories[0] instanceof SpacerFieldFactory);
		assertTrue(factories[1] instanceof SpacerFieldFactory);
		assertTrue(factories[2] instanceof FunctionSignatureFieldFactory);
		assertEquals(300, factories[2].getStartX());
	}

	@Test
	public void testSetSpacerTextAction() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factories = functionFormat.getFactorys(0);
		assertTrue(factories[0] instanceof SpacerFieldFactory);
		selectHeaderField(factories[0]);

		FieldHeaderLocation loc = new FieldHeaderLocation(functionFormat, factories[0], 0, 0);
		ActionContext context = createContext(provider, loc);

		DockingAction headerAction = getHeaderAction("SetTextAction");
		performAction(headerAction, context, false);
		enterTextIntoDialog("Hello");

		functionFormat = formatManager.getFunctionFormat();
		factories = functionFormat.getFactorys(0);
		assertTrue(factories[0] instanceof SpacerFieldFactory);
		assertEquals("Hello", getText((SpacerFieldFactory) factories[0]));

	}

	private String getText(SpacerFieldFactory factory) {
		return runSwing(() -> factory.getText());
	}

	@Test
	public void testDisableEnableFieldActions() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factories = functionFormat.getFactorys(0);
		selectHeaderField(factories[0]);

		assertTrue(factories[1].isEnabled());

		FieldHeaderLocation loc = new FieldHeaderLocation(functionFormat, factories[1], 0, 0);
		ActionContext context = createContext(provider, loc);

		DockingAction headerAction = getHeaderAction("Disable Field");
		performAction(headerAction, context, true);

		assertTrue(!factories[1].isEnabled());

		headerAction = getHeaderAction("Enable Field");
		performAction(headerAction, context, true);
		assertTrue(factories[1].isEnabled());
	}

	@Test
	public void testRemoveFieldAction() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factories = functionFormat.getFactorys(0);
		selectHeaderField(factories[0]);
		assertEquals(3, factories.length);
		assertTrue(factories[1] instanceof FunctionSignatureFieldFactory);

		FieldHeaderLocation loc = new FieldHeaderLocation(functionFormat, factories[1], 0, 1);
		ActionContext context = createContext(provider, loc);

		DockingAction headerAction = getHeaderAction("Remove Field");
		performAction(headerAction, context, true);

		factories = functionFormat.getFactorys(0);
		assertTrue(!(factories[1] instanceof FunctionSignatureFieldFactory));
		assertEquals(2, factories.length);
	}

	@Test
	public void testAddAllFieldsAction() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		FieldFactory[] factories = functionFormat.getFactorys(0);
		int defaultSize = factories.length;
		selectHeaderField(factories[0]);
		functionFormat.removeAllFactories();

		FieldHeaderLocation loc = new FieldHeaderLocation(functionFormat, factories[1], 0, 1);
		ActionContext context = createContext(provider, loc);

		DockingAction headerAction = getHeaderAction("Add All Field");
		performAction(headerAction, context, true);

		factories = functionFormat.getFactorys(0);
		assertTrue(factories.length > defaultSize);
	}

	@Test
	public void testFormatManagerSaveState() {
		FormatManager formatManager = header.getFormatManager();
		FieldFormatModel functionFormat = formatManager.getFunctionFormat();
		SaveState saveState = new SaveState();
		runSwing(() -> {
			formatManager.saveState(saveState);
			functionFormat.removeAllFactories();
		});

		assertEquals(0, functionFormat.getNumFactorys(0));

		runSwing(() -> {
			formatManager.readState(saveState);
		});

		FieldFormatModel updatedFunctionFormat = formatManager.getFunctionFormat();
		assertTrue(updatedFunctionFormat.getNumFactorys(0) > 0);
	}

	private void enterTextIntoDialog(String input) {
		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		assertNotNull("Never found the spacer text input dialog", dialog);
		JTextComponent textField =
			(JTextComponent) findComponentByName(dialog, "input.dialog.text.field.0");
		setText(textField, input);
		pressButtonByText(dialog, "OK", true);
		waitForSwing();
	}

	private void removeAllFactories(final FieldFormatModel model) {
		runSwing(() -> model.removeAllFactories());
	}

	private void selectHeaderField(final FieldFactory fieldFactory) {
		runSwing(() -> header.setSelectedFieldFactory(fieldFactory));
	}

	private void pressContinueOnResetFormatDialog(String title) {
		Window window = waitForWindow(title);
		assertNotNull("Never found the dialog: " + title, window);
		pressButtonByText(window, "Continue");
		waitForSwing();
	}

	private DockingAction getHeaderAction(String name) {
		ListingPanel listingPanel = cb.getListingPanel();
		List<DockingActionIf> actions = listingPanel.getHeaderActions(provider.getName());
		for (DockingActionIf action : actions) {
			if (action.getName().equals(name)) {
				return (DockingAction) action;
			}
		}
		fail("Couldn't find header action: " + name);
		return null;
	}
}
