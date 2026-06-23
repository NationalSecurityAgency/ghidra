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
package ghidra.app.plugin.core.function.editor;

import static org.junit.Assert.*;

import javax.swing.AbstractButton;
import javax.swing.ComboBoxModel;
import javax.swing.table.TableCellEditor;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.button.BrowseButton;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.table.GTable;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.*;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;

public class FunctionEditorDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private FunctionPlugin fp;
	private DockingActionIf editFunction;
	private DockingActionIf createFunction;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);

		env.showTool();
		loadNotepad();
	}

	@After
	public void tearDown() {
		closeAllWindows();
		env.dispose();
	}

	/*
	 * Tests that an invalid parameter type entry will generate the proper error message
	 * shown in the status box, and NOT present the user with a stack trace.
	 */
	@Test
	public void testInvalidParameterDataTypeEdit() throws Exception {

		//
		// First create the tool and a function.  We'll modify one of the function
		// params to have a bogus entry we can test against.
		//
		createFunctionAtEntry();

		FunctionEditorDialog dialog = editFunction();
		GTable paramTable = findComponent(dialog.getComponent(), GTable.class);

		TableCellEditor cellEditor = editCell(paramTable, 0, 1);

		setEditorText(cellEditor, "a/b/c");

		// If the status field indicates that we have an invalid data type, then we're good.  If
		// an exception is thrown on the stopCellEditing() call, then this will be skipped and
		// the test will fail.
		assertTrue(dialog.getStatusText().contains("Invalid data type"));
	}

	@Test
	public void testSetNamespace() throws Exception {

		createFunctionAtEntry();

		String newNamespaceName = "NewNamespace";
		Namespace newNs = createNamespace(newNamespaceName);

		FunctionEditorDialog dialog = editFunction();

		pickNamespaceFromComboBox(dialog, newNs);

		pressButtonByText(dialog, "OK");
		waitForBusyTool(tool);

		Function f = getFunction("0x1006420");
		Namespace actualNamespace = f.getParentNamespace();
		assertEquals(newNs, actualNamespace);
	}

	@Test
	public void testSetNamespace_Browse_CreateNew() throws Exception {

		createFunctionAtEntry();

		String newNamespace = "NonExistingNamespace";

		FunctionEditorDialog dialog = editFunction();

		setNamespaceUsingNsChooserDilaog(dialog, newNamespace);

		pressButtonByText(dialog, "OK");
		waitForBusyTool(tool);

		Function f = getFunction("0x1006420");
		Namespace actualNamespace = f.getParentNamespace();
		assertEquals(newNamespace, actualNamespace.toString());
	}

	@Test
	public void testSetNamespace_Browse_CreateNew_NamespacePath() throws Exception {

		createFunctionAtEntry();

		String newNamespacePath = "Foo::Bar::NonExistingNamespace";

		FunctionEditorDialog dialog = editFunction();

		setNamespaceUsingNsChooserDilaog(dialog, newNamespacePath);

		pressButtonByText(dialog, "OK");
		waitForBusyTool(tool);

		Function f = getFunction("0x1006420");
		Namespace actualNamespace = f.getParentNamespace();
		SymbolPath expectedPath = new SymbolPath(newNamespacePath);
		SymbolPath actualPath = new SymbolPath(actualNamespace.getPathList(true));
		assertEquals(expectedPath, actualPath);
	}

	@Test
	public void testSetNamespace_ViaTextEditor() throws Exception {

		createFunctionAtEntry();

		String newNamespacePath = "Foo::Bar";

		FunctionEditorDialog dialog = editFunction();

		setNamespaceUsingTextEditor(dialog, newNamespacePath);
		assertNamespaceNotVisibleInEditorAfterParsing(dialog);
		assertNamespaceComboBoxIsShowingNamespace(dialog, newNamespacePath);

		pressButtonByText(dialog, "OK");
		waitForBusyTool(tool);

		Function f = getFunction("0x1006420");
		Namespace actualNamespace = f.getParentNamespace();
		SymbolPath expectedPath = new SymbolPath(newNamespacePath);
		SymbolPath actualPath = new SymbolPath(actualNamespace.getPathList(true));
		assertEquals(expectedPath, actualPath);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertNamespaceComboBoxIsShowingNamespace(FunctionEditorDialog dialog,
			String expectedNsPath) {

		Namespace actualNs = runSwing(() -> dialog.getSelectedNamesapce());
		assertEquals(expectedNsPath, actualNs.toString());
	}

	private void assertNamespaceNotVisibleInEditorAfterParsing(FunctionEditorDialog dialog) {
		FunctionSignatureTextField field = dialog.getSignatureField();
		String signature = runSwing(() -> field.getText());
		assertFalse("Namespace should not be visible in the editor after parsing",
			signature.contains("::"));
	}

	private void setNamespaceUsingTextEditor(FunctionEditorDialog dialog, String ns) {

		FunctionSignatureTextField field = dialog.getSignatureField();
		String signature = runSwing(() -> field.getText());

		// Insert namespace in front of name.  Format: 
		// 		undefined entry (void)
		int paren = signature.indexOf('(');
		int spaceBeforeParen = paren - 1;
		int space = signature.lastIndexOf(' ', spaceBeforeParen - 1);
		String beginning = signature.substring(0, space + 1);
		String end = signature.substring(space + 1);
		String updated = beginning + ns + "::" + end;

		setText(field, updated);

		runSwing(() -> dialog.triggerSignatureParsing());
	}

	private void pickNamespaceFromComboBox(FunctionEditorDialog dialog, Namespace ns) {

		GhidraComboBox<?> combo =
			(GhidraComboBox<?>) findComponentByName(dialog, "NamespaceComboBox");

		int index = indexOf(combo, ns);
		if (index < 0) {
			fail("Could not find namespace in combo box: " + ns);
		}
		runSwing(() -> combo.setSelectedIndex(index));
	}

	private int indexOf(GhidraComboBox<?> combo, Namespace ns) {
		return runSwing(() -> {

			String nsName = ns.getName();
			ComboBoxModel<?> model = combo.getModel();
			int n = model.getSize();
			for (int i = 0; i < n; i++) {
				Object element = model.getElementAt(i);
				String elementText = element.toString();
				if (elementText.equals(nsName)) {
					return i;
				}
			}
			return -1;
		});
	}

	private void setNamespaceUsingNsChooserDilaog(FunctionEditorDialog dialog,
			String newNamespace) {

		AbstractButton button = findButtonByName(dialog, BrowseButton.NAME);
		pressButton(button, false);

		NamespaceChooserDialog nsDialog = waitForDialogComponent(NamespaceChooserDialog.class);
		runSwing(() -> nsDialog.setText(newNamespace));

		pressButtonByText(nsDialog, "OK");
		waitForBusyTool(tool);
	}

	private Namespace createNamespace(String newNamespace) {

		Namespace newNs = tx(program, () -> {
			return NamespaceUtils.createNamespaceHierarchy(newNamespace, null, program,
				SourceType.USER_DEFINED);
		});

		runSwing(() -> NamespaceCache.add(program, newNs));

		return newNs;
	}

	private void setEditorText(TableCellEditor cellEditor, String text) {
		DropDownSelectionTextField<?> textField = getDataTypeEditor(cellEditor);
		setText(textField, text);

		finishEditing(cellEditor);
	}

	private FunctionEditorDialog editFunction() {
		performAction(editFunction, cb.getProvider(), false);
		return waitForDialogComponent(FunctionEditorDialog.class);
	}

	private void finishEditing(final TableCellEditor cellEditor) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				cellEditor.stopCellEditing();
			}
		});
		waitForSwing();
	}

	private DropDownSelectionTextField<?> getDataTypeEditor(TableCellEditor cellEditor) {

		assertTrue(cellEditor instanceof ParameterDataTypeCellEditor);

		ParameterDataTypeCellEditor paramEditor = (ParameterDataTypeCellEditor) cellEditor;
		DataTypeSelectionEditor dtEditor = paramEditor.getEditor();
		return dtEditor.getDropDownTextField();
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
		fp = getPlugin(tool, FunctionPlugin.class);
		editFunction = getAction(fp, "Edit Function");
		createFunction = getAction(fp, "Create Function");
	}

	private void loadNotepad() throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		builder.dispose();
		waitForSwing();
		addrFactory = program.getAddressFactory();
	}

	private Function getFunction(String addr) {
		FunctionManager fm = program.getFunctionManager();
		return fm.getFunctionAt(addr(addr));
	}

	private void createFunctionAtEntry() {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(addr("0x1006420"));
		if (f != null) {
			// we want to recreate the function, to get better analysis
			deleteExistingFunction(f.getEntryPoint());
		}

		createFunctionAt("0x1006420");

		assertEquals(1, program.getListing().getGlobalFunctions("entry").size());
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void createFunctionAt(String addrString) {
		cb.goToField(addr(addrString), "Address", 0, 0);

		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(addr(addrString));
		if (f != null) {
			// we want to recreate the function, to get better analysis
			deleteExistingFunction(f.getEntryPoint());
		}

		performAction(createFunction, cb.getProvider().getActionContext(null), true);
		waitForBusyTool(tool);
		cb.goToField(addr(addrString), "Function Signature", 0, 0);
	}

	private void deleteExistingFunction(Address entry) {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		if (f == null) {
			return;
		}

		assertTrue(applyCmd(program, new DeleteFunctionCmd(entry)));
	}
}
