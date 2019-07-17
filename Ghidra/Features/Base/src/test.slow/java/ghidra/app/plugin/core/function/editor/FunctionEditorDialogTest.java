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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.swing.table.TableCellEditor;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.table.GTable;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.test.*;

public class FunctionEditorDialogTest extends AbstractGhidraHeadedIntegrationTest {

	public FunctionEditorDialogTest() {
		super();
	}

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
		env.dispose();
	}

	/**
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

//==================================================================================================
// Private Methods
//==================================================================================================

	private void setEditorText(TableCellEditor cellEditor, String text) {
		DropDownSelectionTextField<?> textField = getDataTypeEditor(cellEditor);
		setText(textField, text);

		finishEditing(cellEditor);
	}

	private FunctionEditorDialog editFunction() {
		performAction(editFunction, cb.getProvider(), false);
		return waitForDialogComponent(null, FunctionEditorDialog.class, DEFAULT_WINDOW_TIMEOUT);
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
