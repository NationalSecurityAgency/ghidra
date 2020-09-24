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
package ghidra.app.plugin.core.functionwindow;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.table.*;

import org.junit.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.widgets.combobox.GComboBox;
import docking.widgets.dialogs.SettingsDialog;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.test.*;

public class FunctionWindowPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private FunctionWindowPlugin plugin;
	private GTable functionTable;
	private ComponentProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		loadProgram("notepad");
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(FunctionWindowPlugin.class);

		plugin.showFunctions();
		waitForSwing();
		provider = tool.getComponentProvider("Functions Window");
		functionTable = (GTable) findComponentByName(provider.getComponent(), "FunctionTable");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);
		waitForSwing();
		waitForNotBusy(functionTable);
	}

	@Test
	public void testDeleteAndRestore() throws Exception {

		int numData = functionTable.getRowCount();

		CompoundCmd cmd = new CompoundCmd("Clear");
		FunctionIterator itr = program.getListing().getFunctions(true);
		while (itr.hasNext()) {
			Function f = itr.next();
			cmd.add(new ClearCmd(f.getBody(), new ClearOptions()));
		}
		applyCmd(program, cmd);
		waitForNotBusy(functionTable);

		assertEquals(0, functionTable.getRowCount());

		undo(program);
		waitForNotBusy(functionTable);

		assertEquals(numData, functionTable.getRowCount());
	}

	@Test
	public void testProgramClose() throws Exception {
		closeProgram();
		waitForNotBusy(functionTable);
		assertEquals(functionTable.getRowCount(), 0);
	}

	@Test
	public void testChangeSettings() throws Exception {
		//
		// This test is for a regression bug.  There were multiple exceptions happening when
		// executing the code paths below.
		//

		int row = 0;
		int column = getColumnIndex("Function Size");
		String startValue = getRenderedTableCellValue(functionTable, row, column);

		JPopupMenu menu = functionTable.getTableColumnPopupMenu(column);
		JMenuItem item = (JMenuItem) menu.getComponent(1);
		assertEquals("Column Settings...", item.getText());

		pressButton(item, false);

		SettingsDialog dialog = waitForDialogComponent(SettingsDialog.class);
		int editRow = getFormatRow(dialog);
		//triggerEdit(dialog, editRow, 1);
		editCell(dialog.getTable(), editRow, 1);
		setComboValue(dialog, "hex");
		endEdit(dialog);
		pressButtonByText(dialog, "Dismiss");

		String endValue = getRenderedTableCellValue(functionTable, row, column);
		assertNotEquals("Changing the format did not change the view", startValue, endValue);
	}

	@Test
	public void testCopyingFunctionSignature() throws Exception {

		int row = 0;
		int column = getColumnIndex("Function Signature");
		select(row);

		String signatureText = getRenderedTableCellValue(functionTable, row, column);

		DockingActionIf copyAction = getAction(tool, ToolConstants.SHARED_OWNER, "Table Data Copy");
		ActionContext context = new ActionContext(provider, functionTable);
		performAction(copyAction, context, true);

		// 
		// Note: we cannot make this call:
		// String clipboardText = getClipboardText();
		//
		// The copy action of the table uses Java's built-in copy code.  That code uses the system
		// clipboard, which we cannot rely on in a testing environment.  So, we will just call
		// the code under test directly.
		//

		// flag to trigger copy code
		setInstanceField("copying", functionTable, Boolean.TRUE);
		String copyText = getCopyText(row, column);
		assertThat(copyText, containsString(signatureText));
	}

	private String getCopyText(int row, int column) {
		Object value = runSwing(() -> functionTable.getValueAt(row, column));
		assertNotNull(value);
		return value.toString();
	}

	private void select(int row) {
		runSwing(() -> {
			functionTable.clearSelection();
			functionTable.addRowSelectionInterval(row, row);
		});
	}

	private int getFormatRow(SettingsDialog dialog) {
		GTable table = dialog.getTable();
		int column = getColumnIndex(table, "Name");
		int n = table.getRowCount();
		for (int i = 0; i < n; i++) {
			int row = i;
			Object name = runSwing(() -> table.getValueAt(row, column));
			if ("Format".equals(name)) {
				return i;
			}
		}

		fail("Unable to find the 'Format' row in the Settings Dialog");
		return -1;
	}

	private int getColumnIndex(String text) {
		return getColumnIndex(functionTable, text);
	}

	private int getColumnIndex(JTable table, String text) {
		TableColumnModel columnModel = table.getColumnModel();
		int n = columnModel.getColumnCount();
		for (int i = 0; i < n; i++) {
			TableColumn column = columnModel.getColumn(i);
			if (text.equals(column.getIdentifier().toString())) {
				return i;
			}
		}
		fail("Could not find column '" + text + "'");
		return -1;
	}

	private void setComboValue(SettingsDialog d, String string) {
		GTable table = d.getTable();
		TableCellEditor activeEditor = runSwing(() -> table.getCellEditor());
		assertNotNull("Table should be editing, but is not", activeEditor);

		assertTrue(activeEditor.getClass().getSimpleName().contains("SettingsEditor"));
		@SuppressWarnings("unchecked")
		GComboBox<String> combo = (GComboBox<String>) getInstanceField("comboBox", activeEditor);
		setComboBoxSelection(combo, string);
	}

	private void endEdit(SettingsDialog d) {
		GTable table = d.getTable();
		runSwing(() -> table.editingStopped(new ChangeEvent(table)));
	}

	private void waitForNotBusy(GTable table) {
		waitForTableModel((ThreadedTableModel<?, ?>) table.getModel());
	}

}
