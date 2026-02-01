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

import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.table.*;

import org.junit.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.widgets.combobox.GComboBox;
import docking.widgets.dialogs.SettingsDialog;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.*;

public class FunctionWindowPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private FunctionWindowPlugin plugin;
	private GTable functionTable;
	private FunctionWindowProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		loadProgram("notepad");
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(FunctionWindowPlugin.class);

		plugin.showFunctions();
		waitForSwing();
		provider = (FunctionWindowProvider) tool.getComponentProvider("Functions Window");
		functionTable = (GTable) findComponentByName(provider.getComponent(), "Functions Table");
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
		waitForTable();
	}

	@Test
	public void testDeleteAndRestore() throws Exception {

		int numData = functionTable.getRowCount();

		CompoundCmd<Program> cmd = new CompoundCmd<>("Clear");
		FunctionIterator itr = program.getListing().getFunctions(true);
		while (itr.hasNext()) {
			Function f = itr.next();
			cmd.add(new ClearCmd(f.getBody(), new ClearOptions()));
		}
		applyCmd(program, cmd);
		waitForTable();

		assertEquals(0, functionTable.getRowCount());

		undo(program);
		waitForTable();

		assertEquals(numData, functionTable.getRowCount());
	}

	@Test
	public void testProgramClose() throws Exception {
		closeProgram();
		waitForTable();
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
		ActionContext context = new DefaultActionContext(provider, functionTable);
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

	@Test
	public void testChange_WithFitler() throws Exception {

		//
		// This tests a regression with changed items.  Normally a changed item is handled by a 
		// remove of the existing row object, with a re-add of that object.  This allows us to avoid
		// duplicates and to sort the item.  We had a bug that prevented the item from being 
		// removed.
		//

		// the bug was only present when sorted on the name column, since the sort was no longer
		// correct when the name had changed
		sort("Name");
		int startRowCount = functionTable.getRowCount();

		// verify the function we will rename is in the table
		assertFunctionInTable("FUN_010058b8");

		// apply a filter that will hide an item we will rename
		filter("entry");
		assertEquals(1, functionTable.getRowCount());
		assertFunctionInTable("entry");

		// rename a function not showing, using a name that will pass the filter		
		// FUN_010058b8 -> entry2
		renameFunction(addr("010058b8"), "entry2");

		// verify the new item appears
		assertEquals(2, functionTable.getRowCount());
		assertFunctionInTable("entry2");

		// remove the filter
		filter("");

		// verify the old item is gone and the new item is still there
		assertFunctionInTable("entry2");
		assertFunctionNotInTable("FUN_010058b8");
		assertEquals("Table row count should not have changed for a function rename", startRowCount,
			functionTable.getRowCount());
	}

	private void sort(String columnName) {

		int column = getColumn(columnName);
		TableSortState descendingSortState = TableSortState.createDefaultSortState(column, false);
		FunctionTableModel model = (FunctionTableModel) functionTable.getModel();
		runSwing(() -> model.setTableSortState(descendingSortState));
		waitForTable();
	}

	private int getColumn(String columnName) {
		int n = functionTable.getColumnCount();
		for (int i = 0; i < n; i++) {
			String name = functionTable.getColumnName(i);
			if (name.equals(columnName)) {
				return i;
			}
		}

		fail("Could not find column '%s'".formatted(columnName));
		return 0;
	}

	private void assertFunctionNotInTable(String expectedName) {
		FunctionTableModel model = (FunctionTableModel) functionTable.getModel();
		List<FunctionRowObject> data = model.getModelData();
		for (FunctionRowObject rowObject : data) {
			Function f = rowObject.getFunction();
			String name = f.getName();
			if (name.equals(expectedName)) {
				fail("The table should not have a function by name '%s'".formatted(expectedName));
			}
		}
	}

	private void assertFunctionInTable(String expectedName) {
		FunctionTableModel model = (FunctionTableModel) functionTable.getModel();
		List<FunctionRowObject> data = model.getModelData();
		for (FunctionRowObject rowObject : data) {
			Function f = rowObject.getFunction();
			String name = f.getName();
			if (name.equals(expectedName)) {
				return;
			}
		}
		fail("The table should have a function by name '%s'".formatted(expectedName));
	}

	private void renameFunction(Address entry, String newName) {

		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		Symbol symbol = f.getSymbol();
		Namespace namespace = f.getParentNamespace();
		RenameLabelCmd cmd =
			new RenameLabelCmd(symbol, newName, namespace, SourceType.USER_DEFINED);
		applyCmd(program, cmd);
		waitForTable();
	}

	private Address addr(String s) {
		AddressFactory af = program.getAddressFactory();
		return af.getAddress(s);
	}

	private void filter(String text) {
		GTableFilterPanel<?> filterPanel = functionTable.getTableFilterPanel();
		runSwing(() -> filterPanel.setFilterText(text));
		waitForTable();
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

	private void waitForTable() {
		waitForTableModel((ThreadedTableModel<?, ?>) functionTable.getModel());
	}

}
