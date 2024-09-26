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
package ghidra.app.plugin.core.datamgr.editor;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.KeyEvent;

import javax.swing.*;
import javax.swing.table.*;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class EnumEditor2Test extends AbstractGhidraHeadedIntegrationTest {

	private Program program;
	private PluginTool tool;
	private TestEnv env;
	private DataTypeManagerPlugin plugin;

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		builder.addCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		program = builder.getProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = getPlugin(tool, DataTypeManagerPlugin.class);

	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testInsertRow() throws Exception {

		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		Enum enumDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		runSwingLater(() -> plugin.edit(enumDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// add an entry with a value of 15
		addEntry(table, model, "Gold", 0x15);
		assertEquals(4, model.getRowCount());

		assertEquals("Blue", model.getValueAt(3, EnumTableModel.NAME_COL));
		assertEquals("Gold", model.getValueAt(2, EnumTableModel.NAME_COL));
		assertEquals(0x15L, model.getValueAt(2, EnumTableModel.VALUE_COL));
		// add an entry with a value of 5
		addEntry(table, model, "Pink", 5);
		assertEquals(5, model.getRowCount());
		assertEquals("Pink", model.getValueAt(1, EnumTableModel.NAME_COL));
	}

	@Test
	public void testSortColumns() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		runSwingLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// sort by Name
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(EnumTableModel.NAME_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		assertEquals("Blue", model.getValueAt(0, EnumTableModel.NAME_COL));
		assertEquals("Green", model.getValueAt(1, EnumTableModel.NAME_COL));
		assertEquals("Red", model.getValueAt(2, EnumTableModel.NAME_COL));

		// sort by Value
		rect = header.getHeaderRect(EnumTableModel.VALUE_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		assertEquals("Red", model.getValueAt(0, EnumTableModel.NAME_COL));
		assertEquals("Green", model.getValueAt(1, EnumTableModel.NAME_COL));
		assertEquals("Blue", model.getValueAt(2, EnumTableModel.NAME_COL));
	}

	@Test
	public void testSortOnComments() {

		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0, "1");
		enumm.add("Green", 0x10, "3");
		enumm.add("Blue", 0x20, "2");

		Enum enummDt = tx(program, () -> {
			return (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		});

		runSwingLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// sort by Name
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(EnumTableModel.COMMENT_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		assertEquals("1", model.getValueAt(0, EnumTableModel.COMMENT_COL));
		assertEquals("2", model.getValueAt(1, EnumTableModel.COMMENT_COL));
		assertEquals("3", model.getValueAt(2, EnumTableModel.COMMENT_COL));

		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		assertEquals("3", model.getValueAt(0, EnumTableModel.COMMENT_COL));
		assertEquals("2", model.getValueAt(1, EnumTableModel.COMMENT_COL));
		assertEquals("1", model.getValueAt(2, EnumTableModel.COMMENT_COL));
	}

	@Test
	public void testSortOrder() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		runSwingLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// sort Descending
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(EnumTableModel.VALUE_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		assertEquals(0x20L, model.getValueAt(0, EnumTableModel.VALUE_COL));
		assertEquals(0x10L, model.getValueAt(1, EnumTableModel.VALUE_COL));
		assertEquals(0L, model.getValueAt(2, EnumTableModel.VALUE_COL));

		// sort by Name
		rect = header.getHeaderRect(EnumTableModel.NAME_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();
		// sort Descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();
		assertEquals("Red", model.getValueAt(0, EnumTableModel.NAME_COL));
		assertEquals("Green", model.getValueAt(1, EnumTableModel.NAME_COL));
		assertEquals("Blue", model.getValueAt(2, EnumTableModel.NAME_COL));
	}

	@Test
	public void testInsertRowByName() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		runSwingLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// sort by Name
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(EnumTableModel.NAME_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		// insert "Cyan"
		addEntry(table, model, "Cyan", 0x30);
		assertEquals("Cyan", model.getValueAt(1, EnumTableModel.NAME_COL));
	}

	@Test
	public void testDeleteRows() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// select rows 2 and 4 ("Purple" and "Blue")
		table.setRowSelectionInterval(2, 2);
		table.addRowSelectionInterval(4, 4);

		DockingActionIf deleteAction = getDeleteAction();
		assertTrue(deleteAction.isEnabled());

		runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
		waitForSwing();
		assertTrue(table.isRowSelected(3));

		DockingActionIf applyAction = getApplyAction();
		assertTrue(applyAction.isEnabled());

		runSwing(() -> applyAction.actionPerformed(new DefaultActionContext()));
		program.flushEvents();
		waitForSwing();

		assertEquals(4, model.getRowCount());
		assertEquals(4, enummDt.getCount());
	}

	@Test
	public void testDeleteAllRows() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();
		DockingActionIf deleteAction = getDeleteAction();

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
			waitForSwing();
		}
		assertEquals(0, model.getRowCount());
		// add an entry so the tear down works properly
		addEntry(table, model, "test", 1);
	}

	@Test
	public void testEmptyEnum() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();
		DockingActionIf deleteAction = getDeleteAction();

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
			waitForSwing();
		}
		applyChanges(true);
		Window w = windowForComponent(table);
		String str = findLabelText(w, "Tool Status");

		assertEquals("Empty enum is not allowed", str);
		// add an entry so the tear down works properly
		addEntry(table, model, "test", 1);
	}

	@Test
	public void testCloseEditorWithError() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();
		DockingActionIf deleteAction = getDeleteAction();

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
			waitForSwing();
		}

		ComponentProvider provider = waitForComponentProvider(EnumEditorProvider.class);
		assertNotNull(provider);
		runSwingLater(() -> provider.closeComponent());
		waitForSwing();
		Window w = windowForComponent(table);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		pressButtonByText(d.getComponent(), "Yes");
		waitForSwing();

		assertTrue(tool.isVisible(provider));
		String str = findLabelText(w, "Tool Status");

		assertEquals("Empty enum is not allowed", str);
		// add an entry so the tear down works properly
		addEntry(table, model, "test", 1);
	}

	@Test
	public void testCloseEditorWithErrorNoSave() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		DockingActionIf deleteAction = getDeleteAction();

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
			waitForSwing();
		}

		ComponentProvider provider = waitForComponentProvider(EnumEditorProvider.class);
		assertNotNull(provider);
		runSwingLater(() -> provider.closeComponent());
		waitForSwing();
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		pressButtonByText(d.getComponent(), "No");
		waitForSwing();
		assertFalse(tool.isVisible(provider));
	}

	@Test
	public void testCloseEditorWithErrorCancel() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();
		DockingActionIf deleteAction = getDeleteAction();

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
			waitForSwing();
		}

		ComponentProvider provider = waitForComponentProvider(EnumEditorProvider.class);
		assertNotNull(provider);
		runSwingLater(() -> provider.closeComponent());
		waitForSwing();
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		pressButtonByText(d.getComponent(), "Cancel");
		waitForSwing();
		assertTrue(tool.isVisible(provider));

		// add an entry so the tear down works properly
		addEntry(table, model, "test", 1);
	}

	@Test
	public void testDeleteFirstRow() throws Exception {

		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// select first row ("Red");
		table.setRowSelectionInterval(0, 0);
		DockingActionIf deleteAction = getDeleteAction();
		assertTrue(deleteAction.isEnabled());

		runSwing(() -> deleteAction.actionPerformed(new DefaultActionContext()));
		waitForSwing();

		assertTrue(table.isRowSelected(0));

		DockingActionIf applyAction = getApplyAction();
		assertTrue(applyAction.isEnabled());

		runSwing(() -> applyAction.actionPerformed(new DefaultActionContext()));
		program.flushEvents();
		waitForSwing();

		assertEquals(5, model.getRowCount());
		assertEquals(5, enummDt.getCount());
	}

	@Test
	public void testEditName() throws Exception {

		Enum enummDt = editSampleEnum();
		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());

		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Name");
			nameField.setText("MyColors");
		});
		waitForSwing();
		applyChanges(true);
		assertEquals("MyColors", enummDt.getName());
	}

	@Test
	public void testEditName_RowChanges_NavigationWithTab() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();

		sortOnNameColumn();

		int row = 0;
		int col = 0;
		clickTableCell(table, row, col, 2);
		assertTrue(runSwing(() -> table.isEditing()));

		// note: this new name will cause the enum entry at row 0 to get moved to row 1
		String newName = "MyColors";
		JTextField editorField = getCellEditorTextField();
		assertNotNull(editorField);
		setText(editorField, newName);

		pressTab(editorField);

		// get the row after the table has been sorted
		int newRow = findRowByName(newName);
		assertNotEquals(row, newRow);

		int newColumn = col + 1;
		assertEditing(newRow, newColumn);
	}

	@Test
	public void testDuplicateName() throws Exception {

		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);
		enumm.add("Purple", 5);
		enumm.add("Turquoise", 0x22);
		enumm.add("Pink", 2);

		Enum en2 = new EnumDataType("FavoriteColors", 1);
		en2.add("Red", 20);
		en2.add("Black", 5);
		en2.add("Topaz", 10);

		int transactionID = program.startTransaction("Test");
		Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		cat.addDataType(en2, DataTypeConflictHandler.DEFAULT_HANDLER);

		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		runSwing(() -> plugin.edit(enummDt), false);
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());

		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Name");
			nameField.setText("FavoriteColors");
		});
		waitForSwing();
		applyChanges(false);
		DialogComponentProvider dialog = waitForErrorDialog();
		assertNotNull(dialog);
		assertEquals("Duplicate Name", dialog.getTitle());
		assertEquals("Colors", enummDt.getName());

		close(dialog);
		waitForSwing();

		assertFalse(getApplyAction().isEnabled());

	}

	@Test
	public void testNameTrim() throws Exception {

		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		String newName = "   MyNewName  ";
		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Name");
			nameField.setText(newName);
		});

		DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());

		performAction(applyAction);
		waitForProgram(program);

		assertEquals(newName.trim(), enummDt.getName());
	}

	@Test
	public void testDescriptionTrim() throws Exception {

		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		String newDescription = "   My new description  ";
		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Description");
			nameField.setText(newDescription);
		});

		DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());

		performAction(applyAction);
		waitForProgram(program);

		assertEquals(newDescription.trim(), enummDt.getDescription());
	}

	@Test
	public void testDuplicateValue() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		addEntry(table, model, "MYColor", 3);
		// change value to an existing value
		int row = model.getRow("MYColor");

		Rectangle rect = table.getCellRect(1, EnumTableModel.VALUE_COL, true);
		clickMouse(table, 1, rect.x, rect.y, 1, 0);

		table.setRowSelectionInterval(row, row);
		runSwingLater(() -> {
			table.editCellAt(1, EnumTableModel.VALUE_COL);
			TableCellEditor editor = table.getCellEditor(row, EnumTableModel.VALUE_COL);
			Component c = editor.getTableCellEditorComponent(table,
				model.getValueAt(row, EnumTableModel.VALUE_COL), true, row,
				EnumTableModel.VALUE_COL);
			JTextField tf = (JTextField) c;
			// set a number that is already assigned
			tf.setText("0x0");
			editor.stopCellEditing();
		});
		waitForSwing();
		Window w = windowForComponent(table);
		String str = findLabelText(w, "Tool Status");
//		assertEquals("Colors enum value 0 already assigned", str);
		// duplicate values are now allowed
		assertEquals("", str);
	}

	@Test
	public void testEditDescription() throws Exception {

		Enum enumDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTextField descField = getTextField(panel, "Description");
		assertEquals("This is a set of Colors", descField.getText());

		runSwing(() -> descField.setText("My Favorite colors"));
		waitForSwing();
		applyChanges(true);
		assertEquals("My Favorite colors", enumDt.getDescription());

	}

	@Test
	public void testClearDescription() throws Exception {

		Enum enumDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTextField descField = getTextField(panel, "Description");

		runSwing(() -> descField.setText(""));
		waitForSwing();
		applyChanges(true);
		assertEquals("", enumDt.getDescription());

	}

	@Test
	public void testMoveColumns() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();

		runSwing(() -> {
			TableColumnModel colModel = table.getColumnModel();
			colModel.moveColumn(1, 0);
		});
		waitForSwing();
		assertEquals("Value", table.getColumnName(0));
		assertEquals("Name", table.getColumnName(1));

		runSwing(() -> {
			TableColumnModel colModel = table.getColumnModel();
			colModel.moveColumn(0, 1);
		});
		waitForSwing();
		assertEquals("Name", table.getColumnName(0));
		assertEquals("Value", table.getColumnName(1));

	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void sortOnNameColumn() {

		JTable table = getTable();
		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		TableSortState sortState = getSortState(sortedModel);
		ColumnSortState primarySortState = sortState.iterator().next();
		SortDirection sortDirection = primarySortState.getSortDirection();
		if (primarySortState.getColumnModelIndex() == EnumTableModel.NAME_COL) {
			if (SortDirection.ASCENDING == sortDirection) {
				return; // already sorted
			}
		}

		TableSortState newSortState =
			TableSortState.createDefaultSortState(EnumTableModel.NAME_COL, true);
		runSwing(() -> sortedModel.setTableSortState(newSortState));
	}

	private TableSortState getSortState(SortedTableModel sortedModel) {
		return runSwing(() -> sortedModel.getTableSortState());
	}

	private JTable getTable() {
		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		return panel.getTable();
	}

	protected JTextField getCellEditorTextField() {
		Object editorComponent = getTable().getEditorComponent();
		if (editorComponent instanceof JTextField) {
			return (JTextField) editorComponent;
		}

		fail("Either not editing, or editing a field that is a custom editor (not a text field)");
		return null;
	}

	private void assertEditing(int row, int column) {
		JTable table = getTable();
		assertTrue(runSwing(table::isEditing));
		assertEquals(row, (int) runSwing(table::getEditingRow));
		assertEquals(row, (int) runSwing(table::getEditingColumn));
	}

	private int findRowByName(String name) {

		JTable table = getTable();
		return runSwing(() -> {
			int col = 0; // Name column defaults to 0
			int n = table.getRowCount();
			for (int i = 0; i < n; i++) {
				String value = table.getValueAt(i, col).toString();
				if (name.equals(value)) {
					return i;
				}
			}
			return -1;
		});
	}

	private void pressTab(JComponent component) {
		triggerActionKey(component, 0, KeyEvent.VK_TAB);
		waitForSwing();
	}

	private EnumEditorPanel findEditorPanel(Window w) {
		Window[] windows = w.getOwnedWindows();
		for (Window window : windows) {
			if (window.isVisible() && JDialog.class.isAssignableFrom(window.getClass())) {
				Container c =
					findContainer(((JDialog) window).getContentPane(), EnumEditorPanel.class);
				if (c != null) {
					return (EnumEditorPanel) c;
				}
			}
		}
		return null;
	}

	private Container findContainer(Container parent, Class<?> theClass) {
		Component[] c = parent.getComponents();
		for (Component element : c) {
			if (theClass.isAssignableFrom(element.getClass())) {
				return (Container) element;
			}
			if (element instanceof Container) {
				Container container = findContainer((Container) element, theClass);
				if (container != null) {
					return container;
				}
			}
		}
		return null;
	}

	private JTextField getTextField(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if ((element instanceof JTextField) && ((JTextField) element).getName().equals(name)) {
				return (JTextField) element;
			}
			if (element instanceof Container) {
				JTextField tf = getTextField((Container) element, name);
				if (tf != null) {
					return tf;
				}
			}
		}
		return null;
	}

	private void addEntry(JTable table, EnumTableModel model, String name, long value)
			throws Exception {
		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			if (lastRow >= 0) {
				table.addRowSelectionInterval(lastRow, lastRow);
			}
			DockingActionIf addAction = getAddAction();
			addAction.actionPerformed(new DefaultActionContext());
		});
		waitForSwing();
		int newRow = model.getRowCount() - 1;
		// change entry
		runSwing(() -> table.addRowSelectionInterval(newRow, newRow));
		Rectangle rect = table.getCellRect(newRow, EnumTableModel.NAME_COL, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);

		runSwing(() -> {
			TableCellEditor editor = table.getCellEditor(newRow, EnumTableModel.NAME_COL);
			Component c = editor.getTableCellEditorComponent(table,
				model.getValueAt(newRow, EnumTableModel.NAME_COL), true, newRow,
				EnumTableModel.NAME_COL);
			JTextField tf = (JTextField) c;
			tf.setText(name);
			editor.stopCellEditing();
		});
		waitForSwing();
		rect = table.getCellRect(newRow, EnumTableModel.VALUE_COL, true);
		clickMouse(table, 1, rect.x + 1, rect.y + 1, 2, 0);

		runSwing(() -> {
			TableCellEditor editor = table.getCellEditor(newRow, EnumTableModel.VALUE_COL);

			Component c = editor.getTableCellEditorComponent(table,
				model.getValueAt(newRow, EnumTableModel.VALUE_COL), true, newRow,
				EnumTableModel.VALUE_COL);
			JTextField tf = (JTextField) c;
			tf.setText("0x" + Long.toHexString(value));
			editor.stopCellEditing();
		});
		waitForSwing();
	}

	private void applyChanges(boolean doWait) throws Exception {

		DockingActionIf applyAction = getApplyAction();
		assertTrue(applyAction.isEnabled());
		Runnable r = () -> applyAction.actionPerformed(new DefaultActionContext());
		if (doWait) {
			runSwing(r);
			program.flushEvents();
		}
		else {
			runSwingLater(r);
		}
		waitForSwing();

	}

	private String findLabelText(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JLabel) {
				if (name.equals(((JLabel) element).getName())) {
					return ((JLabel) element).getText();
				}
			}
			if (element instanceof Container) {
				String str = findLabelText((Container) element, name);
				if (str != null) {
					return str;
				}
			}
		}
		return null;
	}

	private DockingActionIf getAddAction() {
		return getAction(plugin, "Add Enum Value");
	}

	private DockingActionIf getApplyAction() {
		return getAction(plugin, "Apply Enum Changes");
	}

	private DockingActionIf getDeleteAction() {
		return getAction(plugin, "Delete Enum Value");
	}

	private Enum editSampleEnum() {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);
		enumm.add("Purple", 5);
		enumm.add("Turquoise", 0x22);
		enumm.add("Pink", 2);
		enumm.setDescription("This is a set of Colors");

		int transactionID = program.startTransaction("Test");
		Enum enumDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		runSwingLater(() -> plugin.edit(enumDt));
		waitForSwing();
		return enumDt;
	}

}
