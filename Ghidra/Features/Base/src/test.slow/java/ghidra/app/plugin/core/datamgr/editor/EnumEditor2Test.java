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

import javax.swing.*;
import javax.swing.table.*;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
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

	public EnumEditor2Test() {
		super();
	}

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
		env.release(program);
		env.dispose();
	}

	@Test
	public void testInsertRow() throws Exception {

		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(
					new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		final Enum enumDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		SwingUtilities.invokeLater(() -> plugin.edit(enumDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		// add an entry with a value of 15
		addEntry(table, model, "Gold", 0x15);
		assertEquals(4, model.getRowCount());

		assertEquals("Blue", model.getValueAt(3, EnumTableModel.NAME_COL));
		assertEquals("Gold", model.getValueAt(2, EnumTableModel.NAME_COL));
		assertEquals("0x15", model.getValueAt(2, EnumTableModel.VALUE_COL));
		// add an entry with a value of 5
		addEntry(table, model, "Pink", 5);
		assertEquals(5, model.getRowCount());
		assertEquals("Pink", model.getValueAt(1, EnumTableModel.NAME_COL));
	}

	@Test
	public void testSortColumns() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(
					new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		final Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		SwingUtilities.invokeLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

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
	public void testSortOrder() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(
					new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		final Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		SwingUtilities.invokeLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		// sort Descending
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(EnumTableModel.VALUE_COL);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		waitForSwing();

		assertEquals("0x20", model.getValueAt(0, EnumTableModel.VALUE_COL));
		assertEquals("0x10", model.getValueAt(1, EnumTableModel.VALUE_COL));
		assertEquals("0x0", model.getValueAt(2, EnumTableModel.VALUE_COL));

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
				.getCategory(
					new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		int transactionID = program.startTransaction("Test");
		final Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		SwingUtilities.invokeLater(() -> plugin.edit(enummDt));
		waitForSwing();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

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
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		// select rows 2 and 4 ("Purple" and "Blue")
		table.setRowSelectionInterval(2, 2);
		table.addRowSelectionInterval(4, 4);

		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");
		assertTrue(deleteAction.isEnabled());

		runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
		waitForSwing();
		assertTrue(table.isRowSelected(3));

		final DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());

		runSwing(() -> applyAction.actionPerformed(new ActionContext()));
		program.flushEvents();
		waitForSwing();

		assertEquals(4, model.getRowCount());
		assertEquals(4, enummDt.getCount());
	}

	@Test
	public void testDeleteAllRows() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();
		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
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
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();
		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
			waitForSwing();
		}
		applyChanges(true);
		Window w = windowForComponent(table);
		String str = findLabelStr(w, "Tool Status");

		assertEquals("Empty enum is not allowed", str);
		// add an entry so the tear down works properly
		addEntry(table, model, "test", 1);
	}

	@Test
	public void testCloseEditorWithError() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();
		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
			waitForSwing();
		}

		final ComponentProvider provider =
			waitForComponentProvider(EnumEditorProvider.class);
		assertNotNull(provider);
		SwingUtilities.invokeLater(() -> provider.closeComponent());
		waitForSwing();
		Window w = windowForComponent(table);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		pressButtonByText(d.getComponent(), "Yes");
		waitForSwing();

		assertTrue(tool.isVisible(provider));
		String str = findLabelStr(w, "Tool Status");

		assertEquals("Empty enum is not allowed", str);
		// add an entry so the tear down works properly
		addEntry(table, model, "test", 1);
	}

	@Test
	public void testCloseEditorWithErrorNoSave() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
			waitForSwing();
		}

		final ComponentProvider provider =
			waitForComponentProvider(EnumEditorProvider.class);
		assertNotNull(provider);
		SwingUtilities.invokeLater(() -> provider.closeComponent());
		waitForSwing();
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		pressButtonByText(d.getComponent(), "No");
		waitForSwing();
		assertTrue(!tool.isVisible(provider));
	}

	@Test
	public void testCloseEditorWithErrorCancel() throws Exception {
		Enum enummDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();
		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");

		int count = enummDt.getCount();
		table.setRowSelectionInterval(count - 1, count - 1);

		for (int i = 0; i < count; i++) {

			runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
			waitForSwing();
		}

		final ComponentProvider provider =
			waitForComponentProvider(EnumEditorProvider.class);
		assertNotNull(provider);
		SwingUtilities.invokeLater(() -> provider.closeComponent());
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
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		// select first row ("Red");
		table.setRowSelectionInterval(0, 0);
		final DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");
		assertTrue(deleteAction.isEnabled());

		runSwing(() -> deleteAction.actionPerformed(new ActionContext()));
		waitForSwing();

		assertTrue(table.isRowSelected(0));

		final DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());

		runSwing(() -> applyAction.actionPerformed(new ActionContext()));
		program.flushEvents();
		waitForSwing();

		assertEquals(5, model.getRowCount());
		assertEquals(5, enummDt.getCount());
	}

	@Test
	public void testEditName() throws Exception {
		Enum enummDt = editSampleEnum();

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());

		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Name");
			nameField.setText("MyColors");
		});
		waitForSwing();
		applyChanges(true);
		assertEquals("MyColors", enummDt.getName());
	}

	@Test
	public void testDuplicateName() throws Exception {

		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(
					new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
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
		final Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
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

		assertFalse(getAction(plugin, "Apply Enum Changes").isEnabled());

	}

	@Test
	public void testDuplicateValue() throws Exception {

		editSampleEnum();

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		addEntry(table, model, "MYColor", 3);
		// change value to an existing value
		final int row = model.getRow("MYColor");

		Rectangle rect = table.getCellRect(1, EnumTableModel.VALUE_COL, true);
		clickMouse(table, 1, rect.x, rect.y, 1, 0);

		table.setRowSelectionInterval(row, row);
		SwingUtilities.invokeLater(() -> {
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
		String str = findLabelStr(w, "Tool Status");
//		assertEquals("Colors enum value 0 already assigned", str);
		// duplicate values are now allowed
		assertEquals("", str);
	}

	@Test
	public void testEditDescription() throws Exception {

		Enum enumDt = editSampleEnum();

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTextField descField = getTextField(panel, "Description");
		assertEquals("This is a set of Colors", descField.getText());

		runSwing(() -> descField.setText("My Favorite colors"));
		waitForSwing();
		applyChanges(true);
		assertEquals("My Favorite colors", enumDt.getDescription());

	}

	@Test
	public void testClearDescription() throws Exception {

		Enum enumDt = editSampleEnum();

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTextField descField = getTextField(panel, "Description");

		runSwing(() -> descField.setText(""));
		waitForSwing();
		applyChanges(true);
		assertEquals("", enumDt.getDescription());

	}

	@Test
	public void testMoveColumns() throws Exception {

		editSampleEnum();

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();

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

	@Test
	public void testUndoRedo() throws Exception {

		Enum enumDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// delete a row
		table.setRowSelectionInterval(0, 0);
		runSwing(() -> {
			DockingActionIf action = getAction(plugin, "Delete Enum Value");
			action.actionPerformed(new ActionContext());
		});
		applyChanges(true);
		assertNull(enumDt.getName(0));
		// undo
		undo(program);
		assertEquals("Red", model.getValueAt(0, EnumTableModel.NAME_COL));

		//redo
		redo(program);
		assertEquals("Pink", model.getValueAt(0, EnumTableModel.NAME_COL));
	}

	@Test
	public void testChangesBeforeUndoYes() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		int origRowCount = model.getRowCount();
		runSwing(() -> {
			DockingActionIf action = getAction(plugin, "Add Enum Value");
			action.actionPerformed(new ActionContext());
			action.actionPerformed(new ActionContext());
		});
		waitForSwing();
		applyChanges(true);
		// make more changes
		runSwing(() -> {
			DockingActionIf action = getAction(plugin, "Add Enum Value");
			action.actionPerformed(new ActionContext());
			action.actionPerformed(new ActionContext());
		});
		waitForSwing();
		undo(false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		// yes to reload the enum data type
		final JButton button = findButtonByText(d.getComponent(), "Yes");
		assertNotNull(button);
		runSwing(() -> button.getActionListeners()[0].actionPerformed(null));
		waitForSwing();
		assertEquals(origRowCount, model.getRowCount());
	}

	@Test
	public void testChangesBeforeUndoNo() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			if (lastRow >= 0) {
				table.addRowSelectionInterval(lastRow, lastRow);
			}
			DockingActionIf action = getAction(plugin, "Add Enum Value");
			action.actionPerformed(new ActionContext());
			action.actionPerformed(new ActionContext());
		});
		waitForSwing();
		applyChanges(true);
		// make more changes
		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			if (lastRow >= 0) {
				table.addRowSelectionInterval(lastRow, lastRow);
			}
			DockingActionIf action = getAction(plugin, "Add Enum Value");
			action.actionPerformed(new ActionContext());
			action.actionPerformed(new ActionContext());
		});
		waitForSwing();
		int rowCount = model.getRowCount();
		undo(false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		// not to not reload the enum data type
		final JButton button = findButtonByText(d.getComponent(), "No");
		assertNotNull(button);
		runSwing(() -> button.getActionListeners()[0].actionPerformed(null));
		waitForSwing();
		assertEquals(rowCount, model.getRowCount());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

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

	private void addEntry(final JTable table, final EnumTableModel model, final String name,
			final long value) throws Exception {
		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			if (lastRow >= 0) {
				table.addRowSelectionInterval(lastRow, lastRow);
			}
			DockingActionIf addAction = getAction(plugin, "Add Enum Value");
			addAction.actionPerformed(new ActionContext());
		});
		waitForSwing();
		final int newRow = model.getRowCount() - 1;
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
				model.getValueAt(newRow, EnumTableModel.NAME_COL), true, newRow,
				EnumTableModel.NAME_COL);
			JTextField tf = (JTextField) c;
			tf.setText("0x" + Long.toHexString(value));
			editor.stopCellEditing();
		});
		waitForSwing();
	}

	private void applyChanges(boolean doWait) throws Exception {

		final DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());
		Runnable r = () -> applyAction.actionPerformed(new ActionContext());
		if (doWait) {
			runSwing(r);
			program.flushEvents();
		}
		else {
			SwingUtilities.invokeLater(r);
		}
		waitForSwing();

	}

	private String findLabelStr(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JLabel) {
				if (name.equals(((JLabel) element).getName())) {
					return ((JLabel) element).getText();
				}
			}
			if (element instanceof Container) {
				String str = findLabelStr((Container) element, name);
				if (str != null) {
					return str;
				}
			}
		}
		return null;
	}

	private Enum editSampleEnum() {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(
					new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);
		enumm.add("Purple", 5);
		enumm.add("Turquoise", 0x22);
		enumm.add("Pink", 2);
		enumm.setDescription("This is a set of Colors");

		int transactionID = program.startTransaction("Test");
		final Enum enumDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		SwingUtilities.invokeLater(() -> plugin.edit(enumDt));
		waitForSwing();
		return enumDt;
	}

	private void undo(boolean doWait) throws Exception {
		Runnable r = () -> {
			try {
				program.undo();
				program.flushEvents();
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		};
		if (doWait) {
			runSwing(r);
		}
		else {
			SwingUtilities.invokeLater(r);
		}
		waitForSwing();
	}

}
