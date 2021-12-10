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

import static ghidra.app.plugin.core.datamgr.editor.EnumTableModel.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.TableCellEditor;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import generic.stl.Pair;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.EquateTable;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for editing an Enumerated data type.
 */
public class EnumEditor1Test extends AbstractGhidraHeadedIntegrationTest {

	private Program program;
	private PluginTool tool;
	private TestEnv env;
	private DataTypeManagerPlugin plugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = getPlugin(tool, DataTypeManagerPlugin.class);

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		builder.addCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		program = builder.getProgram();

		env.showTool(program);
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testEnumFields() throws Exception {
		Category c = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(c, "TestEnum", 1);
		edit(enumm);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertNotNull(panel);

		// verify the name field; should be "TestEnum"
		JTextField nameField = getTextField(panel, "Name");
		assertNotNull(nameField);
		assertEquals("TestEnum", nameField.getText());
		assertTrue(nameField.isEditable());

		// description should be "Enumerated data type"
		JTextField descField = getTextField(panel, "Description");
		assertNotNull(descField);
		assertEquals("", descField.getText());
		assertTrue(descField.isEditable());

		// category should be notepad.xml/Category1
		JTextField catField = getTextField(panel, "Category");
		assertNotNull(catField);
		assertEquals("notepad/Category1", catField.getText());
		assertTrue(!catField.isEditable());

		// size should be "1"
		@SuppressWarnings("unchecked")
		JComboBox<Object> sizeComboBox =
			(JComboBox<Object>) getInstanceField("sizeComboBox", panel);
		assertNotNull(sizeComboBox);
		Object selectedItem = sizeComboBox.getSelectedItem();
		int intValue = Integer.parseInt(selectedItem.toString());
		assertEquals(intValue, 1);

		// add action should be enabled
		// apply action should be disabled
		// delete action should be disabled
		DockingActionIf addAction = getAction(plugin, "Add Enum Value");
		assertTrue(addAction.isEnabled());
		DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(!applyAction.isEnabled());
		DockingActionIf deleteAction = getAction(plugin, "Delete Enum Value");
		assertTrue(!deleteAction.isEnabled());

		// sort column should be on the value column
		JTable table = (JTable) findContainer(panel, JTable.class);
		EnumTableModel model = (EnumTableModel) table.getModel();
		assertEquals(VALUE_COL, model.getPrimarySortColumnIndex());
	}

	@Test
	public void testEnumSize1() throws Exception {
		Category category = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(category, "TestEnum", 1);
		edit(enumm);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertNotNull(panel);

		addEnumValue();

		waitForSwing();
		DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());
		assertTrue(panel.needsSave());

		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		assertEquals("New_Name", model.getValueAt(0, NAME_COL));
		assertEquals("0x0", model.getValueAt(0, VALUE_COL));

		addEnumValue();

		assertEquals("New_Name_(1)", model.getValueAt(1, NAME_COL));
		assertEquals("0x1", model.getValueAt(1, VALUE_COL));

		addEnumValue();

		assertEquals("New_Name_(2)", model.getValueAt(2, NAME_COL));
		assertEquals("0x2", model.getValueAt(2, VALUE_COL));

		editValueInTable(1, "0x5");

		// 5 gets moved to the end
		assertEquals("0x5", model.getValueAt(2, VALUE_COL));

		// apply the change
		runSwing(() -> applyAction.actionPerformed(new ActionContext()));
		program.flushEvents();
		waitForSwing();

		Enum en = (Enum) category.getDataType("TestEnum");
		String[] names = en.getNames();
		assertEquals(3, names.length);
		assertEquals(5, en.getValue("New_Name_(1)"));
	}

	@Test
	public void testEnumSize1BadInput() throws Exception {
		// test entering too large a value
		Category category = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(category, "TestEnum", 1);
		edit(enumm);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertNotNull(panel);

		addEnumValue();

		waitForSwing();
		DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());
		assertTrue(panel.needsSave());

		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		assertEquals("New_Name", model.getValueAt(0, NAME_COL));
		assertEquals("0x0", model.getValueAt(0, VALUE_COL));

		addEnumValue();

		String editName = "New_Name_(1)";
		assertEquals(editName, model.getValueAt(1, NAME_COL));
		assertEquals("0x1", model.getValueAt(1, VALUE_COL));

		addEnumValue();

		assertEquals("New_Name_(2)", model.getValueAt(2, NAME_COL));
		assertEquals("0x2", model.getValueAt(2, VALUE_COL));

		int row = getRowFor(editName);

		editValueInTable(row, "0x777");

		row = getRowFor(editName); // the row may have changed if we are sorted on the values col
		assertEquals("0x77", model.getValueAt(row, VALUE_COL));
	}

	@Test
	public void testEnumSize4BadInput() throws Exception {
		Category category = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(category, "MyTestEnum", 4);
		edit(enumm);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertNotNull(panel);

		// size should be "4"
		@SuppressWarnings("unchecked")
		JComboBox<Object> sizeComboBox =
			(JComboBox<Object>) getInstanceField("sizeComboBox", panel);
		assertNotNull(sizeComboBox);
		Object selectedItem = sizeComboBox.getSelectedItem();
		int intValue = Integer.parseInt(selectedItem.toString());
		assertEquals(intValue, 4);

		addEnumValue();
		waitForSwing();
		DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
		assertTrue(applyAction.isEnabled());
		assertTrue(panel.needsSave());

		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		assertEquals("New_Name", model.getValueAt(0, NAME_COL));
		assertEquals("0x0", model.getValueAt(0, VALUE_COL));

		addEnumValue();

		String editName = "New_Name_(1)";
		assertEquals(editName, model.getValueAt(1, NAME_COL));
		assertEquals("0x1", model.getValueAt(1, VALUE_COL));

		addEnumValue();

		assertEquals("New_Name_(2)", model.getValueAt(2, NAME_COL));
		assertEquals("0x2", model.getValueAt(2, VALUE_COL));

		int row = getRowFor(editName);

		editValueInTable(row, "0xfff777777");

		row = getRowFor(editName); // the row may have changed if we are sorted on the values col
		assertEquals("0xfff77777", model.getValueAt(row, VALUE_COL));
	}

	@Test
	public void testBadInputForValue() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(cat, "TestEnum", 1);
		edit(enumm);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();

		addEnumValue();
		waitForSwing();

		table.addRowSelectionInterval(0, 0);
		Rectangle rect = table.getCellRect(0, VALUE_COL, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);

		final TableCellEditor editor = table.getCellEditor(0, VALUE_COL);
		Component c = getEditorComponent(editor);
		triggerText(c, "r");
		waitForSwing();

		runSwing(() -> editor.stopCellEditing());
		assertEquals("0x0", model.getValueAt(0, VALUE_COL));
	}

	@Test
	public void testEditExistingEnum1() throws Exception {

		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);

		int transactionID = program.startTransaction("Test");
		final Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// change entry Name  Blue to Cyan
		String newValue = "Cyan";
		editNameInTable(2, newValue);

		assertEquals(newValue, model.getValueAt(2, NAME_COL));
		assertEquals(newValue, panel.getEnum().getName(2));

		apply();

		Enum en = (Enum) cat.getDataType("Colors");
		try {
			en.getValue("Blue");
			Assert.fail("Should not have found Blue!");
		}
		catch (NoSuchElementException e) {
			// expected
		}
		assertEquals(2, en.getValue("Cyan"));
	}

	@Test
	public void testEditExistingEnum2() throws Exception {
		// add a new entry

		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();
		addEntry(table, model, "Purple", 7);

		apply();

		Category cat =
			program.getListing().getDataTypeManager().getCategory(enummDt.getCategoryPath());
		Enum en = (Enum) cat.getDataType("Colors");
		String[] names = en.getNames();
		assertEquals(4, names.length);
		assertEquals(7, en.getValue("Purple"));
	}

	@Test
	public void testValueForNewEntry() throws Exception {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0x10);
		enumm.add("Green", 0x20);
		enumm.add("Blue", 0x30);

		int transactionID = program.startTransaction("Test");
		final Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		final JTable table = panel.getTable();
		final EnumTableModel model = (EnumTableModel) table.getModel();
		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			table.addRowSelectionInterval(lastRow, lastRow);
			DockingActionIf addAction = getAction(plugin, "Add Enum Value");
			addAction.actionPerformed(new ActionContext());
		});
		waitForSwing();

		assertEquals("0x31", model.getValueAt(3, VALUE_COL));
	}

	@Test
	public void testExternalValueUpdate() throws Exception {
		// verify that the editor updates when a new value is added or
		// existing entry is changed
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		int transactionID = program.startTransaction("Test");
		enummDt.add("Yellow", 10);
		enummDt.add("Magenta", 5);

		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		Enum en = getEnum(model);

		assertEquals(10, en.getValue("Yellow"));
		assertEquals(5, en.getValue("Magenta"));

		transactionID = program.startTransaction("Test");
		enummDt.remove("Red");
		enummDt.add("Red", 25);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		en = model.getEnum();
		assertEquals(25, en.getValue("Red"));
		assertEquals("Red", model.getValueAt(model.getRowCount() - 1, NAME_COL));
	}

	@Test
	public void testExternalValueAndNameUpdate() throws Exception {
		// verify that the editor updates when a new value is added or
		// existing entry is changed
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		int transactionID = program.startTransaction("Test");
		enummDt.add("Yellow", 10);
		enummDt.add("Magenta", 5);

		// note: this tests triggers a code path for updating the name that relies upon the name
		//       being edited *after* new values are added above.
		String oldName = enummDt.getName();
		String newName = oldName + "_updated";
		enummDt.setName(newName);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		Enum en = getEnum(model);

		assertEquals(10, getValue(en, "Yellow"));
		assertEquals(5, getValue(en, "Magenta"));
		assertEquals(newName, en.getName());
	}

	@Test
	public void testExternalNameUpdate() throws Exception {
		// verify that the editor updates when a new value is added or
		// existing entry is changed
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		int transactionID = program.startTransaction("Test");
		String oldName = enummDt.getName();
		String newName = oldName + "_updated";
		enummDt.setName(newName);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		Enum en = getEnum(model);
		assertEquals(newName, en.getName());
	}

	@Test
	public void testExternalNameUpdateWithEditorChange() throws Exception {
		//
		// verify that the editor DOES NOT update when the name is externally changed
		//
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());

		String editorName = "EditorNameChange";
		setEditorEnumName(panel, editorName);

		int transactionID = program.startTransaction("Test");
		String oldName = enummDt.getName();
		String newName = oldName + "_updated";
		enummDt.setName(newName);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		String currentEditorName = getEditorEnumName(panel);
		assertEquals(editorName, currentEditorName);
	}

	@Test
	public void testCategoryRemoved() throws Exception {
		//
		// Removing a category triggers the disposal of the editor due to the data type being
		// deleted.
		//
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		removeCategory(enummDt);

		close(waitForInfoDialog());
	}

	@Test
	public void testCategoryMoved() throws Exception {

		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		Category newCategory = moveCategory(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertEquals("Category not updated on a move", newCategory.toString(),
			getEditorCategoryText(panel));
	}

	@Test
	public void testCategoryRenamed() throws Exception {
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		Category newCategory = renameCategory(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertEquals("Category not updated on a rename", newCategory.toString(),
			getEditorCategoryText(panel));
	}

	@Test
	public void testDataTypeReplaced() throws Exception {
		//
		// Replacing a data type triggers the disposal of the editor.
		//
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		Enum newEnummDt = createReplacementEnum(enummDt);

		replaceDataType(enummDt, newEnummDt);

		close(waitForInfoDialog());
	}

	@Test
	public void testDataTypeMoved() throws Exception {
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		String newCategoryPath = "/Test/New/Path";
		setCategoryPath(enummDt, newCategoryPath);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		String editorCategoryText = getEditorCategoryText(panel);
		assertTrue("Category not updated on a move", editorCategoryText.endsWith(newCategoryPath));
	}

	@Test
	public void testExternalDescriptionUpdate() throws Exception {
		// verify that the editor updates when a new value is added or
		// existing entry is changed
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		int transactionID = program.startTransaction("Test");
		String newDescription = "My new description";
		enummDt.setDescription(newDescription);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		Enum en = getEnum(model);
		assertEquals(newDescription, en.getDescription());
	}

	@Test
	public void testExternalRemove() throws Exception {
		Enum enummDt = createRedGreenBlueEnum();
		edit(enummDt);

		DataTypeManager dtm = program.getDataTypeManager();
		int transactionID = program.startTransaction("Test");
		dtm.remove(enummDt, TaskMonitor.DUMMY);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		close(waitForInfoDialog());
	}

	@Test
	public void testEditClonedEnum() throws Exception {
		Enum enummDt = createRedGreenBlueEnum();

		DataTypeManager dtm = program.getListing().getDataTypeManager();
		enummDt = (Enum) enummDt.clone(dtm);

		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();
		addEntry(table, model, "Purple", 7);

		apply();

		DataType conflict = dtm.getDataType(new DataTypePath(enummDt.getCategoryPath(),
			enummDt.getName() + DataType.CONFLICT_SUFFIX));
		assertNull(conflict);
	}

	@Test
	public void testEditNavigateNextPrevious() throws Exception {
		Enum enummDt = createRedGreenBlueEnum();

		DataTypeManager dtm = program.getListing().getDataTypeManager();
		enummDt = (Enum) enummDt.clone(dtm);

		edit(enummDt);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();

		//
		// First, let's try forward then backward
		//
		int startRow = 1;
		int startCol = 0;
		TableCellEditor editor = startEditTableCell(table, startRow, startCol);
		Component c = getEditorComponent(editor);

		triggerActionKey(c, 0, KeyEvent.VK_TAB);
		editor = assertEditingCell(table, startRow, startCol + 1);
		c = getEditorComponent(editor);

		triggerActionKey(c, 0, KeyEvent.VK_TAB);
		editor = assertEditingCell(table, startRow, startCol + 2);
		c = getEditorComponent(editor);

		triggerActionKey(c, InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
		editor = assertEditingCell(table, startRow, startCol + 1);
		c = getEditorComponent(editor);

		triggerActionKey(c, InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
		editor = assertEditingCell(table, startRow, startCol);
		c = getEditorComponent(editor);

		//
		// Now, let's try going around the world and back
		//
		int lastRow = 2;
		int lastCol = 2;
		editor = startEditTableCell(table, lastRow, lastCol);
		c = getEditorComponent(editor);

		triggerActionKey(c, 0, KeyEvent.VK_TAB);

		editor = assertEditingCell(table, 0, 0);
		c = getEditorComponent(editor);

		triggerActionKey(c, InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);

		assertEditingCell(table, lastRow, lastCol);
	}

	@Test
	public void testEditNavigationUpDown() {
		Enum enummDt = createRedGreenBlueEnum();

		DataTypeManager dtm = program.getListing().getDataTypeManager();
		enummDt = (Enum) enummDt.clone(dtm);

		edit(enummDt);

		JTable table = getEditTable();

		//
		// First, let's try up and down
		//
		int startRow = 0;
		int startCol = 0;
		TableCellEditor editor = startEditTableCell(table, startRow, startCol);
		Component c = getEditorComponent(editor);

		triggerActionKey(c, 0, KeyEvent.VK_DOWN);

		editor = assertEditingCell(table, 1, startCol);
		c = getEditorComponent(editor);

		triggerActionKey(c, 0, KeyEvent.VK_UP);

		editor = assertEditingCell(table, startRow, startCol);
		c = getEditorComponent(editor);

		//
		// Now, let's try going around the world and back
		//
		int lastRow = 2;
		startEditTableCell(table, lastRow, startCol);
		triggerActionKey(c, 0, KeyEvent.VK_DOWN);

		editor = assertEditingCell(table, 0, startCol);
		c = getEditorComponent(editor);

		triggerActionKey(c, 0, KeyEvent.VK_UP);

		assertEditingCell(table, lastRow, startCol);
	}

	@Test
	public void testNewEnumFromAction() throws Exception {
		//
		// This test works differently that the others in that it uses the same path as the
		// GUI action to start the editing process.
		//
		DataTypeManager dtm = program.getListing().getDataTypeManager();
		final Category c = dtm.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		final DataTypeEditorManager editorManager = plugin.getEditorManager();

		runSwing(() -> editorManager.createNewEnum(c));
		waitForSwing();

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		addEntry(table, model, "Purple", 7);
		setEditorEnumName(panel, "Test." + testName.getMethodName());

		apply();
	}

	@Test
	public void testChangeEnumSizeAndInStructure() throws Exception {

		Category category = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(category, "EnumX", 2);

		int transactionID = program.startTransaction("Test");
		try {
			enumm.add("Zero", 0);
			enumm.add("One", 1);

			Structure structX = new StructureDataType("StructX", 0);
			structX.setPackingEnabled(true);
			structX.add(new ByteDataType());
			structX.add(enumm);
			structX.add(new ByteDataType());
			category.addDataType(structX, DataTypeConflictHandler.DEFAULT_HANDLER);

			Structure structY = new StructureDataType("StructY", 0);
			structY.setPackingEnabled(false);
			structY.add(new ByteDataType());
			structY.add(enumm);
			category.addDataType(structY, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		edit(enumm);

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertNotNull(panel);

		// size should be "2"
		@SuppressWarnings("unchecked")
		JComboBox<Object> sizeComboBox =
			(JComboBox<Object>) getInstanceField("sizeComboBox", panel);
		assertNotNull(sizeComboBox);
		Object selectedItem = sizeComboBox.getSelectedItem();
		int intValue = Integer.parseInt(selectedItem.toString());
		assertEquals(intValue, 2);

		runSwing(() -> {
			sizeComboBox.setSelectedItem(4);
		});
		apply();

		// size should be "4"
		selectedItem = sizeComboBox.getSelectedItem();
		intValue = Integer.parseInt(selectedItem.toString());
		assertEquals(intValue, 4);

		Structure structX = (Structure) category.getDataType("StructX");
		assertTrue(structX.isPackingEnabled());
		assertEquals(3, structX.getNumComponents());
		assertEquals(1, structX.getComponent(0).getLength());
		assertEquals(4, structX.getComponent(1).getLength());
		assertEquals(1, structX.getComponent(2).getLength());
		assertEquals(12, structX.getLength());

		Structure structY = (Structure) category.getDataType("StructY");
		assertFalse(structY.isPackingEnabled());
		assertEquals(2, structY.getNumComponents());
		assertEquals(1, structY.getComponent(0).getLength());
		assertEquals(4, structY.getComponent(1).getLength());
		assertEquals(5, structY.getLength());
	}

	@Test
	public void testChangeEnumDescriptionEtcAndInStructure() throws Exception {

		Category category = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		Enum enumm = createEnum(category, "EnumX", 2);

		int transactionID = program.startTransaction("Test");
		try {
			enumm.add("Zero", 0);
			enumm.add("One", 1);
			enumm.setDescription("ABCD");

			Structure structX = new StructureDataType("StructX", 0);
			structX.setPackingEnabled(true);
			structX.add(new ByteDataType());
			structX.add(enumm);
			structX.add(new ByteDataType());
			category.addDataType(structX, DataTypeConflictHandler.DEFAULT_HANDLER);

			Structure structY = new StructureDataType("StructY", 0);
			structY.setPackingEnabled(false);
			structY.add(new ByteDataType());
			structY.add(enumm);
			category.addDataType(structY, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		edit(enumm);

		final EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		assertNotNull(panel);
		final JTable table = panel.getTable();

		// size should be "2"
		final JTextField nameField = (JTextField) getInstanceField("nameField", panel);
		assertNotNull(nameField);
		String name = nameField.getText();

		final JTextField descField = (JTextField) getInstanceField("descField", panel);
		assertNotNull(descField);
		String description = descField.getText();

		@SuppressWarnings("unchecked")
		JComboBox<Object> sizeComboBox =
			(JComboBox<Object>) getInstanceField("sizeComboBox", panel);
		assertNotNull(sizeComboBox);
		Object selectedItem = sizeComboBox.getSelectedItem();
		int size = Integer.parseInt(selectedItem.toString());

		assertEquals("EnumX", name);
		assertEquals("ABCD", description);
		assertEquals(2, size);

		runSwing(() -> {
			nameField.setText("EnumY");
			descField.setText("XYZ");
			sizeComboBox.setSelectedItem(4);

			table.editCellAt(1, NAME_COL);

			TableCellEditor editor = table.getCellEditor(1, NAME_COL);

			Component c = getEditorComponent(editor);
			JTextField tf = (JTextField) c;
			// change the name for value of 1.
			tf.setText("Single");
			editor.stopCellEditing();
		});
		apply();

		// name=EnumY, description=XYZ, size=4, Components=[Zero 0, Single 1]
		Enum enumX = (Enum) category.getDataType("EnumX");
		assertNull(enumX);
		Enum enumY = (Enum) category.getDataType("EnumY");
		assertNotNull(enumY);
		assertEquals("XYZ", enumY.getDescription());
		assertEquals(4, enumY.getLength());
		assertEquals(2, enumY.getCount());
		long value0 = enumY.getValue("Zero");
		try {
			enumY.getValue("One");
			Assert.fail("Not expecting One to still be there.");
		}
		catch (NoSuchElementException e) {
			// This exception is expected
		}
		long value1 = enumY.getValue("Single");
		assertEquals(0, value0);
		assertEquals(1, value1);

		Structure structX = (Structure) category.getDataType("StructX");
		assertTrue(structX.isPackingEnabled());
		assertEquals(3, structX.getNumComponents());
		assertEquals(1, structX.getComponent(0).getLength());
		assertEquals(4, structX.getComponent(1).getLength());
		assertEquals(1, structX.getComponent(2).getLength());
		assertEquals(12, structX.getLength());

		Structure structY = (Structure) category.getDataType("StructY");
		assertFalse(structY.isPackingEnabled());
		assertEquals(2, structY.getNumComponents());
		assertEquals(1, structY.getComponent(0).getLength());
		assertEquals(4, structY.getComponent(1).getLength());
		assertEquals(5, structY.getLength());
	}

	@Test
	public void testEquateFieldChanged_Warning_SaveAndRemove() throws Exception {
		doTestFieldChangedWithWarning(true);
	}

	@Test
	public void testEquateFieldChanged_Warning_Save() throws Exception {
		doTestFieldChangedWithWarning(false);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void setCategoryPath(Enum enummDt, String newCategoryPath) throws Exception {
		int txID = program.startTransaction("Test Create Enum");
		try {
			enummDt.setCategoryPath(new CategoryPath(newCategoryPath));
		}
		finally {
			program.endTransaction(txID, true);
		}

		program.flushEvents();
		waitForSwing();
	}

	private Enum createReplacementEnum(Enum enummDt) throws Exception {
		DataTypeManager dtm = enummDt.getDataTypeManager();
		Enum newEnummDt = (Enum) enummDt.copy(dtm);

		int txID = program.startTransaction("Test Create Enum");
		try {
			newEnummDt.setName("ReplacementEnum");
			newEnummDt.add("NewValue", 100);
		}
		finally {
			program.endTransaction(txID, true);
		}

		program.flushEvents();
		waitForSwing();

		return newEnummDt;
	}

	private void replaceDataType(Enum enummDt, Enum newEnummDt) throws Exception {
		DataTypeManager dtm = enummDt.getDataTypeManager();

		int txID = program.startTransaction("Test Create Enum");
		try {
			dtm.replaceDataType(enummDt, newEnummDt, true);
		}
		finally {
			program.endTransaction(txID, true);
		}

		program.flushEvents();
		waitForSwing();
	}

	private Category renameCategory(Enum enummDt) throws Exception {
		DataTypeManager dtm = enummDt.getDataTypeManager();

		Category category = null;
		int txID = program.startTransaction("Test Create Category");
		try {
			category = dtm.getCategory(enummDt.getCategoryPath());
			category.setName("NewName");
		}
		finally {
			program.endTransaction(txID, true);
		}

		program.flushEvents();
		waitForSwing();

		return category;
	}

	private Category moveCategory(Enum enummDt) throws Exception {

		DataTypeManager dtm = enummDt.getDataTypeManager();

		Category category = null;
		int txID = program.startTransaction("Test Create Category");
		try {
			Category newCategory = dtm.createCategory(new CategoryPath("/Test/Category"));
			category = dtm.getCategory(enummDt.getCategoryPath());
			newCategory.moveCategory(category, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txID, true);
		}

		program.flushEvents();
		waitForSwing();

		return category;
	}

	private void removeCategory(Enum enummDt) throws Exception {
		DataTypeManager dtm = enummDt.getDataTypeManager();

		int txID = program.startTransaction("Test Create Category");
		try {
			Category category = dtm.getCategory(enummDt.getCategoryPath());
			Category parentCategory = category.getParent();
			assertTrue("Did not remove category",
				parentCategory.removeCategory(category.getName(), TaskMonitor.DUMMY));
		}
		finally {
			program.endTransaction(txID, true);
		}

		program.flushEvents();
		waitForSwing();
	}

	private long getValue(Enum en, String fieldName) {
		try {
			return en.getValue(fieldName);
		}
		catch (NoSuchElementException e) {
			Assert.fail("Enum does not contain field: " + fieldName + ".\nCurrent fields for " +
				en.getName() + ": " + getFieldNames(en));
			return -1;// can't get here
		}
	}

	private String getFieldNames(Enum en) {
		StringBuilder buffy = new StringBuilder();
		String[] names = en.getNames();
		for (String name : names) {
			buffy.append("\n    ");
			buffy.append(name);
		}
		return buffy.toString();
	}

	private void setEditorEnumName(final EnumEditorPanel panel, final String name) {
		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Name");
			nameField.setText(name);
		});
		waitForSwing();
	}

	private String getEditorEnumName(final EnumEditorPanel panel) {
		final AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> {
			JTextField nameField = getTextField(panel, "Name");
			ref.set(nameField.getText());
		});
		return ref.get();
	}

	private String getEditorCategoryText(final EnumEditorPanel panel) {
		final AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> {
			JTextField field = getTextField(panel, "Category");
			ref.set(field.getText());
		});
		return ref.get();
	}

	private Enum getEnum(final EnumTableModel model) {
		final AtomicReference<Enum> ref = new AtomicReference<>();
		runSwing(() -> ref.set(model.getEnum()));
		return ref.get();
	}

	private TableCellEditor startEditTableCell(final JTable table, final int startRow,
			final int startCol) {
		runSwing(() -> {
			table.changeSelection(startRow, startCol, false, false);
			table.editCellAt(startRow, startCol);
		});

		assertEditingCell(table, startRow, startCol);
		return runSwing(() -> table.getCellEditor());
	}

	private TableCellEditor assertEditingCell(final JTable table, final int row, final int col) {
		Pair<Integer, Integer> rowCol = getEditingCell(table);
		assertEquals("Not editing expected row", row, (int) rowCol.first);
		assertEquals("Not editing expected column", col, (int) rowCol.second);
		return runSwing(() -> table.getCellEditor());
	}

	private Pair<Integer, Integer> getEditingCell(final JTable table) {
		final AtomicReference<Pair<Integer, Integer>> ref = new AtomicReference<>();
		runSwing(() -> {
			int editingRow = table.getEditingRow();
			int editingColumn = table.getEditingColumn();
			ref.set(new Pair<>(editingRow, editingColumn));
		});
		return ref.get();
	}

	private Enum createRedGreenBlueEnum() {
		Category cat = program.getListing()
				.getDataTypeManager()
				.getCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		final Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);
		enumm.setDescription("Red Green Blue Enum");

		int transactionID = program.startTransaction("Test");
		Enum enummDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		return enummDt;
	}

	private void edit(final Enum enummDt) {
		waitForSwing();
		SwingUtilities.invokeLater(() -> plugin.edit(enummDt));
		waitForSwing();
	}

	private void apply() {
		runSwing(() -> {
			DockingActionIf applyAction = getAction(plugin, "Apply Enum Changes");
			applyAction.actionPerformed(new ActionContext());
		}, false);
		program.flushEvents();
		waitForSwing();
	}

	private Enum createEnum(Category c, String name, int size) {
		Enum dt = new EnumDataType(name, size);
		int transactionID = program.startTransaction("Test");
		Enum enummDt = (Enum) c.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
		program.endTransaction(transactionID, true);
		return enummDt;
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
		addEnumValue();
		waitForSwing();
		final int row = model.getRowCount() - 1;
		// change entry
		table.addRowSelectionInterval(row, row);
		Rectangle rect = table.getCellRect(row, NAME_COL, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);

		runSwing(() -> {
			TableCellEditor editor = table.getCellEditor(row, NAME_COL);
			Component c = editor.getTableCellEditorComponent(table, model.getValueAt(row, NAME_COL),
				true, row, NAME_COL);
			JTextField tf = (JTextField) c;
			tf.setText(name);
			editor.stopCellEditing();
		});
		waitForSwing();
		rect = table.getCellRect(row, VALUE_COL, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);

		runSwing(() -> {
			TableCellEditor editor = table.getCellEditor(row, VALUE_COL);

			Component c = getEditorComponent(editor);
			JTextField tf = (JTextField) c;
			tf.setText("0x" + Long.toHexString(value));
			editor.stopCellEditing();
		});
		waitForSwing();
	}

	private JTable getEditTable() {
		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		return table;
	}

	private void doTestFieldChangedWithWarning(boolean alsoRemove) throws Exception {

		Enum enoom = createRedGreenBlueEnum();
		String formattedEqName = EquateManager.formatNameForEquate(enoom.getUniversalID(), 0);
		createEquate(formattedEqName);

		edit(enoom);

		editValueInTable(0, "2");

		// This IS the warning dialog
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, alsoRemove ? "Save and remove" : "Save");
		waitForTasks();

		EquateTable et = program.getEquateTable();
		if (alsoRemove) {
			assertNull(et.getEquate(formattedEqName));
		}
		else {
			assertNotNull(et.getEquate(formattedEqName));
		}
	}

	private void editValueInTable(int row, String newValue) {

		editCellInTable(row, VALUE_COL, newValue);
	}

	private void editNameInTable(int row, String newValue) {

		editCellInTable(row, NAME_COL, newValue);
	}

	private void editCellInTable(int row, int col, String newValue) {

		JTable table = getEditTable();
		startEditTableCell(table, row, col);
		TableCellEditor editor = runSwing(() -> table.getCellEditor());
		Component c = getEditorComponent(editor);
		triggerText(c, newValue);
		triggerActionKey(c, 0, KeyEvent.VK_ENTER);
		apply();
	}

	private Component getEditorComponent(TableCellEditor editor) {
		if (editor instanceof Component) {
			return (Component) editor;
		}
		else if (editor instanceof DefaultCellEditor) {
			return ((DefaultCellEditor) editor).getComponent();
		}
		fail("Could not find editor component");
		return null;
	}

	private void createEquate(String name) throws Exception {
		EquateTable et = program.getEquateTable();

		int id = program.startTransaction("test");
		et.createEquate(name, 0);
		program.endTransaction(id, true);
	}

	private void addEnumValue() {
		runSwing(() -> {
			DockingActionIf addAction = getAction(plugin, "Add Enum Value");
			addAction.actionPerformed(new ActionContext());
		});
	}

	private int getRowFor(String theName) {

		JTable table = getEditTable();
		int rows = table.getRowCount();
		for (int i = 0; i < rows; i++) {
			String name = (String) table.getValueAt(i, NAME_COL);
			if (name.equals(theName)) {
				return i;
			}
		}

		fail("Could not find row for '" + theName + "'");
		return -1; // can't get here
	}

}
