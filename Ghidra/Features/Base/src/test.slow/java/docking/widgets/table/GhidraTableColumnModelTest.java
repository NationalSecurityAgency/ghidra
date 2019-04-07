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
package docking.widgets.table;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.*;

import org.jdom.*;
import org.junit.*;

import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.action.DockingActionIf;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesPlugin;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesProvider;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.table.GhidraTable;

public class GhidraTableColumnModelTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String[] COLUMN_NAMES = { "Column 1", "Column 2", "Column 3", "Column 4" };
	private TestEnv env;
	private ProgramDB program;
	private PluginTool tool;
	private LocationReferencesPlugin locationReferencesPlugin;
	private DockingActionIf showReferencesAction;
	private CodeBrowserPlugin codeBrowser;

	/*
	 * Test method for 'setVisible(TableColumn, boolean)' and 'isVisible(TableColumn)'
	 */
	@Test
	public void testSetVisible() {
		TableModel tableModel = createTableModel();
		GhidraTable table = new GhidraTable(tableModel);
		TableColumnModel columnModel = table.getColumnModel();

		assertTrue((columnModel instanceof GTableColumnModel));
		GTableColumnModel ghidraColumnModel = (GTableColumnModel) columnModel;

		List<TableColumn> allColumns = ghidraColumnModel.getAllColumns();
		int columnCount = allColumns.size();
		for (int i = 0; i < columnCount; i++) {
			TableColumn column = allColumns.get(i);
			assertTrue("Column is not visible by default when it should be.",
				ghidraColumnModel.isVisible(column));
		}

		// setVisible()
		for (int i = 0; i < columnCount; i++) {
			TableColumn column = allColumns.get(i);
			ghidraColumnModel.setVisible(column, false);
		}

		for (int i = 0; i < columnCount; i++) {
			TableColumn column = allColumns.get(i);
			assertTrue("Column is visible when it was made hidden.",
				!ghidraColumnModel.isVisible(column));
		}
	}

	@After
	public void tearDown() throws Exception {
		cleanupGhidraWithNotepad();
	}

	/*
	 * Test method for 'addColumn(TableColumn)', 'removeColumn(TableColumn)', 'getColumnCount()',
	 * 'getColumn(int)', 'getColumnIndex(Object)', 'getAllColumns()', and 'getColumns()'
	 */
	@Test
	public void testAddRemoveRetrieveColumns() {
		TableModel tableModel = createTableModel();
		GhidraTable table = new GhidraTable(tableModel);

		// NOTE: we have to make the table visible for the full persistence mechanism to work.  So,
		// perform the tests *before* the table is visible, and then perform them after it has 
		// been made visible
		shakeupTable(table);

		JPanel panel = new JPanel();
		JScrollPane scrollPane = new JScrollPane(table);
		panel.add(scrollPane);
		JFrame frame = new JFrame();

		frame.getContentPane().add(panel);
		frame.setSize(400, 400);
		runSwing(() -> frame.setVisible(true));

		// now try after being visible
		shakeupTable(table);

		frame.setVisible(false);
		frame.dispose();
	}

	@Test
	public void testPersistence() throws Exception {
		// we need a tool in order to get the DockingWindowManager
		loadGhidraWithNotepad();

		// NOTE:  must make sure that the table is visible, or the persistence will not be activated        
		// 010039fe - LAB_010039fe 
		Address address = getAddress(program, 0x010039fe);
		int column = 3;
		assertTrue(codeBrowser.goToField(address, "Label", 0, 0, column));

		// test that the current provider contains the correct location descriptor for a
		// given location
		CodeViewerProvider codeViewerProvider = codeBrowser.getProvider();
		performAction(showReferencesAction, codeViewerProvider, true);

		LocationReferencesProvider provider = findProvider();

		GhidraTable table = getTable(provider);
		waitForTable(table);
		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
		TableColumnModelState columnModelState =
			(TableColumnModelState) TestUtils.getInstanceField("columnModelState", columnModel);

		// get the PreferenceState object associated with the table's column model
		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);

		// we need a lookup key in order to get the correct preference state
		waitForSwing();// make sure we've saved a state
		String preferenceKey = (String) invokeInstanceMethod("getPreferenceKey", columnModelState);
		PreferenceState preferenceState = dockingWindowManager.getPreferenceState(preferenceKey);

		// test moving                    
		// moveColumn() triggers a saveState()
		int columnIndex = 0;
		int newColumnIndex = 1;
		TableColumn originalColumn = columnModel.getColumn(columnIndex);
		moveColumn(columnModel, columnIndex, newColumnIndex);
		waitForSwing();

		// get the updated preference state data        
		preferenceState = dockingWindowManager.getPreferenceState(preferenceKey);
		List<TableColumn> newColumnList =
			getTableColumnsFromPreferencesState(table, preferenceState, columnModelState);
		assertEquals("Moving the column has not triggered the state to be saved.",
			originalColumn.getIdentifier(), newColumnList.get(newColumnIndex).getIdentifier());

		// change the visibility of a column and make sure the change took
		// setVisible() triggers a saveState()
		assertTrue("Column is not visible as expected.", columnModel.isVisible(originalColumn));
		columnModel.setVisible(originalColumn, false);
		waitForSwing();

		preferenceState = dockingWindowManager.getPreferenceState(preferenceKey);
		newColumnList =
			getTableColumnsFromPreferencesState(table, preferenceState, columnModelState);

		cleanupGhidraWithNotepad();
	}

	@Test
	public void testPersistingMultipleSortedColumns() throws Exception {
		// we need a tool in order to get the DockingWindowManager
		loadGhidraWithNotepad();

		// NOTE:  must make sure that the table is visible, or the persistence will not be activated        
		// 010039fe - LAB_010039fe 
		Address address = getAddress(program, 0x010039fe);
		int column = 3;
		assertTrue(codeBrowser.goToField(address, "Label", 0, 0, column));

		// test that the current provider contains the correct location descriptor for a
		// given location
		performAction(showReferencesAction, codeBrowser.getProvider(), true);

		LocationReferencesProvider provider = findProvider();

		// get the save state update manager
		GhidraTable table = getTable(provider);
		waitForTable(table);

		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
		TableColumnModelState columnModelState =
			(TableColumnModelState) TestUtils.getInstanceField("columnModelState", columnModel);

		// get the PreferenceState object associated with the table's column model
		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
		assertNotNull(dockingWindowManager);

		// we need a lookup key in order to get the correct preference state
		waitForSwing();// make sure we've saved a state
		String preferenceKey = (String) invokeInstanceMethod("getPreferenceKey", columnModelState);
		PreferenceState preferenceState =
			getSavedSortStatePreference(preferenceKey, dockingWindowManager);

		// test moving                    
		// moveColumn() triggers a saveState()
		int columnZero = 0;
		int columnOne = 1;

		// verify sorted by default on the 0th column
		AbstractSortedTableModel<?> model = (AbstractSortedTableModel<?>) table.getModel();
		assertEquals(columnZero, model.getPrimarySortColumnIndex());

		TableSortState tableSortState = getSortState(model);
		assertEquals(1, tableSortState.getSortedColumnCount());

		// make sure the preferences has only one sorted column
		TableSortState savedSortState =
			getSortStateFromPreferenceState(preferenceState, columnModelState);
		assertEquals(1, savedSortState.getSortedColumnCount());
		ColumnSortState columnSortState = savedSortState.getColumnSortState(columnZero);
		assertNotNull(columnSortState);
		SortDirection sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());

		// add a second sorted column
		sortByClick(table, columnOne, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
		waitForSwing();// make sure we've saved a state

		tableSortState = getSortState(model);
		assertEquals(2, tableSortState.getSortedColumnCount());
		columnSortState = tableSortState.getColumnSortState(columnZero);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());// sanity check--check the model's data
		columnSortState = tableSortState.getColumnSortState(columnOne);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());

		// now check the saved preferences
		preferenceState = getSavedSortStatePreference(preferenceKey, dockingWindowManager);
		savedSortState = getSortStateFromPreferenceState(preferenceState, columnModelState);

		assertEquals(tableSortState, savedSortState);

		assertEquals(2, savedSortState.getSortedColumnCount());
		columnSortState = savedSortState.getColumnSortState(columnZero);
		assertNotNull(columnSortState);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());

		columnSortState = savedSortState.getColumnSortState(columnOne);
		assertNotNull(columnSortState);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());

		// change direction of primary sort
		sortByClick(table, columnZero, 0);
		waitForSwing();// make sure we've saved a state

		tableSortState = getSortState(model);
		assertEquals(2, tableSortState.getSortedColumnCount());
		columnSortState = tableSortState.getColumnSortState(columnZero);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(!sortDirection.isAscending());// sanity check--check the model's data
		columnSortState = tableSortState.getColumnSortState(columnOne);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());

		// now check the saved preferences
		preferenceState = getSavedSortStatePreference(preferenceKey, dockingWindowManager);
		savedSortState = getSortStateFromPreferenceState(preferenceState, columnModelState);
		assertEquals(2, savedSortState.getSortedColumnCount());
		columnSortState = savedSortState.getColumnSortState(columnZero);
		assertNotNull(columnSortState);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(!sortDirection.isAscending());

		columnSortState = savedSortState.getColumnSortState(columnOne);
		assertNotNull(columnSortState);
		sortDirection = columnSortState.getSortDirection();
		assertTrue(sortDirection.isAscending());

		cleanupGhidraWithNotepad();
	}

	@Test
	public void testPersistingSortedHiddenColumn() throws Exception {
		// we need a tool in order to get the DockingWindowManager
		loadGhidraWithNotepad();

		// NOTE:  must make sure that the table is visible, or the persistence will not be activated        
		// 010039fe - LAB_010039fe 
		Address address = getAddress(program, 0x010039fe);
		int column = 3;
		assertTrue(codeBrowser.goToField(address, "Label", 0, 0, column));

		// test that the current provider contains the correct location descriptor for a
		// given location
		performAction(showReferencesAction, codeBrowser.getProvider(), true);

		// launch the 
		LocationReferencesProvider provider = findProvider();
		GhidraTable table = getTable(provider);
		waitForTable(table);
		TableColumnModel columnModel = table.getColumnModel();
		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		int sortedColumnIndex = sortedModel.getPrimarySortColumnIndex();

		TableColumn sortedColumn = getSortedTableColumn(columnModel, sortedColumnIndex);
		assertNotNull("No table column is sorted.", sortedColumn);

		int newColumnIndex = columnModel.getColumnIndex(sortedColumn.getIdentifier());
		if (newColumnIndex == columnModel.getColumnCount() - 1) {
			newColumnIndex = 0;
		}

		// click the table header to change the column
		JTableHeader tableHeader = table.getTableHeader();
		Rectangle headerRect = tableHeader.getHeaderRect(newColumnIndex);
		clickMouse(tableHeader, MouseEvent.BUTTON3, headerRect.x + 2, headerRect.y + 2, 1, 0);
		waitForPostedSwingRunnables();

		// verify the sort
		int newSortedIndex = sortedModel.getPrimarySortColumnIndex();
		assertEquals("Clicking the column header did not sort the column.", newColumnIndex,
			newSortedIndex);

		// close the provider
		tool.removeComponentProvider(provider);

		// re-show the provider
		performAction(showReferencesAction, codeBrowser.getProvider(), true);
		provider = findProvider();

		// verify the sorted column is the last column we clicked
		table = getTable(provider);
		sortedModel = (SortedTableModel) table.getModel();
		newSortedIndex = sortedModel.getPrimarySortColumnIndex();
		assertEquals("Clicking the column header did not sort the column.", newColumnIndex,
			newSortedIndex);

		cleanupGhidraWithNotepad();
	}

	@Test
	public void testColumnChooserDialog() throws Exception {
		// we need a tool in order to get the DockingWindowManager
		loadGhidraWithNotepad();

		// NOTE:  must make sure that the table is visible, or the persistence will not be activated        
		// 010039fe - LAB_010039fe 
		Address address = getAddress(program, 0x010039fe);
		int column = 3;
		assertTrue(codeBrowser.goToField(address, "Label", 0, 0, column));

		// test that the current provider contains the correct location descriptor for a
		// given location
		performAction(showReferencesAction, codeBrowser.getProvider(), true);

		// launch the 
		LocationReferencesProvider provider = findProvider();
		GhidraTable table = getTable(provider);

		// check the default state
		final GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();

		// show column chooser dialog
		JPopupMenu tableColumnPopupMenu = table.getTableColumnPopupMenu(0);
		MenuElement[] subElements = tableColumnPopupMenu.getSubElements();
		final JMenuItem menuItem = (JMenuItem) subElements[0].getComponent();
		executeOnSwingWithoutBlocking(() -> menuItem.doClick());

		// verify the dialog is showing
		SelectColumnsDialog dialog = waitForDialogComponent(SelectColumnsDialog.class);
		assertNotNull("Column chooser dialog has not been shown.", dialog);
		JTable dialogTable = (JTable) TestUtils.getInstanceField("ghidraTable", dialog);
		final String columnName = dialogTable.getValueAt(0, 1).toString();
		clickTableCell(dialogTable, 0, 0, 1);

		// make sure the item is de-selected
		Boolean isVisible = (Boolean) dialogTable.getValueAt(0, 0);
		assertTrue(
			"The table column was not made visible after clicking the checkbox in the " + "table.",
			!isVisible);

		// press OK
		final JButton okButton = (JButton) TestUtils.getInstanceField("okButton", dialog);
		runSwing(() -> okButton.doClick());
		waitForPostedSwingRunnables();

		// make sure the deselected column from above is now not visible
		runSwing(() -> {
			int columnIndex = columnModel.getColumnIndex(columnName);
			assertEquals("The column was not hidden when deselected from the chooser dialog.", -1,
				columnIndex);
		});

		cleanupGhidraWithNotepad();
	}

//==================================================================================================
// Private methods
//==================================================================================================    

	private void waitForTable(GhidraTable table) {
		int maxWait = 50;
		int waitCount = 0;
		while (!table.isShowing() && waitCount < maxWait) {
			waitCount++;
			sleep(100);
		}
		if (!table.isShowing()) {
			Assert.fail("Table did not become visible!");
		}

		TableModel model = table.getModel();
		if (model instanceof ThreadedTableModel<?, ?>) {
			waitForTableModel((ThreadedTableModel<?, ?>) model);
		}

		waitForSwing();
	}

	private TableSortState getSortState(final AbstractSortedTableModel<?> model) {
		final AtomicReference<TableSortState> ref = new AtomicReference<>();
		runSwing(() -> ref.set(model.getTableSortState()));

		return ref.get();
	}

	private PreferenceState getSavedSortStatePreference(final String preferenceKey,
			final DockingWindowManager dockingWindowManager) {

		waitForSwing();
		final AtomicReference<PreferenceState> ref = new AtomicReference<>();
		runSwing(() -> ref.set(dockingWindowManager.getPreferenceState(preferenceKey)));

		return ref.get();
	}

	private GhidraTable getTable(LocationReferencesProvider provider) {
		Object referencesPanel = TestUtils.getInstanceField("referencesPanel", provider);
		GhidraTable table = (GhidraTable) TestUtils.getInstanceField("table", referencesPanel);
		return table;
	}

	private void sortByClick(JTable table, int columnToClick, int modifiers) throws Exception {
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(columnToClick);
		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, modifiers);
		waitForNotBusy(table);
	}

	private void waitForNotBusy(JTable table) throws Exception {
		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		waitForTableModel(model);
	}

	private void shakeupTable(GhidraTable table) {
		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();

		// test add/remove methods
		ArrayList<TableColumn> columnList = Collections.list(columnModel.getColumns());
		for (TableColumn column : columnList) {
			removeColumn(columnModel, column);

			int columnIndex = columnModel.getColumnIndex(column.getIdentifier());
			assertEquals("The column was not removed as expected.", -1, columnIndex);

			addColumn(columnModel, column);
			columnIndex = columnModel.getColumnIndex(column.getIdentifier());
			assertEquals("Column was not placed at the end of the sequence after a call to " +
				"addColumn().", columnIndex, columnModel.getColumnCount() - 1);
		}

		// test count methods
		assertEquals("getColumns() did not return the same number of columns as getColumnCount()",
			columnList.size(), columnModel.getColumnCount());
		assertEquals(
			"getAllColumns() did not return the same number of columns as getColumnCount()",
			columnList.size(), columnModel.getAllColumns().size());

		// move method
		columnList = Collections.list(columnModel.getColumns());
		for (TableColumn column : columnList) {
			int originalIndex = columnModel.getColumnIndex(column.getIdentifier());
			int newIndex = originalIndex + 1;
			if (originalIndex == columnList.size() - 1) {
				newIndex = 0;// handle the last column case
			}

			moveColumn(columnModel, originalIndex, newIndex);
			assertEquals("Column move was unsuccessful.",
				columnModel.getColumnIndex(column.getIdentifier()), newIndex);

			moveColumn(columnModel, newIndex, originalIndex);
			assertEquals("Column move was unsuccessful.",
				columnModel.getColumnIndex(column.getIdentifier()), originalIndex);
		}

		// getAllColumns() and getColumn(int)
		List<TableColumn> allColumns = columnModel.getAllColumns();
		for (int i = 0; i < allColumns.size(); i++) {
			assertEquals("Columns are out of order.", allColumns.get(i), columnModel.getColumn(i));
		}
	}

	private void moveColumn(final GTableColumnModel columnModel, final int originalIndex,
			final int newIndex) {
		runSwing(() -> columnModel.moveColumn(originalIndex, newIndex));
	}

	private void addColumn(final GTableColumnModel columnModel, final TableColumn column) {
		runSwing(() -> columnModel.addColumn(column));
	}

	private void removeColumn(final GTableColumnModel columnModel, final TableColumn column) {
		runSwing(() -> columnModel.removeColumn(column));
	}

	private TableModel createTableModel() {
		DefaultTableModel tableModel = new DefaultTableModel();

		for (String element : COLUMN_NAMES) {
			tableModel.addColumn(element);
		}

		return tableModel;
	}

	private void loadGhidraWithNotepad() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test", "0x010039f0", 100);
		builder.createLabel("0x010039fe", "Test_Label");

		program = builder.getProgram();

		env = new TestEnv();
		tool = env.launchDefaultTool(program);
		tool.addPlugin(LocationReferencesPlugin.class.getName());
		codeBrowser = getPlugin(tool, CodeBrowserPlugin.class);
		locationReferencesPlugin = getPlugin(tool, LocationReferencesPlugin.class);
		showReferencesAction = (DockingActionIf) TestUtils.getInstanceField("referencesToAction",
			locationReferencesPlugin);
	}

	private void cleanupGhidraWithNotepad() {
		if (env == null) {
			return;
		}

		executeOnSwingWithoutBlocking(() -> {
			env.dispose();
			env = null;
		});

		// this handles the save changes dialog and potential analysis dialogs
		closeAllWindows();
	}

	private List<TableColumn> getTableColumnsFromPreferencesState(GhidraTable table,
			PreferenceState preferenceState, TableColumnModelState columnModelState)
			throws DataConversionException {

		GDynamicColumnTableModel<?, ?> model = (GDynamicColumnTableModel<?, ?>) table.getModel();

		String xmlColumnKey = (String) TestUtils.getInstanceField("XML_COLUMN", columnModelState);
		String xmlElementKey =
			(String) TestUtils.getInstanceField("XML_COLUMN_DATA", columnModelState);
		String xmlColumnNameKey =
			(String) TestUtils.getInstanceField("XML_COLUMN_NAME", columnModelState);
		String xmlColumnWidthKey =
			(String) TestUtils.getInstanceField("XML_COLUMN_WIDTH", columnModelState);
		String xmlColumnVisibleKey =
			(String) TestUtils.getInstanceField("XML_COLUMN_VISIBLE", columnModelState);

		Element xmlElement = preferenceState.getXmlElement(xmlElementKey);
		List<TableColumn> completeList = new ArrayList<>();
		List<?> children = xmlElement.getChildren(xmlColumnKey);
		for (int i = 0; i < children.size(); i++) {
			Element element = (Element) children.get(i);
			String columnName = element.getAttributeValue(xmlColumnNameKey);
			GhidraTableTestColumn column = new GhidraTableTestColumn(i);
			String displayName = getColumnNameByUniqueID(model, columnName);
			column.setIdentifier(displayName);

			Attribute widthAttribute = element.getAttribute(xmlColumnWidthKey);
			int width = widthAttribute.getIntValue();// throws exception
			column.setWidth(width);
			column.setPreferredWidth(width);

			Attribute visibleAttribute = element.getAttribute(xmlColumnVisibleKey);
			boolean visible = visibleAttribute.getBooleanValue();// throws exception
			column.setVisible(visible);
			if (visible) {
				completeList.add(column);
			}
		}

		return completeList;
	}

	private String getColumnNameByUniqueID(VariableColumnTableModel model, String ID) {
		int columnCount = model.getColumnCount();
		for (int i = 0; i < columnCount; i++) {
			String uniqueIdentifier = model.getUniqueIdentifier(i);
			if (uniqueIdentifier.equals(ID)) {
				return model.getColumnDisplayName(i);
			}
		}

		Assert.fail("Unable to find column by ID: " + ID);
		return null;// can't get here
	}

	private TableSortState getSortStateFromPreferenceState(PreferenceState preferenceState,
			TableColumnModelState columnModelState) {
		String xmlElementKey =
			(String) TestUtils.getInstanceField("XML_COLUMN_DATA", columnModelState);
		Element xmlElement = preferenceState.getXmlElement(xmlElementKey);
		return TableSortState.restoreFromXML(xmlElement);
	}

	private Address getAddress(Program p, long offset) {
		AddressFactory addrMap = p.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private LocationReferencesProvider findProvider() {
		List<?> providerList =
			(List<?>) TestUtils.getInstanceField("providerList", locationReferencesPlugin);
		if (providerList.size() == 0) {
			return null;
		}
		return (LocationReferencesProvider) providerList.get(0);
	}

	private TableColumn getSortedTableColumn(TableColumnModel columnModel, int sortedColumnIndex) {
		int columnCount = columnModel.getColumnCount();
		for (int i = 0; i < columnCount; i++) {
			TableColumn tableColumn = columnModel.getColumn(i);
			if (tableColumn.getModelIndex() == sortedColumnIndex) {
				return tableColumn;
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class GhidraTableTestColumn extends TableColumn {
		private boolean visible;

		GhidraTableTestColumn(int modelIndex) {
			super(modelIndex);
		}

		void setVisible(boolean visible) {
			this.visible = visible;
		}

		boolean isVisible() {
			return visible;
		}
	}
}
