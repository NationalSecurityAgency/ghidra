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
package ghidra.app.plugin.core.symtable;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.table.*;

import org.jdom.Element;
import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.filter.*;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;
import ghidra.util.SystemUtilities;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.ProgramTableModel;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.xml.XmlUtilities;

public class SymbolTablePluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin browser;
	private SymbolTablePlugin plugin;
	private DockingActionIf viewSymAction;
	private DockingActionIf viewRefAction;
	private DockingActionIf deleteAction;
	private DockingActionIf makeSelectionAction;
	private DockingActionIf setPinnedAction;
	private DockingActionIf clearPinnedAction;
	private DockingActionIf setFilterAction;
	private ProgramDB prog;
	private GTable symbolTable;
	private SymbolTableModel symbolModel;
	private JTableHeader symbolTableHeader;
	private GTable referenceTable;
	private GhidraTableFilterPanel<SymbolRowObject> filterPanel;
	private SymbolProvider provider;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		tool = env.getTool();
		configureTool(tool);

		browser = env.getPlugin(CodeBrowserPlugin.class);
		plugin = env.getPlugin(SymbolTablePlugin.class);
		provider = (SymbolProvider) getInstanceField("symProvider", plugin);

		viewSymAction = getAction(plugin, "View Symbol Table");
		viewRefAction = getAction(plugin, "View Symbol References");
		deleteAction = getAction(plugin, "Delete Symbols");
		makeSelectionAction = getAction(plugin, "Make Selection");
		setFilterAction = getAction(plugin, "Set Filter");
		setPinnedAction = getAction(plugin, "Pin Symbol");
		clearPinnedAction = getAction(plugin, "Clear Pinned Symbol");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testNavigation() throws Exception {
		openProgram("notepad");
		int row = findRow("ghidra", "Global");

		TableModel model = symbolTable.getModel();
		doubleClick(symbolTable, row, SymbolTableModel.LOCATION_COL);
		ProgramLocation pl = getProgramLocation(row, SymbolTableModel.LOCATION_COL, model);
		assertEquals(pl.getAddress(), browser.getCurrentAddress());
	}

	@Test
	public void testSortingLabelColumn() throws Exception {
		openProgram("notepad");

		Rectangle rect = symbolTableHeader.getHeaderRect(SymbolTableModel.LABEL_COL);

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		TableColumn column =
			symbolTableHeader.getColumnModel().getColumn(SymbolTableModel.LABEL_COL);
		GTableHeaderRenderer renderer = (GTableHeaderRenderer) column.getHeaderRenderer();
		assertTrue(renderer.isSortedAscending());

		TableModel model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Symbol sym1 = (Symbol) model.getValueAt(i + 0, SymbolTableModel.LABEL_COL);
			Symbol sym2 = (Symbol) model.getValueAt(i + 1, SymbolTableModel.LABEL_COL);
			int compare = sym1.getName().compareToIgnoreCase(sym2.getName());
			assertTrue("row " + i + " not sorted correctly", (compare < 0 || compare == 0));
		}

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);
		assertTrue(!renderer.isSortedAscending());

		model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Symbol sym1 = (Symbol) model.getValueAt(i + 0, SymbolTableModel.LABEL_COL);
			Symbol sym2 = (Symbol) model.getValueAt(i + 1, SymbolTableModel.LABEL_COL);
			int compare = sym1.getName().compareToIgnoreCase(sym2.getName());
			assertTrue("row " + i + " not sorted correctly", (compare > 0 || compare == 0));
		}
	}

	@Test
	public void testColumnDiscovery() throws Exception {
		//
		// Note: this is somewhat of a tripwire test--it is designed to catch a major breakage
		//       to the DynamicTableColumn discovery mechanism.
		//
		openProgram("notepad");

		List<String> columnNames = new ArrayList<>();
		int columnCount = symbolModel.getColumnCount();
		for (int i = 0; i < columnCount; i++) {
//			Msg.debug(this, "found column: " + symbolModel.getColumnName(i));
			columnNames.add(symbolModel.getColumnName(i));
		}

		assertTrue(columnNames.contains("Name"));
		assertTrue(columnNames.contains("Location"));
		assertTrue(columnNames.contains("Symbol Type"));
		assertTrue(columnNames.contains("Data Type"));
		assertTrue(columnNames.contains("Namespace"));
		assertTrue(columnNames.contains("Source"));
		assertTrue(columnNames.contains("Reference Count"));
		assertTrue(columnNames.contains("Offcut Ref Count"));
		assertTrue(columnNames.contains("Offcut Reference Count"));
		assertTrue(columnNames.contains("Mem Block"));
		assertTrue(columnNames.contains("Reference Count"));
		assertTrue(columnNames.contains("Mem Type"));
		assertTrue(columnNames.contains("Label"));
		assertTrue(columnNames.contains("Location"));
		assertTrue(columnNames.contains("Namespace"));
		assertTrue(columnNames.contains("Label"));
		assertTrue(columnNames.contains("Function Name"));
		assertTrue(columnNames.contains("Byte Count"));
		assertTrue(columnNames.contains("Preview"));
		assertTrue(columnNames.contains("Bytes"));
	}

	@Test
	public void testSortingAddressColumn() throws Exception {
		openProgram("notepad");

		Rectangle rect = symbolTableHeader.getHeaderRect(SymbolTableModel.LOCATION_COL);

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		TableColumn column =
			symbolTableHeader.getColumnModel().getColumn(SymbolTableModel.LOCATION_COL);
		GTableHeaderRenderer renderer = (GTableHeaderRenderer) column.getHeaderRenderer();
		assertTrue(renderer.isSortedAscending());

		SymbolTableModel model = (SymbolTableModel) symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			AddressBasedLocation refs1 =
				(AddressBasedLocation) model.getValueAt(i + 0, SymbolTableModel.LOCATION_COL);
			AddressBasedLocation refs2 =
				(AddressBasedLocation) model.getValueAt(i + 1, SymbolTableModel.LOCATION_COL);
			assertTrue(refs1.compareTo(refs2) <= 0);
		}

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);
		assertTrue(!renderer.isSortedAscending());

		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			AddressBasedLocation refs1 =
				(AddressBasedLocation) model.getValueAt(i + 0, SymbolTableModel.LOCATION_COL);
			AddressBasedLocation refs2 =
				(AddressBasedLocation) model.getValueAt(i + 1, SymbolTableModel.LOCATION_COL);
			assertTrue(refs1.compareTo(refs2) >= 0);
		}
	}

	@Test
	public void testSortingReferenceColumn() throws Exception {
		openProgram("notepad");

		sortOnColumn(SymbolTableModel.REFS_COL);

		TableColumn column =
			symbolTableHeader.getColumnModel().getColumn(SymbolTableModel.REFS_COL);
		GTableHeaderRenderer renderer = (GTableHeaderRenderer) column.getHeaderRenderer();
		assertTrue(renderer.isSortedAscending());

		TableModel model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Integer refs1 = (Integer) model.getValueAt(i + 0, SymbolTableModel.REFS_COL);
			Integer refs2 = (Integer) model.getValueAt(i + 1, SymbolTableModel.REFS_COL);
			assertTrue(refs1.compareTo(refs2) <= 0);
		}

		sortOnColumn(SymbolTableModel.REFS_COL);
		assertTrue(!renderer.isSortedAscending());

		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Integer refs1 = (Integer) model.getValueAt(i + 0, SymbolTableModel.REFS_COL);
			Integer refs2 = (Integer) model.getValueAt(i + 1, SymbolTableModel.REFS_COL);
			assertTrue(refs1.compareTo(refs2) >= 0);
		}
	}

	@Test
	public void testFilter() throws Exception {
		openProgram("notepad");

		performAction(setFilterAction, new ActionContext(), false);
		waitForSwing();

		final FilterDialog filterDialog1 = waitForDialogComponent(FilterDialog.class);
		assertNotNull(filterDialog1);

		final NewSymbolFilter filter = new NewSymbolFilter();
		turnOffAllFilterTypes(filter);
		filter.setFilter("Function Labels", true);
		runSwing(() -> filterDialog1.setFilter(filter));

		pressButtonByText(filterDialog1, "OK");
		waitForSwing();
		waitForNotBusy(symbolTable);

		//
		// Functions: 'ghidra', 'func_with_parms'
		//
		assertEquals(2, symbolTable.getRowCount());

		FilterDialog filterDialog2 = showFilterDialog();
		runSwing(() -> {
			final NewSymbolFilter newFilter = new NewSymbolFilter();
			turnOffAllFilterTypes(newFilter);
			newFilter.setFilter("Instruction Labels", true);
			newFilter.setFilter("Data Labels", true);
			newFilter.setFilter("Function Labels", true);
			newFilter.setFilter("Entry Points", true);
			filterDialog2.setFilter(newFilter);

		});

		pressButtonByText(filterDialog2, "OK");
		waitForSwing();
		waitForNotBusy(symbolTable);

		//
		// Entry Points: 'entry'
		//
		assertEquals(1, symbolTable.getRowCount());

		showFilterDialog();

		final FilterDialog filterDialog3 = showFilterDialog();
		runSwing(() -> {
			final NewSymbolFilter newFilter = new NewSymbolFilter();
			turnOffAllFilterTypes(newFilter);
			newFilter.setFilter("Instruction Labels", true);
			newFilter.setFilter("Data Labels", true);
			newFilter.setFilter("Locals", true);
			filterDialog2.setFilter(newFilter);
		});
		pressButtonByText(filterDialog3, "OK");
		waitForSwing();
		waitForNotBusy(symbolTable);

		//
		// Locals: 'AnotherLocal', 'MyLocal'
		//
		assertEquals(2, symbolTable.getRowCount());
	}

	private FilterDialog showFilterDialog() {

		performAction(setFilterAction, false);

		FilterDialog dialog = waitForDialogComponent(FilterDialog.class);
		assertNotNull(dialog);
		return dialog;
	}

	@Test
	public void testFilterPersistence() throws Exception {

		NewSymbolFilter filter = new NewSymbolFilter();
		Element element = filter.saveToXml();
		String defaultXml = XmlUtilities.toString(element);

		changeSomeFilterSettings(filter);
		Element changedElement = filter.saveToXml();
		String savedXml = XmlUtilities.toString(changedElement);
		Assert.assertNotEquals(defaultXml, savedXml);

		NewSymbolFilter newFilter = new NewSymbolFilter();
		Element newDefaultElement = newFilter.saveToXml();
		String newDefaultXml = XmlUtilities.toString(newDefaultElement);
		assertEquals(defaultXml, newDefaultXml); // sanity check

		newFilter.restoreFromXml(changedElement);
		String restoredXml = XmlUtilities.toString(changedElement);
		assertEquals(savedXml, restoredXml);
	}

	private void changeSomeFilterSettings(NewSymbolFilter filter) {
		//
		// Change different filter types and values.  (This requires some guilty knowledge).
		//
		// Symbol type name and default state: 
		// 
		// Symbol Types: 
		// 		Label filters:  instruction (active), data (active), function (active) 
		//      Non-label filters: namespaces, classes, params, etc (all inactive)
		// 
		// Advanced filters: externals, globals, entry points, locals, etc (all inactive)
		//
		// Symbol Source Types: user defined (active), imported (active), 
		//  		default label (inactive), default function, analysis (active) 
		//

		boolean active = true;
		boolean inactive = false;
		filter.setFilter("User Defined", inactive);
		filter.setFilter("Default (Labels)", active);

		filter.setFilter("Function Labels", inactive);

		filter.setFilter("Local Variables", active);

		filter.setFilter("Register Variables", active);
		filter.setFilter("Subroutines", active);
		filter.setFilter("Non-Primary Labels", active);
	}

	@Test
	public void testEditing() throws Exception {
		openProgram("notepad");

		waitForNotBusy(symbolTable);

		int row = findRow("ghidra", "Global");

		doubleClick(symbolTable, row, SymbolTableModel.LABEL_COL);
		waitForSwing();
		assertTrue(symbolTable.isEditing());

		Component editor = symbolTable.getEditorComponent();
		assertNotNull(editor);
		JTextField textField = (JTextField) editor;
		triggerActionKey(textField, 0, KeyEvent.VK_END);
		myTypeText(editor, ".Is.Cool");
		runSwing(() -> symbolTable.editingStopped(new ChangeEvent(symbolTable)));

		waitForNotBusy(symbolTable);

		assertTrue(!symbolTable.isEditing());

		Symbol s = (Symbol) symbolTable.getValueAt(row, SymbolTableModel.LABEL_COL);
		assertEquals("ghidra.Is.Cool", s.getName());
	}

	@Test
	public void testQuickLookup() throws Exception {
		openProgram("notepad");

		int id = prog.startTransaction(testName.getMethodName());
		try {
			Address sample = prog.getMinAddress();
			SymbolTable st = prog.getSymbolTable();
			st.createLabel(sample.getNewAddress(0x01008100), "_", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008100), "a", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008200), "ab", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008300), "abc", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008400), "abc1", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008500), "abc123", SourceType.USER_DEFINED);
		}
		finally {
			prog.endTransaction(id, true);
		}

		waitForNotBusy(symbolTable);

		runSwing(() -> symbolTable.setRowSelectionInterval(0, 0));

		triggerAutoLookup("a");
		waitForNotBusy(symbolTable);
		assertEquals(findRow("a", "Global"), symbolTable.getSelectedRow());
		Thread.sleep(GTable.KEY_TIMEOUT);

		triggerAutoLookup("ab");
		waitForNotBusy(symbolTable);
		assertEquals(findRow("ab", "Global"), symbolTable.getSelectedRow());
		Thread.sleep(GTable.KEY_TIMEOUT);

		triggerAutoLookup("abc");
		waitForNotBusy(symbolTable);
		assertEquals(findRow("abc", "Global"), symbolTable.getSelectedRow());
		Thread.sleep(GTable.KEY_TIMEOUT);

		triggerAutoLookup("abcd");
		waitForNotBusy(symbolTable);
		assertEquals(findRow("abc1", "Global"), symbolTable.getSelectedRow());
		Thread.sleep(GTable.KEY_TIMEOUT);

		runSwing(() -> symbolTable.setRowSelectionInterval(0, 0));
		waitForSwing();
		triggerAutoLookup("abc12");
		waitForNotBusy(symbolTable);
		assertEquals(findRow("abc123", "Global"), symbolTable.getSelectedRow());
	}

	@Test
	public void testDeleting() throws Exception {
		openProgram("notepad");

		int rowCount = symbolTable.getRowCount();
		assertTrue(!deleteAction.isEnabled());

		final int row = findRow("ghidra", "Global");
		Rectangle rect = symbolTable.getCellRect(row, 0, true);
		symbolTable.scrollRectToVisible(rect);
		singleClick(symbolTable, row, 0);

		assertTrue(deleteAction.isEnabled());
		performAction(deleteAction, true);

		waitForNotBusy(symbolTable);

		assertNull(getUniqueSymbol(prog, "ghidra"));
		Symbol myLocalSymbol = getUniqueSymbol(prog, "MyLocal");
		assertNotNull(myLocalSymbol);// MyLocal should have been promoted to global since user defined.
		assertEquals(SourceType.USER_DEFINED, myLocalSymbol.getSource());
		assertEquals(prog.getGlobalNamespace(), myLocalSymbol.getParentNamespace());
		Symbol anotherLocalSymbol = getUniqueSymbol(prog, "AnotherLocal");
		assertNotNull(anotherLocalSymbol);// AnotherLocal should have been promoted to global since user defined.
		assertEquals(SourceType.USER_DEFINED, anotherLocalSymbol.getSource());
		assertEquals(prog.getGlobalNamespace(), anotherLocalSymbol.getParentNamespace());

		// 1 Function label removed (1 dynamic added at function entry)
		// Locals were promoted to global.
		assertEquals(rowCount, symbolTable.getRowCount());

		final int anotherLocal_RowIndex = findRow("AnotherLocal", "Global");
		runSwing(() -> symbolTable.setRowSelectionInterval(anotherLocal_RowIndex,
			anotherLocal_RowIndex));

		int selectedRow = symbolTable.getSelectedRow();
		assertEquals("Row was not selected!", anotherLocal_RowIndex, selectedRow);

		waitForSwing();

		performAction(deleteAction, true);
		anotherLocalSymbol = getUniqueSymbol(prog, "AnotherLocal");
		assertNull("Delete action did not delete symbol: " + anotherLocalSymbol,
			anotherLocalSymbol);// AnotherLocal should have been promoted to global since user defined.

		waitForNotBusy(symbolTable);

		// 1 Data label removed
		int expected = rowCount - 1;
		assertEquals(expected, symbolTable.getRowCount());
		assertEquals("Symbol Table (Filter settings matched " + expected + " Symbols)",
			plugin.getSymbolProvider().getName() + " " + plugin.getSymbolProvider().getSubTitle());
	}

	@Test
	public void testDeleteParamter_ForSCR_7892() throws Exception {
		openProgram("login");
		Address addr = addr("0x100");

		// grab the test symbol from the symbol table database and make sure it exists
		FunctionManager functionManager = prog.getFunctionManager();

		Function function = functionManager.getFunctionContaining(addr);
		Symbol param1Symbol = getUniqueSymbol(prog, "param_1", function);

		assertNotNull("Could not find param_1 in function", param1Symbol);

		setupSymbolTableFilterToShowParameters();

		final int row = getRowForSymbol(param1Symbol);

		// select that row
		runSwing(() -> symbolTable.setRowSelectionInterval(row, row));

		// execute the delete action
		performAction(deleteAction, true);
		Assert.assertNotEquals(param1Symbol, getUniqueSymbol(prog, "param_1", function));
	}

	@Test
	public void testMakeSelection() throws Exception {
		openProgram("notepad");

		assertTrue(!makeSelectionAction.isEnabled());

		final int row = findRow("ghidra", "Global");
		int rowCount = 3;
		runSwing(() -> {
			symbolTable.setRowSelectionInterval(row, row + 2);
			Rectangle rect = symbolTable.getCellRect(row + 2, 0, true);
			symbolTable.scrollRectToVisible(rect);
		});

		assertTrue(makeSelectionAction.isEnabled());

		int[] selectedRows = symbolTable.getSelectedRows();
		assertEquals(rowCount, selectedRows.length);

		performAction(makeSelectionAction, true);
		waitForSwing();

		ProgramSelection sel = browser.getCurrentSelection();

		assertEquals(rowCount, sel.getNumAddressRanges());

		Address sample = prog.getMinAddress();

		long address = 0x52;
		assertTrue("Selection does not contain address: " + address + " - selection: " + sel,
			sel.contains(sample.getNewAddress(address)));
		address = 0x21;
		assertTrue("Selection does not contain address: " + address + " - selection: " + sel,
			sel.contains(sample.getNewAddress(address)));
		address = 0x58;
		assertTrue("Selection does not contain address: " + address + " - selection: " + sel,
			sel.contains(sample.getNewAddress(address)));

	}

	@Test
	public void testSetAndClearPinnedAction() throws Exception {
		openProgram("notepad");

		final int row = findRow("ADVAPI32.dll_IsTextUnicode", "Global");
		runSwing(() -> {
			symbolTable.setRowSelectionInterval(row, row + 2);
			Rectangle rect = symbolTable.getCellRect(row + 2, 0, true);
			symbolTable.scrollRectToVisible(rect);
		});
		ActionContext actionContext = provider.getActionContext(null);
		int[] selectedRows = symbolTable.getSelectedRows();
		assertEquals(3, selectedRows.length);
		for (int selectedRow : selectedRows) {
			Symbol symbol = (Symbol) symbolTable.getValueAt(selectedRow, 0);
			assertTrue(!symbol.isPinned());
		}
		assertTrue(setPinnedAction.isEnabledForContext(actionContext));
		assertTrue(!clearPinnedAction.isEnabledForContext(actionContext));

		performAction(setPinnedAction, actionContext, true);
		waitForSwing();
		for (int selectedRow : selectedRows) {
			Symbol symbol = (Symbol) symbolTable.getValueAt(selectedRow, 0);
			assertTrue(symbol.isPinned());
		}

		performAction(clearPinnedAction, actionContext, true);
		waitForSwing();
		for (int selectedRow : selectedRows) {
			Symbol symbol = (Symbol) symbolTable.getValueAt(selectedRow, 0);
			assertTrue(!symbol.isPinned());
		}

	}

	@Test
	public void testSetPinnedActionNotEnabledForExternalSymbols() throws Exception {
		openProgram("notepad");

		final int row = findRow("CharLowerW", "USER32.dll");
		runSwing(() -> {
			symbolTable.setRowSelectionInterval(row, row + 1);
			Rectangle rect = symbolTable.getCellRect(row + 1, 0, true);
			symbolTable.scrollRectToVisible(rect);
		});
		ActionContext actionContext = provider.getActionContext(null);
		int[] selectedRows = symbolTable.getSelectedRows();

		for (int selectedRow : selectedRows) {
			Symbol symbol = (Symbol) symbolTable.getValueAt(selectedRow, 0);
			assertTrue(!symbol.isPinned());
		}
		assertTrue(!setPinnedAction.isEnabledForContext(actionContext));
		assertTrue(!clearPinnedAction.isEnabledForContext(actionContext));

	}

	@Test
	public void testUpdateOnSymbolsAdded() throws Exception {
		openProgram("notepad");
		Address sample = prog.getMinAddress();
		SymbolTable st = prog.getSymbolTable();
		Symbol sym = null;
		int rowCount = symbolTable.getRowCount();
		int id = prog.startTransaction(testName.getMethodName());
		try {
			sym = st.createLabel(sample.getNewAddress(0x01007000), "Zeus", SourceType.USER_DEFINED);
			waitForNotBusy(symbolTable);
			assertEquals(rowCount + 1, symbolTable.getRowCount());
			assertTrue(symbolModel.getRowIndex(new SymbolRowObject(sym.getID())) >= 0);

			sym =
				st.createLabel(sample.getNewAddress(0x01007100), "Athena", SourceType.USER_DEFINED);
			waitForNotBusy(symbolTable);
			assertEquals(rowCount + 2, symbolTable.getRowCount());
			assertTrue(symbolModel.getRowIndex(new SymbolRowObject(sym.getID())) >= 0);
		}
		finally {
			prog.endTransaction(id, true);
		}
	}

	@Test
	public void testSymbolsAddedWithFilterOn() throws Exception {
		openProgram("notepad");

		final JTextField textField = getFilterTextField();
		final JCheckBox checkBox = findComponent(filterPanel, JCheckBox.class);

		// =====================
		// case insensitive
		// =====================
		boolean caseSensitive = checkBox.isSelected();
		if (caseSensitive) {
			runSwing(() -> checkBox.doClick());
		}

		myTypeText(textField, "s");
		int rowCount = symbolModel.getRowCount();

		Address sample = prog.getMinAddress();
		SymbolTable st = prog.getSymbolTable();
		Symbol sym = null;
		int id = prog.startTransaction(testName.getMethodName());
		try {
			sym =
				st.createLabel(sample.getNewAddress(0x01007000), "saaaa", SourceType.USER_DEFINED);
			waitForNotBusy(symbolTable);
			assertTrue(symbolModel.getRowIndex(new SymbolRowObject(sym.getID())) >= 0);
		}
		finally {
			prog.endTransaction(id, true);
		}

		waitForNotBusy(symbolTable);
		assertEquals(rowCount + 1, symbolModel.getRowCount());// make sure we added one while the filter is on
	}

	@Test
	public void testDefaultFunctionToNamedFunctionWithFilterOn() throws Exception {
		openProgram("notepad");

		performAction(setFilterAction, new ActionContext(), false);
		waitForSwing();

		final FilterDialog filterDialog1 = waitForDialogComponent(FilterDialog.class);
		assertNotNull(filterDialog1);

		final NewSymbolFilter filter = new NewSymbolFilter();
		filter.setFilter("Function Labels", true);
		filter.setFilter("Default (Functions)", false);
		runSwing(() -> filterDialog1.setFilter(filter));

		pressButtonByText(filterDialog1, "OK");
		waitForSwing();
		waitForNotBusy(symbolTable);

		//
		// Functions: 'ghidra', 'func_with_parms'
		//
		assertEquals(22, symbolTable.getRowCount());

		Symbol symbol = getUniqueSymbol(prog, "ghidra");
		setName(symbol, null, SourceType.DEFAULT);
		assertEquals(21, symbolTable.getRowCount());

		setName(symbol, "foobar", SourceType.USER_DEFINED);
		assertEquals(22, symbolTable.getRowCount());

	}

	@Test
	public void testUpdateOnSymbolsRemoved() throws Exception {
		openProgram("notepad");

		SymbolTable st = prog.getSymbolTable();
		Symbol sym = getUniqueSymbol(prog, "entry");
		assertNull(getUniqueSymbol(prog, "EXT_00000051"));

		int id = prog.startTransaction(testName.getMethodName());
		try {
			st.removeSymbolSpecial(sym);
		}
		finally {
			prog.endTransaction(id, true);
		}
		waitForNotBusy(symbolTable);

		// entry symbol replaced by dynamic External Entry symbol
		assertNull(getUniqueSymbol(prog, "entry"));
		assertNotNull(getUniqueSymbol(prog, "EXT_00000051"));
		assertTrue(symbolModel.getRowIndex(new SymbolRowObject(sym.getID())) == -1);
	}

	@Test
	public void testUpdateOnReferencesAdded() throws Exception {
		openProgram("notepad");
		Address sample = prog.getMinAddress();

		Symbol s = getUniqueSymbol(prog, "entry");

		int row = symbolModel.getRowIndex(new SymbolRowObject(s.getID()));
		Integer refCount = (Integer) symbolTable.getValueAt(row, SymbolTableModel.REFS_COL);
		assertNotNull(refCount);
		assertEquals(3, refCount.intValue());

		ReferenceManager rm = prog.getReferenceManager();
		int id = prog.startTransaction(testName.getMethodName());
		try {
			Reference ref = rm.addMemoryReference(sample.getNewAddress(0x01004203),
				sample.getNewAddress(0x51), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
			rm.setPrimary(ref, true);
		}
		finally {
			prog.endTransaction(id, true);
		}
		waitForNotBusy(symbolTable);

		row = symbolModel.getRowIndex(new SymbolRowObject(s.getID()));

		refCount = (Integer) symbolTable.getValueAt(row, SymbolTableModel.REFS_COL);
		assertNotNull(refCount);
		assertEquals(4, refCount.intValue());
	}

	@Test
	public void testUpdateOnReferencesRemoved() throws Exception {
		openProgram("notepad");
		Address sample = prog.getMinAddress();

		Symbol s = getUniqueSymbol(prog, "doStuff");

		int row = symbolModel.getRowIndex(new SymbolRowObject(s.getID()));

		Integer refCount = (Integer) symbolTable.getValueAt(row, SymbolTableModel.REFS_COL);
		assertNotNull(refCount);
		assertEquals(4, refCount.intValue());

		ReferenceManager rm = prog.getReferenceManager();
		Reference[] refs = rm.getReferencesFrom(sample.getNewAddress(0x01004aea));
		Address toAddr = sample.getNewAddress(0x50);
		Reference ref = null;
		for (Reference element : refs) {
			if (toAddr.equals(element.getToAddress())) {
				ref = element;
				break;
			}
		}
		if (ref == null) {
			Assert.fail("Did not find expected mem reference!");
		}
		int id = prog.startTransaction(testName.getMethodName());
		try {
			rm.delete(ref);
		}
		finally {
			prog.endTransaction(id, true);
		}
		waitForNotBusy(symbolTable);

		refCount = (Integer) symbolTable.getValueAt(row, SymbolTableModel.REFS_COL);
		assertNotNull(refCount);
		assertEquals(3, refCount.intValue());
	}

	@Test
	public void testUpdateOnProgramRestore() throws Exception {
		openProgram("notepad");

		int id = prog.startTransaction(testName.getMethodName());
		try {
			ClearCmd cmd = new ClearCmd(prog.getMemory(), new ClearOptions());
			tool.execute(cmd, prog);
			waitForBusyTool(tool);
		}
		finally {
			prog.endTransaction(id, true);
		}
		waitForNotBusy(symbolTable);

		// Externals are not cleared

		assertEquals(3, symbolTable.getRowCount());

		undo(prog);
		waitForNotBusy(symbolTable);

		assertEquals(24, symbolTable.getRowCount());

		redo(prog);
		waitForNotBusy(symbolTable);

		assertEquals(3, symbolTable.getRowCount());
	}

	@Test
	public void testBigProgram() throws Exception {
		openProgram("winword.exe");
		showFilterDialog();

		final FilterDialog filterDialog = waitForDialogComponent(FilterDialog.class);
		assertNotNull(filterDialog);
		runSwing(() -> {
			final NewSymbolFilter filter = new NewSymbolFilter();
			turnOffAllFilterTypes(filter);
			filter.setFilter("Function Labels", true);
			filterDialog.setFilter(filter);

		});

		pressButtonByText(filterDialog, "OK");
		waitForSwing();
		waitForNotBusy(symbolTable);
		waitForSwing();
	}

	@Test
	public void testSegmentedProgram() throws Exception {
		openProgram("winhelp");

		/************** LABEL **********************/

		Rectangle rect = symbolTableHeader.getHeaderRect(SymbolTableModel.LABEL_COL);

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		TableColumn column =
			symbolTableHeader.getColumnModel().getColumn(SymbolTableModel.LABEL_COL);
		GTableHeaderRenderer renderer = (GTableHeaderRenderer) column.getHeaderRenderer();
		assertTrue(renderer.isSortedAscending());

		TableModel model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Symbol sym1 = (Symbol) model.getValueAt(i + 0, SymbolTableModel.LABEL_COL);
			Symbol sym2 = (Symbol) model.getValueAt(i + 1, SymbolTableModel.LABEL_COL);
			int compare = sym1.getName().compareToIgnoreCase(sym2.getName());
			assertTrue("Symbol \"" + sym1 + "\" is not sorted as less than symbol \"" + sym2 + "\"",
				compare <= 0);
		}

		/************** ADDRESS **********************/

		rect = symbolTableHeader.getHeaderRect(SymbolTableModel.LOCATION_COL);

		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		column = symbolTableHeader.getColumnModel().getColumn(SymbolTableModel.LOCATION_COL);
		renderer = (GTableHeaderRenderer) column.getHeaderRenderer();
		assertTrue(renderer.isSortedAscending());

		model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			AddressBasedLocation loc1 =
				(AddressBasedLocation) model.getValueAt(i, SymbolTableModel.LOCATION_COL);
			AddressBasedLocation loc2 =
				(AddressBasedLocation) model.getValueAt(i + 1, SymbolTableModel.LOCATION_COL);
			int compare = SystemUtilities.compareTo(loc1, loc2);
			assertTrue(
				"Location1 \"" + loc1 + "\"is not sorted as less than location2 \"" + loc2 + "\"",
				compare <= 0);
		}

		/************** REFERENCES **********************/

		rect = symbolTableHeader.getHeaderRect(SymbolTableModel.REFS_COL);
		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);

		column = symbolTableHeader.getColumnModel().getColumn(SymbolTableModel.REFS_COL);
		renderer = (GTableHeaderRenderer) column.getHeaderRenderer();
		assertTrue(renderer.isSortedAscending());

		model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Integer refs1 = (Integer) model.getValueAt(i + 0, SymbolTableModel.REFS_COL);
			Integer refs2 = (Integer) model.getValueAt(i + 1, SymbolTableModel.REFS_COL);
			assertTrue(
				"The number of references (\"" + refs1 + "\") for row did not " +
					"compare as less than the number for the following row (\"" + refs2 + "\")",
				refs1.compareTo(refs2) <= 0);
		}
	}

	@Test
	public void testReferences() throws Exception {
		openProgram("notepad");

		showReferencesTable();

		singleClick(symbolTable, findRow("ghidra", "Global"), SymbolTableModel.LABEL_COL);

		/*****************************/

		DockingActionIf refsToAction = getAction(plugin, "References To");
		assertNotNull(refsToAction);
		performAction(refsToAction, true);
		waitForSwing();

		waitForNotBusy(symbolTable);
		waitForNotBusy(referenceTable);
		assertEquals(4, referenceTable.getRowCount());

		assertReferencesAddressColumnValue(0, 0x54);
		assertReferencesAddressColumnValue(1, 0x1004100);
		assertReferencesAddressColumnValue(2, 0x1004101);
		assertReferencesAddressColumnValue(3, 0x1004bea);

		// from refs
		/*****************************/

		ToggleDockingAction instFromAction =
			(ToggleDockingAction) getAction(plugin, "Instruction References From");
		assertNotNull(instFromAction);
		performAction(instFromAction, true);

		waitForSwing();

		waitForNotBusy(symbolTable);
		waitForNotBusy(referenceTable);
		assertEquals(3, referenceTable.getRowCount());

		assertReferencesAddressColumnValue(0, 0x53);
		assertReferencesAddressColumnValue(1, 0x54);
		assertReferencesAddressColumnValue(2, 0x55);

		// data refs
		/*****************************/

		ToggleDockingAction dataFromAction =
			(ToggleDockingAction) getAction(plugin, "Data References From");
		assertNotNull(dataFromAction);
		performAction(dataFromAction, true);

		waitForSwing();

		waitForNotBusy(symbolTable);
		waitForNotBusy(referenceTable);
		assertEquals(2, referenceTable.getRowCount());

		// data
		assertReferencesAddressColumnValue(0, 0x56);
		assertReferencesAddressColumnValue(1, 0x57);
	}

	@Test
	public void testFilterTextField() throws Exception {
		openProgram("notepad");

		JTextField textField = getFilterTextField();

		int fullRowCount = symbolModel.getRowCount();

		setupSymbolTableFilterOnName(true);

		//
		//
		// 'starts with' filter; case insensitive
		//
		//
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);

		String text = "_";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatchesIgnoringCase(text);

		deleteTextFieldText(textField);
		assertEquals("The symbol table model do not properly filter its contents with no " +
			"text in the filter text field.", fullRowCount, symbolModel.getRowCount());

		text = "ent";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatchesIgnoringCase(text);

		deleteText(textField, true, true);

		// no matches
		text = "entx";
		myTypeText(textField, text);
		assertTrue("There is unexpected matching filtered data in the table model.",
			(symbolModel.getRowCount() == 0));
		deleteText(textField);

		// call backspace to delete all chars
		deleteTextFieldText(textField);
		assertEquals("The symbol table model do not properly filter its contents with no " +
			"text in the filter text field.", fullRowCount, symbolModel.getRowCount());

		myTypeText(textField, "ad*api");// matches "advapi"

		text = "advapi";
		modelMatchesIgnoringCase(text);

		deleteText(textField);

		// sort on a different column to trigger the other kind of filtering
		sortOnColumn(SymbolTableModel.REFS_COL);

		text = "_";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatchesIgnoringCase(text);

		deleteTextFieldText(textField);
		assertEquals("The symbol table model do not properly filter its contents with no " +
			"text in the filter text field.", fullRowCount, symbolModel.getRowCount());

		text = "ent";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatchesIgnoringCase(text);

		deleteText(textField, true, true);

		//
		//
		// 'starts with' filter; case sensitive
		//
		//
		setFilterOptions(TextFilterStrategy.STARTS_WITH, true);

		text = "_";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatches(text);

		deleteTextFieldText(textField);
		assertEquals("The symbol table model do not properly filter its contents with no " +
			"text in the filter text field.", fullRowCount, symbolModel.getRowCount());

		text = "USER";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatches(text);

		deleteText(textField, true, false);

		// no matches
		text = "ENTX";
		myTypeText(textField, text);
		assertTrue("There is unexpected matching filtered data in the table model.",
			(symbolModel.getRowCount() == 0));

		deleteText(textField);

		// test regex text
		myTypeText(textField, "_*");
		modelMatches("_");

		// call backspace twice to delete both chars
		deleteTextFieldText(textField);
		assertEquals("The symbol table model do not properly filter its contents with no " +
			"text in the filter text field.", fullRowCount, symbolModel.getRowCount());

		String typedText = "C*ar";
		myTypeText(textField, typedText);// matches "Char"

		text = "Char";
		modelMatches(text);

		deleteText(textField);

		// sort on a different column to trigger the other kind of filtering
		sortOnColumn(SymbolTableModel.LOCATION_COL);

		text = "_";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatches(text);

		deleteTextFieldText(textField);
		assertEquals("The symbol table model do not properly filter its contents with no " +
			"text in the filter text field.", fullRowCount, symbolModel.getRowCount());

		text = "USER";
		myTypeText(textField, text);

		// make sure the model has been filtered
		modelMatches(text);

		deleteText(textField, true, false);
	}

	@Test
	public void testFilterTextFieldFindsAllMatches() throws Exception {
		openProgram("notepad");

		JTextField textField = getFilterTextField();

		// setup labels in the program for matching
		waitForNotBusy(symbolTable);
		int rowCount = symbolTable.getRowCount();

		addLabel("bob", null, addr("010058f6"));

		addLabel("bob", "billy", addr("01005917"));
		waitForNotBusy(symbolTable);

		int updatedRowCount = symbolTable.getRowCount();
		assertEquals(rowCount + 2, updatedRowCount);

		// test ascending
		runSwing(() -> TableUtils.columnSelected(symbolTable, 0));
		waitForNotBusy(symbolTable);

		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);

		myTypeText(textField, "bo");
		waitForNotBusy(symbolTable);

		// make sure both 'bob's are in the table
		assertEquals("Did not find two bobs.", 2, symbolTable.getRowCount());
		modelMatchesIgnoringCase("bob");

		myTypeText(textField, "b");
		waitForNotBusy(symbolTable);

		assertEquals("Did not find two bobs.", 2, symbolTable.getRowCount());
		modelMatchesIgnoringCase("bob");

		// test descending
		runSwing(() -> TableUtils.columnSelected(symbolTable, 0));
		waitForNotBusy(symbolTable);

		assertEquals("Did not find two bobs in descending order.", 2, symbolTable.getRowCount());
		modelMatchesIgnoringCase("bob");
	}

//==================================================================================================
// Helper methods
//==================================================================================================

	private void triggerAutoLookup(String text) {

		KeyListener listener = (KeyListener) getInstanceField("autoLookupListener", symbolTable);

		BiConsumer<Component, KeyEvent> consumer = (c, e) -> {
			if (e.getID() != KeyEvent.KEY_PRESSED) {
				return;
			}
			runSwing(() -> listener.keyPressed(e));
		};

		// use the version of triggerText that allows us to consume the event directly, bypassing
		// the focus system
		triggerText(symbolTable, text, consumer);
	}

	private void setName(Symbol symbol, String name, SourceType type) throws Exception {
		int startTransaction = prog.startTransaction("Test");
		try {
			symbol.setName(name, SourceType.DEFAULT);
		}
		finally {
			prog.endTransaction(startTransaction, true);
		}
		waitForSwing();
		waitForNotBusy(symbolTable);

	}

	private void assertReferencesAddressColumnValue(int row, long value) {
		Address addr =
			(Address) referenceTable.getValueAt(row, SymbolReferenceModel.ADDRESS_COLUMN);
		assertEquals("Address in row " + row + " is not the expected value", value,
			addr.getOffset());
	}

	private void sortOnColumn(int column) throws Exception {
		Rectangle rect = symbolTableHeader.getHeaderRect(column);
		clickMouse(symbolTableHeader, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy(symbolTable);
	}

	private void deleteText(JTextField field) throws Exception {
		deleteText(field, false, false);
	}

	private void deleteText(JTextField field, boolean validate, boolean ignoreCase)
			throws Exception {

		if (!validate) {
			setText(field, "");
			return;
		}

		String text = getText(field);
		while (text.length() > 0) {
			text = text.substring(0, text.length() - 1);
			typeBackspaceOnComponent(field);

			if (!validate) {
				continue;
			}

			if (ignoreCase) {
				modelMatchesIgnoringCase(text);
			}
			else {
				modelMatches(text);
			}
		}
	}

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean caseSensitive) {
		filterPanel.setFilterOptions(new FilterOptions(filterStrategy, true, caseSensitive, false));
		waitForTable();

	}

	private void waitForTable() {
		waitForSwing();
	}

	private JTextField getFilterTextField() {
		FilterTextField filterField =
			(FilterTextField) getInstanceField("filterField", filterPanel);
		return (JTextField) getInstanceField("textField", filterField);
	}

	private void setupSymbolTableFilterOnName(boolean state) {

		final JCheckBox checkBox =
			(JCheckBox) findComponentByName(provider.getComponent(), "NameOnly");

		runSwing(() -> checkBox.setSelected(state));

		waitForPostedSwingRunnables();
	}

	private void setupSymbolTableFilterToShowParameters() throws Exception {
		// get the filter action -  "Set Filter"
		List<DockingActionIf> actions =
			tool.getDockingActionsByFullActionName("Set Filter (SymbolTablePlugin)");
		assertNotNull(actions);
		assertTrue(actions.size() > 0);
		DockingActionIf filterAction = actions.get(0);

		// execute
		performAction(filterAction, false);

		// wait for the dialog
		Window filterDialog = waitForWindow("Symbol Table Filter");

		final JCheckBox checkBox = (JCheckBox) findComponentByName(filterDialog, "Parameters");

		runSwing(() -> checkBox.setSelected(true));

		pressButtonByText(filterDialog, "OK", true);

		waitForNotBusy(symbolTable);
	}

	private int getRowForSymbol(Symbol symbol) {
		for (int i = 0; i < symbolTable.getRowCount(); i++) {
			Object name = symbolTable.getValueAt(i, 0);
			if (name.toString().equals(symbol.getName())) {
				Object namespace = symbolTable.getValueAt(i, 4);
				if (namespace.toString().equals(symbol.getParentNamespace().getName())) {
					return i;
				}
			}
		}
		Assert.fail("Didn't find symbol in symbol table: " + symbol.getName());
		return -1;
	}

//
//	private void createFunctionWithDefaultParameters(Address addr) {
//		CreateFunctionCmd cmd =
//			new CreateFunctionCmd(null, addr, null, SourceType.DEFAULT, false, true);
//		int transactionID = prog.startTransaction("TestCreateFunction");
//		try {
//			boolean success = tool.execute(cmd, prog);
////			boolean success = cmd.applyTo(prog);
//			if (!success) {
//				Assert.fail("Unexpectedly could not create a function");
//			}
//		}
//		finally {
//			prog.endTransaction(transactionID, true);
//		}
//
//		prog.flushEvents();
//		waitForBusyTool(tool);
//
//		FunctionManager functionManager = prog.getFunctionManager();
//		Function function = functionManager.getFunctionAt(addr);
//		assertNotNull(function);
//	}

	private ProgramLocation getProgramLocation(int row, int column, TableModel model) {
		ProgramTableModel programModel = (ProgramTableModel) model;
		return programModel.getProgramLocation(row, column);
	}

	private void addLabel(String label, String namespaceName, Address address) throws Exception {
		Namespace namespace = null;
		if (namespaceName != null) {
			Command command = new CreateNamespacesCmd(namespaceName, SourceType.USER_DEFINED);
			if (tool.execute(command, prog)) {
				List<Namespace> namespaces =
					NamespaceUtils.getNamespaces(namespaceName, null, prog);

				if (namespaces.size() != 1) {
					Assert.fail("Unable to find the newly created parent namespace.");
				}
				namespace = namespaces.get(0);
			}
		}

		Command command = new AddLabelCmd(address, label, namespace, SourceType.USER_DEFINED);
		tool.execute(command, prog);
		waitForNotBusy(symbolTable);
	}

	private Address addr(String address) {
		return prog.getAddressFactory().getAddress(address);
	}

	private void myTypeText(Component c, String text) throws Exception {
		triggerText(c, text);
		waitForNotBusy(symbolTable);
	}

	private void deleteTextFieldText(JTextField textField) {
		String textFieldText = textField.getText();
		for (int i = 0; i < textFieldText.length(); i++) {
			triggerActionKey(textField, 0, KeyEvent.VK_BACK_SPACE);
		}

		waitForSwing();
		try {
			waitForNotBusy(symbolTable);
		}
		catch (Exception exc) {
			// we don't care
		}
	}

	private void typeBackspaceOnComponent(Component component) throws Exception {
		triggerActionKey(component, 0, KeyEvent.VK_BACK_SPACE);
		waitForNotBusy(symbolTable);
	}

	// makes sure that all of the symbols in the model start with the given string
	private void modelMatches(final String filterString) {

		final String finalFilterText =
			(filterString.startsWith("^")) ? filterString.substring(1) : filterString;

		runSwing(() -> {
			int rowCount = symbolModel.getRowCount();
			assertTrue(
				"There are no filtered matches as expected from filter string: " + filterString,
				rowCount > 0);
			for (int i = 0; i < rowCount; i++) {
				Symbol symbol = (Symbol) symbolModel.getValueAt(i, SymbolTableModel.LABEL_COL);
				assertTrue(
					"Found an entry in the symbol table model that " + "does not match the given " +
						"filter: " + filterString + " and symbol: " + symbol.getName(),
					symbol.getName().startsWith(finalFilterText));
			}
		});
	}

	private void modelMatchesIgnoringCase(String string) {
		int rowCount = symbolModel.getRowCount();
		assertTrue("There are no filtered matches as expected from filter string: " + string,
			rowCount > 0);

		String filterText = string;

		for (int i = 0; i < rowCount; i++) {
			Symbol symbol = (Symbol) symbolModel.getValueAt(i, SymbolTableModel.LABEL_COL);
			assertTrue(
				"Found an entry in the symbol table model that does not match the given " +
					"filter: " + string + " and symbol: " + symbol.getName(),
				symbol.getName().toUpperCase().startsWith(filterText.toUpperCase()));
		}
	}

	private void waitForNotBusy(GTable table) throws Exception {
		prog.flushEvents();

		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		waitForTableModel(model);
	}

	private void openProgram(String name) throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder(name, true);
		prog = builder.getProgram();

		builder.createMemory("test0", "1", 0x100);
		builder.createMemory("test1", "0x01001000", 0x1000);
		builder.createMemory("test2", "0x01004000", 0x1000);
		builder.createMemory("test3", "0x01007000", 0x1000);
		builder.createMemory("test4", "0x01008000", 0x1000);

		builder.createLabel("1", "__getmainargs");

		builder.createLabel("0x20", "ADVAPI32.dll_IsTextUnicode");
		builder.createLabel("0x21", "KERNEL32.dll_GetProcAddress");

		builder.createLabel("0x30", "CharLowerW");
		builder.createLabel("0x30", "USER32.dll_CharLowerW");
		builder.createExternalLibraries("USER32.dll");
		builder.createExternalReference("0x30", "USER32.dll", "CharLowerW", 0);
		builder.createExternalReference("0x30", "USER32.dll", "CharLowerZ", 0);

		builder.createLabel("0x40", "_DAT_01001388");
		builder.createLabel("0x41", "_DAT_01001398");

		String doStuff = "0x50";
		builder.createLabel(doStuff, "doStuff");
		String entry = "0x51";
		builder.createEntryPoint(entry, "entry");

		String ghidra = "0x52";// 0x52
		builder.createEmptyFunction("ghidra", ghidra, 10, new Undefined1DataType());
		builder.addBytesNOP("0x52", 1);
		builder.addBytesNOP("0x53", 1);
		builder.addBytesNOP("0x54", 1);
		builder.addBytesNOP("0x55", 1);
		builder.addBytesNOP("0x56", 1);
		builder.addBytesNOP("0x57", 1);
		builder.addBytesNOP("0x58", 1);
		builder.addBytesNOP("0x59", 1);
		builder.disassemble("0x52", 10);
		builder.createLabel("0x52", "ghidra");
		builder.createLabel("0x53", "MyLocal", "ghidra");
		builder.createLabel("0x55", "AnotherLocal", "ghidra");

		builder.createLabel("0x60", "_LAB_010018B3");
		builder.createLabel("0x61", "_LAB_0100193F");
		builder.createLabel("0x62", "_LAB_01002306");
		builder.createLabel("0x63", "_LAB_01002321");
		builder.createLabel("0x64", "_LAB_01003E71");

		builder.createLabel("0x70", "rsrc_Icon_7_ea8");

		builder.createLabel("0x80", "_SUB_010059A3");

		// a generic function with params for testing
		ParameterImpl p = new ParameterImpl(null, new ByteDataType(), prog);
		builder.createEmptyFunction("func_with_parms", "0x100", 10, new Undefined1DataType(), p, p);

		// references to these symbols
		builder.createMemoryCallReference("0x01004aea", doStuff);// doStuff
		builder.createMemoryCallReference("0x01004000", doStuff);// doStuff
		builder.createMemoryCallReference("0x01004001", doStuff);// doStuff

		builder.createMemoryCallReference("0x01004201", entry);// entry

		// refs for ghidra - to, from and data
		// to
		builder.createMemoryCallReference("0x01004bea", ghidra);
		builder.createMemoryCallReference("0x01004100", ghidra);
		builder.createMemoryCallReference("0x01004101", ghidra);

		// from ghidra
		builder.createMemoryCallReference(add(ghidra, 1), doStuff);// ghidra -> doStuff
		builder.createMemoryCallReference(add(ghidra, 2), ghidra);// ghidra -> ghidra
		builder.createMemoryCallReference(add(ghidra, 3), entry);// ghidra -> entry

		// data from ghidra
		builder.createMemoryReadReference(add(ghidra, 4), add(ghidra, 6));
		builder.createMemoryReadReference(add(ghidra, 5), add(ghidra, 7));

		// for testing navigation
		builder.addBytesNOP(doStuff, 1);

		env.showTool(prog);

		setUpSymbolTable();
	}

	private String add(String addr, int amt) {
		Address address = addr(addr);
		address = address.add(amt);
		return address.toString();
	}

	private void setUpSymbolTable() throws Exception {

		waitForSwing();

		performAction(viewSymAction, true);

		SymbolProvider symbolTableProvider = waitForComponentProvider(SymbolProvider.class);

		symbolTable =
			(GTable) findComponentByName(symbolTableProvider.getComponent(), "SymbolTable");
		assertNotNull(symbolTable);

		symbolModel = (SymbolTableModel) symbolTable.getModel();
		filterPanel = getFilterPanel();

		final NewSymbolFilter filter = new NewSymbolFilter();
		turnOffAllFilterTypes(filter);
		filter.setFilter("Instruction Labels", true);
		filter.setFilter("Data Labels", true);
		filter.setFilter("Function Labels", true);
		filter.setFilter("Default (Functions)", true);
		filter.setFilter("Default (Labels)", true);
		symbolModel.setFilter(filter);

		waitForNotBusy(symbolTable);

		symbolTableHeader = symbolTable.getTableHeader();
	}

	private void showReferencesTable() {

		performAction(viewRefAction, true);
		ReferenceProvider referencesProvider = waitForComponentProvider(ReferenceProvider.class);
		referenceTable =
			(GTable) findComponentByName(referencesProvider.getComponent(), "ReferenceTable");
		assertNotNull(referenceTable);
	}

	@SuppressWarnings("unchecked")
	private GhidraTableFilterPanel<SymbolRowObject> getFilterPanel() {
		Object symProvider = getInstanceField("symProvider", plugin);
		Object panel = getInstanceField("symbolPanel", symProvider);
		return (GhidraTableFilterPanel<SymbolRowObject>) getInstanceField("tableFilterPanel",
			panel);
	}

	private void singleClick(final JTable table, final int row, final int col) throws Exception {
		clickTableCell(table, row, col, 1);
	}

	private void doubleClick(final JTable table, final int row, final int col) throws Exception {
		clickTableCell(table, row, col, 2);
	}

	private void turnOffAllFilterTypes(final NewSymbolFilter filter) {
		String[] names = filter.getLabelTypeFilterNames();
		for (String element : names) {
			filter.setFilter(element, false);
		}
		names = filter.getNonLabelTypeFilterNames();
		for (String element : names) {
			filter.setFilter(element, false);
		}
	}

	private void configureTool(PluginTool tool1) throws Exception {
		tool1.addPlugin(CodeBrowserPlugin.class.getName());
		tool1.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool1.addPlugin(SymbolTablePlugin.class.getName());
	}

	private int findRow(String symbolName, String namespace) {
		int max = symbolTable.getRowCount();
		for (int i = 0; i < max; i++) {
			Symbol s = (Symbol) symbolTable.getValueAt(i, SymbolTableModel.LABEL_COL);
			if (symbolName.equals(s.getName()) &&
				namespace.equals(s.getParentNamespace().getName())) {
				return i;
			}
		}
		Assert.fail("Symbol cell not found: " + namespace + "::" + symbolName);
		return -1;
	}

}
