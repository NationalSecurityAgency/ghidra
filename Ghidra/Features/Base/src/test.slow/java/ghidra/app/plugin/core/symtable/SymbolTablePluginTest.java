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
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableModel;

import org.jdom.Element;
import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.filter.*;
import docking.widgets.table.*;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.cmd.refs.RemoveReferenceCmd;
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
import util.CollectionUtils;

public class SymbolTablePluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cbPlugin;
	private SymbolTablePlugin plugin;
	private ProgramDB program;
	private GTable symbolTable;
	private SymbolTableModel symbolModel;
	private GTable referenceTable;
	private GhidraTableFilterPanel<Symbol> filterPanel;
	private SymbolProvider provider;

	private DockingActionIf viewSymAction;
	private DockingActionIf viewRefAction;
	private DockingActionIf deleteAction;
	private DockingActionIf makeSelectionAction;
	private DockingActionIf setPinnedAction;
	private DockingActionIf clearPinnedAction;
	private DockingActionIf setFilterAction;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		tool = env.getTool();
		configureTool(tool);

		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		plugin = env.getPlugin(SymbolTablePlugin.class);
		provider = (SymbolProvider) getInstanceField("symProvider", plugin);

		viewSymAction = getAction(plugin, "Symbol Table");

		// this action is actually in the tool twice: once for the provider and once as a 
		// local action in the Symbol Table header, so we must pick one
		Set<DockingActionIf> symbolReferencesActions =
			getActionsByOwnerAndName(tool, plugin.getName(), "Symbol References");
		viewRefAction = CollectionUtils.any(symbolReferencesActions);

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
		openProgram("sample");
		int row = findRow("ghidra");

		TableModel model = symbolTable.getModel();
		doubleClick(symbolTable, row, SymbolTableModel.LOCATION_COL);
		ProgramLocation pl = getProgramLocation(row, SymbolTableModel.LOCATION_COL, model);
		assertEquals(pl.getAddress(), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testSortingLabelColumn() throws Exception {
		openProgram("sample");

		sortAscending(SymbolTableModel.LABEL_COL);

		TableModel model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Symbol sym1 = getSymbol(i);
			Symbol sym2 = getSymbol(i + 1);
			int compare = sym1.getName().compareToIgnoreCase(sym2.getName());
			assertTrue("row " + i + " not sorted correctly", (compare < 0 || compare == 0));
		}

		sortDescending(SymbolTableModel.LABEL_COL);

		model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Symbol sym1 = getSymbol(i);
			Symbol sym2 = getSymbol(i + 1);
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
		openProgram("sample");

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
		openProgram("sample");

		sortAscending(SymbolTableModel.LOCATION_COL);

		SymbolTableModel model = (SymbolTableModel) symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			AddressBasedLocation loc1 = getLocation(i);
			AddressBasedLocation loc2 = getLocation(i + 0);
			assertTrue(loc1.compareTo(loc2) <= 0);
		}

		sortDescending(SymbolTableModel.LOCATION_COL);

		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			AddressBasedLocation loc1 = getLocation(i);
			AddressBasedLocation loc2 = getLocation(i + 0);
			assertTrue(loc1.compareTo(loc2) >= 0);
		}
	}

	@Test
	public void testSortingReferenceColumn() throws Exception {
		openProgram("sample");

		sortAscending(SymbolTableModel.REFS_COL);

		TableModel model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Integer refs1 = getRefCount(i);
			Integer refs2 = getRefCount(i + 1);
			assertTrue(refs1.compareTo(refs2) <= 0);
		}

		sortDescending(SymbolTableModel.REFS_COL);

		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Integer refs1 = getRefCount(i);
			Integer refs2 = getRefCount(i + 1);
			assertTrue(refs1.compareTo(refs2) >= 0);
		}
	}

	@Test
	public void testFilter() throws Exception {
		openProgram("sample");

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
		waitForNotBusy();

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
		waitForNotBusy();

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
		waitForNotBusy();

		//
		// Locals: 'AnotherLocal', 'MyLocal'
		//
		assertEquals(2, symbolTable.getRowCount());
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

	@Test
	public void testEditing() throws Exception {
		openProgram("sample");

		waitForNotBusy();

		String symbolName = "ghidra";
		int row = findRow(symbolName);

		doubleClick(symbolTable, row, SymbolTableModel.LABEL_COL);
		waitForSwing();
		assertTrue(symbolTable.isEditing());

		Component editor = symbolTable.getEditorComponent();
		assertNotNull(editor);
		JTextField textField = (JTextField) editor;
		String currentText = getText(textField);
		assertEquals(symbolName, currentText);

		triggerActionKey(textField, 0, KeyEvent.VK_END);
		myTypeText(editor, ".Is.Cool");
		runSwing(() -> symbolTable.editingStopped(new ChangeEvent(symbolTable)));

		waitForNotBusy();

		assertTrue(!symbolTable.isEditing());

		Symbol s = getSymbol(row);
		assertEquals("ghidra.Is.Cool", s.getName());
	}

	@Test
	public void testQuickLookup() throws Exception {
		openProgram("sample");

		tx(program, () -> {

			Address sample = program.getMinAddress();
			SymbolTable st = program.getSymbolTable();
			st.createLabel(sample.getNewAddress(0x01008100), "_", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008100), "a", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008200), "ab", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008300), "abc", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008400), "abc1", SourceType.USER_DEFINED);
			st.createLabel(sample.getNewAddress(0x01008500), "abc123", SourceType.USER_DEFINED);
		});

		waitForNotBusy();
		int testTimeoutMs = 100;
		symbolTable.setAutoLookupTimeout(testTimeoutMs);

		selectRow(0);

		triggerAutoLookup("a");
		assertEquals(findRow("a", "Global"), symbolTable.getSelectedRow());
		sleep(testTimeoutMs);

		triggerAutoLookup("ab");
		assertEquals(findRow("ab", "Global"), symbolTable.getSelectedRow());
		sleep(testTimeoutMs);

		triggerAutoLookup("abc");
		assertEquals(findRow("abc", "Global"), symbolTable.getSelectedRow());
		sleep(testTimeoutMs);

		triggerAutoLookup("abcd");
		assertEquals(findRow("abc1", "Global"), symbolTable.getSelectedRow());
		sleep(testTimeoutMs);

		selectRow(0);
		triggerAutoLookup("abc12");
		assertEquals(findRow("abc123", "Global"), symbolTable.getSelectedRow());
	}

	@Test
	public void testDeleting() throws Exception {
		openProgram("sample");

		int rowCount = symbolTable.getRowCount();
		assertTrue(!deleteAction.isEnabled());

		int row = findRow("ghidra");
		Rectangle rect = symbolTable.getCellRect(row, 0, true);
		symbolTable.scrollRectToVisible(rect);
		singleClick(symbolTable, row, 0);

		assertTrue(deleteAction.isEnabled());
		performAction(deleteAction, true);
		waitForNotBusy();

		assertNull(getUniqueSymbol(program, "ghidra"));
		Symbol myLocalSymbol = getUniqueSymbol(program, "MyLocal");
		assertNotNull(myLocalSymbol);// MyLocal should have been promoted to global since user defined.
		assertEquals(SourceType.USER_DEFINED, myLocalSymbol.getSource());
		assertEquals(program.getGlobalNamespace(), myLocalSymbol.getParentNamespace());

		int rowAfterDelete = findRow("ghidra");
		assertEquals(-1, rowAfterDelete);

		Symbol anotherLocalSymbol = getUniqueSymbol(program, "AnotherLocal");
		assertNotNull(anotherLocalSymbol);// AnotherLocal should have been promoted to global since user defined.
		assertEquals(SourceType.USER_DEFINED, anotherLocalSymbol.getSource());
		assertEquals(program.getGlobalNamespace(), anotherLocalSymbol.getParentNamespace());

		// 1 Function label removed (1 dynamic added at function entry)
		// Locals were promoted to global.
		int newDynamicSymbolRow = findRow("SUB_00000052");
		assertNotEquals(-1, newDynamicSymbolRow);
		assertEquals(rowCount, symbolTable.getRowCount());

		int anotherLocal_RowIndex = findRow("AnotherLocal");
		selectRow(anotherLocal_RowIndex);

		performAction(deleteAction, true);
		waitForNotBusy();
		anotherLocalSymbol = getUniqueSymbol(program, "AnotherLocal");
		assertNull("Delete action did not delete symbol: " + anotherLocalSymbol,
			anotherLocalSymbol);// AnotherLocal should have been promoted to global since user defined.

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
		FunctionManager functionManager = program.getFunctionManager();

		Function function = functionManager.getFunctionContaining(addr);
		Symbol param1Symbol = getUniqueSymbol(program, "param_1", function);

		assertNotNull("Could not find param_1 in function", param1Symbol);

		setupSymbolTableFilterToShowParameters();

		int row = getRowForSymbol(param1Symbol);
		selectRow(row);

		// execute the delete action
		performAction(deleteAction, true);
		Assert.assertNotEquals(param1Symbol, getUniqueSymbol(program, "param_1", function));
	}

	@Test
	public void testBuiltInTableActionsAvailable() throws Exception {
		openProgram("sample");

		int row = 0;
		selectRow(row);

		JPopupMenu popup = triggerPopup(row);
		List<JMenuItem> popupItems = getPopupMenuItems(popup);
		assertMenuContains(popupItems, "Copy");
		assertMenuContains(popupItems, "Export");
		assertMenuContains(popupItems, "Select All");
	}

	@Test
	public void testMakeSelection() throws Exception {
		openProgram("sample");

		assertTrue(!makeSelectionAction.isEnabled());

		int row1 = findRow("ghidra");
		int row2 = findRow("KERNEL32.dll_GetProcAddress");
		int row3 = findRow("LAB_00000058");
		int rowCount = 3;
		selectRows(row1, row2, row3);

		assertTrue(makeSelectionAction.isEnabled());

		int[] selectedRows = symbolTable.getSelectedRows();
		assertEquals(rowCount, selectedRows.length);

		performAction(makeSelectionAction, true);
		waitForSwing();

		ProgramSelection sel = cbPlugin.getCurrentSelection();

		assertEquals(rowCount, sel.getNumAddressRanges());

		Address sample = program.getMinAddress();

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
		openProgram("sample");

		int row1 = findRow("ADVAPI32.dll_IsTextUnicode");
		int row2 = findRow("AnotherLocal", "ghidra");
		int row3 = findRow("CharLowerW");
		selectRows(row1, row2, row3);

		ActionContext actionContext = provider.getActionContext(null);
		int[] selectedRows = symbolTable.getSelectedRows();
		assertEquals(3, selectedRows.length);
		for (int selectedRow : selectedRows) {
			Symbol symbol = getSymbol(selectedRow);
			assertFalse(symbol.isPinned());
		}
		assertTrue(setPinnedAction.isEnabledForContext(actionContext));
		assertFalse(clearPinnedAction.isEnabledForContext(actionContext));

		performAction(setPinnedAction, actionContext, true);
		waitForNotBusy();
		for (int selectedRow : selectedRows) {
			Symbol symbol = getSymbol(selectedRow);
			assertTrue(symbol.isPinned());
		}

		performAction(clearPinnedAction, actionContext, true);
		waitForSwing();
		for (int selectedRow : selectedRows) {
			Symbol symbol = getSymbol(selectedRow);
			assertFalse(symbol.isPinned());
		}
	}

	@Test
	public void testSetPinnedActionNotEnabledForExternalSymbols() throws Exception {
		openProgram("sample");

		int row1 = findRow("CharLowerW", "USER32.dll");
		int row2 = findRow("CharLowerZ", "USER32.dll");
		selectRows(row1, row2);

		ActionContext actionContext = provider.getActionContext(null);
		int[] selectedRows = symbolTable.getSelectedRows();

		for (int selectedRow : selectedRows) {
			Symbol symbol = getSymbol(selectedRow);
			assertFalse(symbol.isPinned());
		}
		assertFalse(setPinnedAction.isEnabledForContext(actionContext));
		assertFalse(clearPinnedAction.isEnabledForContext(actionContext));

	}

	@Test
	public void testUpdateOnSymbolsAdded() throws Exception {
		openProgram("sample");
		Address sample = program.getMinAddress();
		SymbolTable st = program.getSymbolTable();
		int rowCount = symbolTable.getRowCount();

		Symbol sym = modifyProgram(program, p -> {
			return st.createLabel(sample.getNewAddress(0x01007000), "Zeus",
				SourceType.USER_DEFINED);
		});
		waitForNotBusy();
		assertEquals(rowCount + 1, symbolTable.getRowCount());
		assertTrue(symbolModel.getRowIndex(sym) >= 0);

		sym = modifyProgram(program, p -> {
			return st.createLabel(sample.getNewAddress(0x01007100), "Athena",
				SourceType.USER_DEFINED);
		});
		waitForNotBusy();
		assertEquals(rowCount + 2, symbolTable.getRowCount());
		assertTrue(symbolModel.getRowIndex(sym) >= 0);
	}

	@Test
	public void testSymbolsAddedWithFilterOn() throws Exception {
		openProgram("sample");

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

		Address sample = program.getMinAddress();
		SymbolTable st = program.getSymbolTable();
		Symbol sym = modifyProgram(program, p -> {
			return st.createLabel(sample.getNewAddress(0x01007000), "saaaa",
				SourceType.USER_DEFINED);
		});
		waitForNotBusy();
		assertTrue(symbolModel.getRowIndex(sym) >= 0);

		// make sure we added one while the filter is on
		assertEquals(rowCount + 1, symbolModel.getRowCount());
	}

	@Test
	public void testRenameUpdatesSort() throws Exception {

		openProgram("sample");

		waitForNotBusy();

		//
		// Functions: 'ghidra', 'func_with_parms'
		//
		assertEquals(25, symbolTable.getRowCount());

		Symbol symbol = getUniqueSymbol(program, "ghidra");
		int rowIndex = indexOf(symbol);

		setName(symbol, "____ghidra", SourceType.DEFAULT);
		assertEquals(25, symbolTable.getRowCount());

		int updatedRowIndex = indexOf(symbol);
		assertNotEquals(rowIndex, updatedRowIndex);
		assertEquals(0, updatedRowIndex);
	}

	@Test
	public void testDefaultFunctionToNamedFunctionWithFilterOn() throws Exception {
		openProgram("sample");

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
		waitForNotBusy();

		//
		// Functions: 'ghidra', 'func_with_parms'
		//
		assertEquals(22, symbolTable.getRowCount());

		Symbol symbol = getUniqueSymbol(program, "ghidra");
		setName(symbol, null, SourceType.DEFAULT);
		assertEquals(21, symbolTable.getRowCount());

		setName(symbol, "foobar", SourceType.USER_DEFINED);
		assertEquals(22, symbolTable.getRowCount());
	}

	@Test
	public void testUpdateOnSymbolsRemoved() throws Exception {
		openProgram("sample");

		SymbolTable st = program.getSymbolTable();
		Symbol sym = getUniqueSymbol(program, "entry");
		assertNull(getUniqueSymbol(program, "EXT_00000051"));

		tx(program, () -> st.removeSymbolSpecial(sym));
		waitForNotBusy();

		// entry symbol replaced by dynamic External Entry symbol
		assertNull(getUniqueSymbol(program, "entry"));
		assertNotNull(getUniqueSymbol(program, "EXT_00000051"));
		assertTrue("Deleted symbol not removed from table", symbolModel.getRowIndex(sym) < 0);
	}

	@Test
	public void testUpdateOnReferencesAdded() throws Exception {
		openProgram("sample");
		Address sample = program.getMinAddress();

		Symbol s = getUniqueSymbol(program, "entry");

		int row = symbolModel.getRowIndex(s);
		Integer refCount = getRefCount(row);
		assertNotNull(refCount);
		assertEquals(3, refCount.intValue());

		tx(program, () -> {
			ReferenceManager rm = program.getReferenceManager();
			Reference ref = rm.addMemoryReference(sample.getNewAddress(0x01004203),
				sample.getNewAddress(0x51), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
			rm.setPrimary(ref, true);
		});

		waitForNotBusy();

		row = symbolModel.getRowIndex(s);

		refCount = getRefCount(row);
		assertNotNull(refCount);
		assertEquals(4, refCount.intValue());
	}

	@Test
	public void testUpdateOnReferencesRemoved() throws Exception {
		openProgram("sample");
		Address sample = program.getMinAddress();

		Symbol s = getUniqueSymbol(program, "doStuff");
		int row = symbolModel.getRowIndex(s);
		Integer refCount = getRefCount(row);
		assertNotNull(refCount);
		assertEquals(4, refCount.intValue());

		Address from = sample.getNewAddress(0x01004aea);
		Address to = sample.getNewAddress(0x50);
		Reference ref = getReference(from, to);

		tx(program, () -> {
			ReferenceManager manager = program.getReferenceManager();
			manager.delete(ref);
		});

		waitForNotBusy();

		refCount = getRefCount(row);
		assertNotNull(refCount);
		assertEquals(3, refCount.intValue());
	}

	@Test
	public void testUpdateOnProgramRestore() throws Exception {
		openProgram("sample");

		int startRowCount = symbolTable.getRowCount();

		ClearCmd cmd = new ClearCmd(program.getMemory(), new ClearOptions());
		applyCmd(program, cmd);
		waitForBusyTool(tool);
		waitForNotBusy();

		// Externals are not cleared
		int clearedRowCount = 3;
		assertEquals(clearedRowCount, symbolTable.getRowCount());

		undo(program);
		waitForNotBusy();

		assertEquals(startRowCount, symbolTable.getRowCount());

		redo(program);
		waitForNotBusy();

		assertEquals(clearedRowCount, symbolTable.getRowCount());
	}

	@Test
	public void testBigProgram() throws Exception {
		openProgram("winword.exe");
		showFilterDialog();

		FilterDialog filterDialog = waitForDialogComponent(FilterDialog.class);
		assertNotNull(filterDialog);
		runSwing(() -> {
			NewSymbolFilter filter = new NewSymbolFilter();
			turnOffAllFilterTypes(filter);
			filter.setFilter("Function Labels", true);
			filterDialog.setFilter(filter);
		});

		pressButtonByText(filterDialog, "OK");
		waitForSwing();
		waitForNotBusy();
		waitForSwing();
	}

	@Test
	public void testSegmentedProgram() throws Exception {
		openProgram("winhelp");

		/************** LABEL **********************/

		sortAscending(SymbolTableModel.LABEL_COL);

		TableModel model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Symbol sym1 = getSymbol(i);
			Symbol sym2 = getSymbol(i + 1);
			int compare = sym1.getName().compareToIgnoreCase(sym2.getName());
			assertTrue("Symbol \"" + sym1 + "\" is not sorted as less than symbol \"" + sym2 + "\"",
				compare <= 0);
		}

		/************** ADDRESS **********************/

		sortAscending(SymbolTableModel.LOCATION_COL);

		model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			AddressBasedLocation loc1 = getLocation(i);
			AddressBasedLocation loc2 = getLocation(i + 1);
			int compare = SystemUtilities.compareTo(loc1, loc2);
			assertTrue(
				"Location1 \"" + loc1 + "\"is not sorted as less than location2 \"" + loc2 + "\"",
				compare <= 0);
		}

		/************** REFERENCES **********************/

		sortAscending(SymbolTableModel.REFS_COL);

		model = symbolTable.getModel();
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			Integer refs1 = getRefCount(i);
			Integer refs2 = getRefCount(i + 1);
			assertTrue(
				"The number of references (\"" + refs1 + "\") for row did not " +
					"compare as less than the number for the following row (\"" + refs2 + "\")",
				refs1.compareTo(refs2) <= 0);
		}
	}

	@Test
	public void testReferences() throws Exception {
		openProgram("sample");

		showReferencesTable();

		singleClick(symbolTable, findRow("ghidra", "Global"), SymbolTableModel.LABEL_COL);

		/*****************************/

		DockingActionIf refsToAction = getAction(plugin, "References To");
		assertNotNull(refsToAction);
		performAction(refsToAction, true);
		waitForSwing();

		waitForNotBusy();
		waitForNotBusy();
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

		waitForNotBusy();
		waitForNotBusy();
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

		waitForNotBusy();
		waitForNotBusy();
		assertEquals(2, referenceTable.getRowCount());

		// data
		assertReferencesAddressColumnValue(0, 0x56);
		assertReferencesAddressColumnValue(1, 0x57);
	}

	@Test
	public void testFilterTextField() throws Exception {
		openProgram("sample");

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
		sortAscending(SymbolTableModel.REFS_COL);

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
		sortAscending(SymbolTableModel.LOCATION_COL);

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
		openProgram("sample");

		JTextField textField = getFilterTextField();

		// setup labels in the program for matching
		int rowCount = symbolTable.getRowCount();

		addLabel("bob", null, addr("010058f6"));

		addLabel("bob", "billy", addr("01005917"));
		waitForNotBusy();

		int updatedRowCount = symbolTable.getRowCount();
		assertEquals(rowCount + 2, updatedRowCount);

		// test ascending
		runSwing(() -> TableUtils.columnSelected(symbolTable, 0));
		waitForNotBusy();

		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);

		myTypeText(textField, "bo");
		waitForNotBusy();

		// make sure both 'bob's are in the table
		assertEquals("Did not find two bobs.", 2, symbolTable.getRowCount());
		modelMatchesIgnoringCase("bob");

		myTypeText(textField, "b");
		waitForNotBusy();

		assertEquals("Did not find two bobs.", 2, symbolTable.getRowCount());
		modelMatchesIgnoringCase("bob");

		// test descending
		runSwing(() -> TableUtils.columnSelected(symbolTable, 0));
		waitForNotBusy();

		assertEquals("Did not find two bobs in descending order.", 2, symbolTable.getRowCount());
		modelMatchesIgnoringCase("bob");
	}

	@Test
	public void testReferenceRemvoed_ReferenceToDynamicSymbol() throws Exception {

		openProgram("sample");

		int row = findRow("DAT_00000006");
		assertTrue(row > -1);

		removeReference("0x00000005", "0x00000006");

		row = findRow("DAT_00000006");
		assertFalse(row > -1);
	}

//==================================================================================================
// Helper methods
//==================================================================================================

	private Reference getReference(Address from, Address to) {

		ReferenceManager rm = program.getReferenceManager();
		Reference[] refs = rm.getReferencesFrom(from);
		for (Reference element : refs) {
			if (to.equals(element.getToAddress())) {
				return element;
			}
		}

		fail("Did not find expected mem reference between " + from + " and " + to);
		return null;
	}

	private void sortAscending(int column) {
		runSwing(() -> symbolModel.setTableSortState(
			TableSortState.createDefaultSortState(column, true)));
		waitForTableModel(symbolModel);

		waitForCondition(() -> {
			TableSortState sort = runSwing(() -> symbolModel.getTableSortState());
			return sort.getColumnSortState(column).isAscending();
		});
	}

	private void sortDescending(int column) {
		runSwing(() -> symbolModel.setTableSortState(
			TableSortState.createDefaultSortState(column, false)));
		waitForTableModel(symbolModel);

		waitForCondition(() -> {
			TableSortState sort = runSwing(() -> symbolModel.getTableSortState());
			return !sort.getColumnSortState(column).isAscending();
		});
	}

	private int indexOf(Symbol symbol) {
		return runSwing(() -> symbolModel.getRowIndex(symbol));
	}

	private void removeReference(String from, String to) {

		ReferenceManager rm = program.getReferenceManager();
		Reference ref = rm.getReference(addr(from), addr(to), 0);
		RemoveReferenceCmd cmd = new RemoveReferenceCmd(ref);
		applyCmd(program, cmd);
	}

	private void assertMenuContains(List<JMenuItem> popupItems, String string) {
		for (JMenuItem item : popupItems) {
			String text = item.getText();
			if (text.equals(string)) {
				return; // found it
			}
		}
		fail("'" + string + "' not in the popup menu!");
	}

	private List<JMenuItem> getPopupMenuItems(JPopupMenu popup) {
		List<JMenuItem> list = new ArrayList<>();
		Component[] children = popup.getComponents();
		for (Component child : children) {
			if (child instanceof JMenuItem) {
				list.add((JMenuItem) child);
			}
		}
		return list;
	}

	private JPopupMenu triggerPopup(int row) {
		DockingWindowManager dwm = DockingWindowManager.getInstance(symbolTable);
		ActionContext context = provider.getActionContext(null);
		JPopupMenu popup =
			runSwing(() -> DockingWindowManagerTestHelper.getPopupMenu(dwm, context));
		return popup;
	}

	private void selectRow(int row) {
		selectRows(row, row);

		int selectedRow = symbolTable.getSelectedRow();
		assertEquals("Row was not selected!", row, selectedRow);
		waitForSwing();
	}

	private void selectRows(int... rows) {
		assertNotNull(rows);
		assertTrue("Must have at least one row to select", rows.length > 0);
		runSwing(() -> {

			symbolTable.clearSelection();

			for (int row : rows) {
				symbolTable.addRowSelectionInterval(row, row);
			}
			int end = rows[rows.length - 1];
			Rectangle rect = symbolTable.getCellRect(end, 0, true);
			symbolTable.scrollRectToVisible(rect);
		});
		waitForSwing();
	}

	private FilterDialog showFilterDialog() {

		performAction(setFilterAction, false);

		FilterDialog dialog = waitForDialogComponent(FilterDialog.class);
		assertNotNull(dialog);
		return dialog;
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

	private void triggerAutoLookup(String text) throws Exception {

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
		waitForNotBusy();
	}

	private void setName(Symbol symbol, String name, SourceType type) throws Exception {
		tx(program, () -> symbol.setName(name, SourceType.DEFAULT));
		waitForNotBusy();
	}

	private Symbol getSymbol(int row) {
		return symbolModel.getRowObject(row);
	}

	private Integer getRefCount(int row) {
		Integer count =
			runSwing(() -> (Integer) symbolModel.getValueAt(row, SymbolTableModel.REFS_COL));
		return count;
	}

	private AddressBasedLocation getLocation(int row) {
		AddressBasedLocation location =
			runSwing(() -> (AddressBasedLocation) symbolModel.getValueAt(row,
				SymbolTableModel.LOCATION_COL));
		return location;
	}

	private void assertReferencesAddressColumnValue(int row, long value) {
		Address addr =
			(Address) referenceTable.getValueAt(row, SymbolReferenceModel.ADDRESS_COLUMN);
		assertEquals("Address in row " + row + " is not the expected value", value,
			addr.getOffset());
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

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean caseSensitive)
			throws Exception {
		filterPanel.setFilterOptions(new FilterOptions(filterStrategy, true, caseSensitive, false));
		waitForNotBusy();
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

		DockingActionIf filterAction = getAction(tool, "SymbolTablePlugin", "Set Filter");

		// execute
		performAction(filterAction, false);

		// wait for the dialog
		Window filterDialog = waitForWindow("Symbol Table Filter");

		final JCheckBox checkBox = (JCheckBox) findComponentByName(filterDialog, "Parameters");

		runSwing(() -> checkBox.setSelected(true));

		pressButtonByText(filterDialog, "OK", true);

		waitForNotBusy();
	}

	private int getRowForSymbol(Symbol symbol) {
		for (int i = 0; i < symbolTable.getRowCount(); i++) {
			Symbol rowSymbol = getSymbol(i);
			if (rowSymbol.equals(symbol)) {
//				if (rowSymbol.getParentNamespace().equals(symbol.getParentNamespace())) {
//					return i;
//				}
				return i;
			}
		}
		Assert.fail("Didn't find symbol in symbol table: " + symbol.getName());
		return -1;
	}

	private ProgramLocation getProgramLocation(int row, int column, TableModel model) {
		ProgramTableModel programModel = (ProgramTableModel) model;
		return programModel.getProgramLocation(row, column);
	}

	private void addLabel(String label, String namespaceName, Address address) throws Exception {
		Namespace namespace = null;
		if (namespaceName != null) {
			Command command = new CreateNamespacesCmd(namespaceName, SourceType.USER_DEFINED);
			if (tool.execute(command, program)) {
				List<Namespace> namespaces =
					NamespaceUtils.getNamespaceByPath(program, null, namespaceName);

				if (namespaces.size() != 1) {
					Assert.fail("Unable to find the newly created parent namespace.");
				}
				namespace = namespaces.get(0);
			}
		}

		Command command = new AddLabelCmd(address, label, namespace, SourceType.USER_DEFINED);
		tool.execute(command, program);
		waitForNotBusy();
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private void myTypeText(Component c, String text) throws Exception {
		triggerText(c, text);
		waitForNotBusy();
	}

	private void deleteTextFieldText(JTextField textField) {
		String textFieldText = textField.getText();
		for (int i = 0; i < textFieldText.length(); i++) {
			triggerActionKey(textField, 0, KeyEvent.VK_BACK_SPACE);
		}

		waitForSwing();
		try {
			waitForNotBusy();
		}
		catch (Exception exc) {
			// we don't care
		}
	}

	private void typeBackspaceOnComponent(Component component) throws Exception {
		triggerActionKey(component, 0, KeyEvent.VK_BACK_SPACE);
		waitForNotBusy();
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
				Symbol symbol = getSymbol(i);
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
			Symbol symbol = getSymbol(i);
			assertTrue(
				"Found an entry in the symbol table model that does not match the given " +
					"filter: " + string + " and symbol: " + symbol.getName(),
				symbol.getName().toUpperCase().startsWith(filterText.toUpperCase()));
		}
	}

	private void waitForNotBusy() throws Exception {
		waitForProgram(program);
		waitForCondition(() -> !plugin.isBusy());
	}

	private void openProgram(String name) throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder(name, true);
		program = builder.getProgram();

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
		ParameterImpl p = new ParameterImpl(null, new ByteDataType(), program);
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
		builder.createMemoryReadReference("0x00000005", "0x00000006");

		// for testing navigation
		builder.addBytesNOP(doStuff, 1);

		env.showTool(program);

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
		runSwing(() -> symbolModel.setFilter(filter));

		waitForNotBusy();

		sortAscending(SymbolTableModel.LABEL_COL);
	}

	private void showReferencesTable() {

		performAction(viewRefAction, true);
		ReferenceProvider referencesProvider = waitForComponentProvider(ReferenceProvider.class);
		referenceTable =
			(GTable) findComponentByName(referencesProvider.getComponent(), "ReferenceTable");
		assertNotNull(referenceTable);
	}

	@SuppressWarnings("unchecked")
	private GhidraTableFilterPanel<Symbol> getFilterPanel() {
		Object symProvider = getInstanceField("symProvider", plugin);
		Object panel = getInstanceField("symbolPanel", symProvider);
		return (GhidraTableFilterPanel<Symbol>) getInstanceField("tableFilterPanel", panel);
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

	private int findRow(String symbolName) {
		return findRow(symbolName, "Global");
	}

	private int findRow(String symbolName, String namespace) {
		waitForSwing();
		int max = symbolTable.getRowCount();
		for (int i = 0; i < max; i++) {
			Symbol s = (Symbol) symbolTable.getValueAt(i, SymbolTableModel.LABEL_COL);
			if (s == null) {
				continue; // symbol deleted
			}
			if (symbolName.equals(s.getName()) &&
				namespace.equals(s.getParentNamespace().getName())) {
				return i;
			}
		}

		return -1;
	}

}
