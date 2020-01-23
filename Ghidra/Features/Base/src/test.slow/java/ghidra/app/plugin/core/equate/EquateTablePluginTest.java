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
package ghidra.app.plugin.core.equate;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.util.*;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.table.GhidraTable;
import util.CollectionUtils;

/**
 * Tests for the equate table plugin.
 */
public class EquateTablePluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private EquateTablePlugin plugin;
	private CodeBrowserPlugin cb;
	private EquateTableModel equatesModel;
	private EquateReferenceTableModel refsModel;
	private GhidraTable equatesTable;
	private GhidraTable refsTable;
	private EquateTableProvider provider;
	private EquateTable et;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(EquateTablePlugin.class.getName());
		cb = getPlugin(tool, CodeBrowserPlugin.class);

		plugin = getPlugin(tool, EquateTablePlugin.class);

		et = program.getEquateTable();

		showProvider();
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		builder.createMemory("test", "0x01006000", 0x1000);

		builder.createEquate("0x010060f0", "ANOTHER_ONE", 1, 0);

		builder.createEquate("0x010064c5", "EIGHT", 8, 1);
		builder.createEquate("0x01006500", "EIGHT", 8, 1);

		builder.createEquate("0x01006455", "FOUR", 4, 1);
		builder.createEquate("0x010064ae", "FOUR", 4, 1);

		builder.createEquate("0x01006140", "ONE", 1, 0);
		builder.createEquate("0x01006147", "ONE", 1, 0);
		builder.createEquate("0x0100621d", "ONE", 1, 1);
		builder.createEquate("0x010063f4", "ONE", 1, 1);

		builder.createEquate("0x010061a2", "THIRTY", 30, 0);

		builder.createEquate("0x01006252", "TWO", 2, 0);
		builder.createEquate("0x010063da", "TWO", 2, 1);
		builder.createEquate("0x0100644d", "TWO", 2, 0);

		builder.createEquate("0x010060b2", "TWO_alt", 2, 1);
		builder.createEquate("0x01006254", "TWO_alt", 2, 0);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testEquateTableView() throws Exception {
		// verify that the equate table shows the equates and the references	
		assertNotNull(refsTable);
		assertNotNull(refsModel);
		assertEquals(1, refsModel.getRowCount());

		checkTableValues();
	}

	@Test
	public void testShowReferences() {
		setRowSelection(equatesTable, 1, 1);// this triggers the refs table to update
		waitForSwing();

		Equate eq = equatesModel.getEquate(1);
		assertEquals(et.getEquate("EIGHT"), eq);
		assertEquals(eq.getReferenceCount(), refsModel.getRowCount());

	}

	@Test
	public void testRefsNavigation() {
		// select a row in the refs table; the browser should go there	

		setRowSelection(equatesTable, 1, 1);

		Address equateAddress = (Address) refsModel.getValueAt(0, 0);
		changeSelectionToNavigate(refsTable, 0, 0);

		ProgramLocation location = cb.getCurrentLocation();
		assertEquals(equateAddress, location.getAddress());
		assertTrue(location instanceof OperandFieldLocation);
	}

	private void changeSelectionToNavigate(GhidraTable table, int row, int col) {

		// Note: due to focus issues, we will call navigate directly

		runSwing(() -> table.navigate(row, col));
	}

	@Test
	public void testReferencesTableUpdates() {
		setRowSelection(equatesTable, 1, 1);

		Object value = refsTable.getValueAt(0, 0);
		assertNotNull(
			"No value found in equates reference table when row selected in the equates table",
			value);
		Address reference = (Address) value;
		assertEquals("Did not get expected value in refs table for selection in equates table",
			"010064c5", reference.toString());

		setRowSelection(equatesTable, 2, 2);
		value = refsTable.getValueAt(0, 0);
		assertNotNull(
			"No value found in equates reference table when row selected in the equates table",
			value);
		reference = (Address) value;
		assertEquals("Did not get expected value in refs table for selection in equates table",
			"01006455", reference.toString());
	}

	@Test
	public void testAddEquateReference() throws Exception {
		// add another equate reference; the reference count should update.

		Equate eq = equatesModel.getEquate(2);
		TableCellRenderer renderer = getRenderer(EquateTableModel.REFS_COL);
		String value = getRenderedValue(renderer, 2, EquateTableModel.REFS_COL);
		assertEquals("2", value);

		int transactionID = program.startTransaction("test");
		eq.addReference(getAddr(0x0100248c), 0);
		endTransaction(transactionID);

		value = getRenderedValue(renderer, 2, EquateTableModel.REFS_COL);
		assertEquals("3", value);

		undo();
		value = getRenderedValue(renderer, 2, EquateTableModel.REFS_COL);
		assertEquals("2", value);

		redo();
		value = getRenderedValue(renderer, 2, EquateTableModel.REFS_COL);
		assertEquals("3", value);
	}

	@Test
	public void testRemoveEquateReference() throws Exception {
		Equate eq = equatesModel.getEquate(3);

		int transactionID = program.startTransaction("test");
		// remove an equate reference; the reference count should update.
		eq.removeReference(getAddr(0x0100621d), 1);
		endTransaction(transactionID);

		TableCellRenderer renderer = getRenderer(EquateTableModel.REFS_COL);
		String value = getRenderedValue(renderer, 3, EquateTableModel.REFS_COL);
		assertEquals("3", value);

		undo();
		value = getRenderedValue(renderer, 3, EquateTableModel.REFS_COL);
		assertEquals("4", value);

		redo();
		value = getRenderedValue(renderer, 3, EquateTableModel.REFS_COL);
		assertEquals("3", value);
	}

	@Test
	public void testRemovingEquateRemovesFromTable() throws Exception {
		// remove an equate with a single reference; the table should remove
		// the entry from the table.

		Equate eq = equatesModel.getEquate(0);

		TableCellRenderer renderer = getRenderer(EquateTableModel.REFS_COL);
		String value = getRenderedValue(renderer, 0, EquateTableModel.REFS_COL);
		assertEquals("1", value);
		int rowCount = equatesModel.getRowCount();

		tool.execute(new RemoveEquateCmd(eq.getName(), tool), program);
		waitForProgram(program);
		waitForSwing();

		assertEquals(rowCount - 1, equatesModel.getRowCount());
		eq = equatesModel.getEquate(0);
		assertEquals("EIGHT", eq.getName());

		undo();
		assertEquals(rowCount, equatesModel.getRowCount());
		eq = equatesModel.getEquate(0);
		assertEquals("ANOTHER_ONE", eq.getName());

		redo();
		assertEquals(rowCount - 1, equatesModel.getRowCount());
		eq = equatesModel.getEquate(0);
		assertEquals("EIGHT", eq.getName());
	}

	@Test
	public void testEquateTableDeleteEquate() throws Exception {
		// delete an equate using the table
		// select equate TWO
		int rowCount = equatesModel.getRowCount();
		setRowSelection(equatesTable, 5, 5);
		Equate eq = equatesModel.getEquate(5);

		assertEquals("TWO", eq.getName());

		DockingActionIf pluginAction = getAction(plugin, "Delete Equate");
		assertNotNull(pluginAction);
		assertTrue(pluginAction.isEnabled());
		performAction(pluginAction, false);

		OptionDialog d = waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		assertNotNull(d);
		assertEquals("Delete Equate?", d.getTitle());

		pressButtonByText(d.getComponent(), "Delete");
		waitForProgram(program);
		waitForSwing();

		assertEquals(rowCount - 1, equatesModel.getRowCount());
		eq = equatesModel.getEquate(5);
		assertEquals("TWO_alt", eq.getName());

		undo();
		assertEquals(rowCount, equatesModel.getRowCount());
		eq = equatesModel.getEquate(5);
		assertEquals("TWO", eq.getName());

		redo();
		assertEquals(rowCount - 1, equatesModel.getRowCount());
		eq = equatesModel.getEquate(5);
		assertEquals("TWO_alt", eq.getName());
	}

	@Test
	public void testEquateTableDeleteCancel() throws Exception {
		// select equate TWO
		int rowCount = equatesModel.getRowCount();
		setRowSelection(equatesTable, 5, 5);
		Equate eq = equatesModel.getEquate(5);
		assertEquals("TWO", eq.getName());

		DockingActionIf pluginAction = getAction(plugin, "Delete Equate");
		assertNotNull(pluginAction);
		assertTrue(pluginAction.isEnabled());
		performAction(pluginAction, false);

		OptionDialog d = waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		assertNotNull(d);
		assertEquals("Delete Equate?", d.getTitle());

		pressButtonByText(d.getComponent(), "Cancel");
		eq = equatesModel.getEquate(5);
		assertEquals("TWO", eq.getName());

		assertEquals(rowCount, equatesModel.getRowCount());
	}

	@Test
	public void testProgramClosed() {
		env.close(program);

		assertEquals(0, equatesModel.getRowCount());
		assertEquals(0, refsModel.getRowCount());
	}

//==================================================================================================
// Private methods
//==================================================================================================	

	private void setRowSelection(JTable table, int rowStart, int rowEnd) {
		waitForSwing();
		runSwing(() -> table.setRowSelectionInterval(rowStart, rowEnd));
	}

	private TableCellRenderer getRenderer(int column) {
		TableCellRenderer renderer = equatesTable.getCellRenderer(0, column);
		return renderer;
	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private void showProvider() {
		provider = plugin.getProvider();

		tool.showComponentProvider(provider, true);

		equatesTable = provider.getEquatesTable();
		refsTable = provider.getReferencesTable();
		equatesModel = provider.getEquatesModel();
		refsModel = (EquateReferenceTableModel) refsTable.getModel();
	}

	private void endTransaction(int transactionID) throws Exception {
		program.endTransaction(transactionID, true);
		waitForProgram(program);
	}

	private void undo() throws Exception {
		undo(program);
		waitForProgram(program);
	}

	private void redo() throws Exception {
		redo(program);
		waitForProgram(program);
	}

	private void checkTableValues() throws Exception {
		Iterator<Equate> iter = et.getEquates();
		List<Equate> list = CollectionUtils.asList(iter);

		Collections.sort(list, (e1, e2) -> e1.getName().compareTo(e2.getName()));
		assertEquals(list.size(), equatesModel.getRowCount());

		TableCellRenderer nameRenderer = getRenderer(EquateTableModel.NAME_COL);
		TableCellRenderer valueRenderer = getRenderer(EquateTableModel.VALUE_COL);
		TableCellRenderer refCountRenderer = getRenderer(EquateTableModel.REFS_COL);

		for (int i = 0; i < list.size(); i++) {

			Equate eq = list.get(i);
			Rectangle rect = equatesTable.getCellRect(i, EquateTableModel.NAME_COL, true);
			runSwing(() -> equatesTable.scrollRectToVisible(rect));

			String value = getRenderedValue(nameRenderer, i, EquateTableModel.NAME_COL);
			assertEquals("Name not equal at index: " + i, eq.getName(), value);

			// The value column is default-rendered as hex
			value = getRenderedValue(valueRenderer, i, EquateTableModel.VALUE_COL);
			assertEquals("Value not equal at index: " + i, Long.toHexString(eq.getValue()) + "h",
				value);

			value = getRenderedValue(refCountRenderer, i, EquateTableModel.REFS_COL);
			assertEquals("Reference count not equal at index: " + i,
				Integer.toString(eq.getReferenceCount()), value);
		}
	}

	private String getRenderedValue(TableCellRenderer renderer, int row, int column) {
		return runSwing(() -> {

			Object value = equatesTable.getValueAt(row, column);

			return ((JLabel) renderer.getTableCellRendererComponent(equatesTable, value, false,
				false, row, column)).getText().trim();
		});
	}

}
