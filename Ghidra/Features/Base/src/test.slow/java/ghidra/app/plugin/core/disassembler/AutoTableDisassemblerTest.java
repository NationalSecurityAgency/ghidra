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
package ghidra.app.plugin.core.disassembler;

import static org.junit.Assert.*;

import java.awt.Component;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.TaskUtilities;
import ghidra.util.TrackedTaskListener;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.Task;
import utility.function.Callback;

public class AutoTableDisassemblerTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private DockingActionIf searchAction;
	private AutoTableDisassemblerPlugin plugin;
	private CodeBrowserPlugin cb;

	private TestTaskListener taskListener = new TestTaskListener();

	private AddressTableDialog dialog;
	private JButton makeTable;
	private JButton search;
	private JButton disassemble;
	private GTable table;
	private JTextField viewOffset;
	private JTextField offset;
	private JTextField alignment;
	private JCheckBox autoLabel;
	private JCheckBox searchSelection;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);
		plugin = env.getPlugin(AutoTableDisassemblerPlugin.class);

		TaskUtilities.addTrackedTaskListener(taskListener);

		performAction(searchAction);
		dialog = waitForDialogComponent(AddressTableDialog.class);
		makeTable = findButtonByText(dialog, "Make Table");
		search = findButtonByText(dialog, "Search");
		disassemble = findButtonByText(dialog, "Disassemble");
		table = findComponent(dialog, GTable.class);

		viewOffset = (JTextField) findComponentByName(dialog.getComponent(), "viewOffset");
		offset = (JTextField) findComponentByName(dialog.getComponent(), "offset");
		alignment = (JTextField) findComponentByName(dialog.getComponent(), "Alignment");
		autoLabel = (JCheckBox) findAbstractButtonByText(dialog.getComponent(), "Auto Label");
		searchSelection =
			(JCheckBox) findAbstractButtonByText(dialog.getComponent(), "Search Selection");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testBasicState() throws Exception {

		// do the search
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertTable(model, "00401030", "00402434", "004024ac", "00402518", "004035e8", "00403870",
			"004038b0");

		// select a result and make a table
		selectRow(0, 0);
		assertTrue(makeTable.isEnabled());
		assertTrue(disassemble.isEnabled());
		waitFor(() -> pressButton(makeTable));

		select("00401030");
		selectRow(0, 0);

		Symbol s = getUniqueSymbol(program, "AddrTable00401030");
		assertNotNull(s);
		assertEquals(addr("0x0401030"), s.getAddress());

		Listing l = program.getListing();
		Data d = l.getDataAt(addr("0x401030"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x401034"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x401038"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x40103c"));
		assertTrue(d.getDataType() instanceof Pointer);

		// disassemble
		waitFor(() -> pressButton(disassemble));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x401030")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x401034")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x401038")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x40103c")).getAddress(0)));

		// make table at 00403870 - this one tests that the index does not go past the elements when the
		// elements are valid index values (ie. the bytes pointed to by the table are values from 0 - len-1)
		select("00403870");
		assertEnabled(makeTable, true);
		assertEnabled(disassemble, true);
		waitFor(() -> pressButton(makeTable));
		s = getUniqueSymbol(program, "AddrTable00403870", null);
		assertNotNull(s);
		assertEquals(addr("0x0403870"), s.getAddress());

		// test that table elements made and labeled correctly
		l = program.getListing();
		d = l.getDataAt(addr("0x403870"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x403874"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x403878"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x40387c"));
		assertTrue(d.getDataType() instanceof Pointer);

		// test that index found and that byte array was made
		d = l.getDataAt(addr("0x403880"));
		assertTrue(d.isArray());
		DataType dt = d.getBaseDataType();
		assertEquals("byte[8]", dt.getName());
		s = getUniqueSymbol(program, "IndexToAddrTable00403870");
		assertNotNull(s);
		assertEquals(addr("0x0403880"), s.getAddress());

		// make table selection for 004038b0
		// this will test that index does not go past a table element when the table element occurs right after
		// the table and the data is valid index values (0 - len-1)
		select("004038b0");
		assertEnabled(makeTable, true);
		assertEnabled(disassemble, true);
		waitFor(() -> pressButton(makeTable));
		s = getUniqueSymbol(program, "AddrTable004038b0");
		assertNotNull(s);
		assertEquals(addr("0x04038b0"), s.getAddress());

		// test that table elements made and labeled correctly
		l = program.getListing();

		d = l.getDataAt(addr("0x4038b0"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038bc"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038c8"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038ec"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038b4"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038b8"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038c0"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x4038cc"));
		assertTrue(d.getDataType() instanceof Pointer);

	}

	@Test
	public void testMultiRowSelection() throws Exception {

		// do the search
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertEquals(8, model.getRowCount());
		assertEquals(addr("0x0401030"), model.getRowObject(0).getTopAddress());
		assertEquals(addr("0x0402434"), model.getRowObject(1).getTopAddress());
		assertEquals(addr("0x04024ac"), model.getRowObject(2).getTopAddress());
		assertEquals(addr("0x04024bd"), model.getRowObject(3).getTopAddress());
		assertEquals(addr("0x0402518"), model.getRowObject(4).getTopAddress());
		assertEquals(addr("0x04035e8"), model.getRowObject(5).getTopAddress());
		assertEquals(addr("0x0403870"), model.getRowObject(6).getTopAddress());
		assertEquals(addr("0x04038b0"), model.getRowObject(7).getTopAddress());

		// select a multiple results and make a table
		assertEnabled(makeTable, false);

		selectRow(0, 2);
		assertEnabled(makeTable, true);
		assertEnabled(disassemble, true);
		waitFor(() -> pressButton(makeTable));
		selectRow(0, 2);
		assertEnabled(makeTable, true);
		assertEnabled(disassemble, true);

		Symbol s = getUniqueSymbol(program, "AddrTable00401030");
		assertNotNull(s);
		assertEquals(addr("0x0401030"), s.getAddress());

		s = getUniqueSymbol(program, "AddrTable00402434");
		assertNotNull(s);
		s = getUniqueSymbol(program, "AddrTable004024ac");
		assertNotNull(s);

		Listing l = program.getListing();
		assertTrue(l.getDataAt(addr("0x401030")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x401030")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x401030")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x401030")).getDataType() instanceof Pointer);

		assertTrue(l.getDataAt(addr("0x402434")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x402438")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x40243c")).getDataType() instanceof Pointer);

		assertTrue(l.getDataAt(addr("0x4024ac")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x4024b0")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x4024b4")).getDataType() instanceof Pointer);
		assertTrue(l.getDataAt(addr("0x4024b8")).getDataType() instanceof Pointer);

		// disassemble

		int[] selectedRows = table.getSelectedRows();
		for (int i = 0; i < selectedRows.length; i++) {
			assertTrue(selectedRows[i] == i);
		}

		// check some of the disassembly
		waitFor(() -> pressButton(disassemble));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x401030")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x401034")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x401038")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x40103c")).getAddress(0)));

		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x402434")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x402438")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x40243c")).getAddress(0)));

	}

	@Test
	public void testOffset() throws Exception {

		// do the search
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertTable(model, "00401030", "00402434", "004024ac", "00402518", "004035e8", "00403870",
			"004038b0");

		assertEnabled(makeTable, false);
		select("004038b0");
		assertEnabled(makeTable, true);
		assertEnabled(disassemble, true);

		waitFor(() -> pressButton(makeTable));

		Listing l = program.getListing();

		undo(program);
		select("00402518");
		setText(offset, "4");
		assertEnabled(makeTable, false);
		assertEnabled(disassemble, false);
		assertEquals("Invalid offset length - check table length, must be >= 0 and < 4",
			dialog.getStatusText());

		setText(offset, "1");
		assertEnabled(makeTable, true);
		assertEnabled(disassemble, true);
		assertEquals("0040251c", viewOffset.getText());

		waitFor(() -> pressButton(makeTable));

		select("00402518");

		l = program.getListing();
		Data d = l.getDataAt(addr("0x40251c"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x402520"));
		assertTrue(d.getDataType() instanceof Pointer);
		d = l.getDataAt(addr("0x402524"));
		assertTrue(d.getDataType() instanceof Pointer);

		setText(offset, "2");

		// disassemble
		waitFor(() -> pressButton(disassemble));
		assertNull(l.getInstructionAt(l.getDataAt(addr("0x40251c")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x402520")).getAddress(0)));
		assertNotNull(l.getInstructionAt(l.getDataAt(addr("0x402524")).getAddress(0)));

	}

	@Test
	public void testAlignment() {

		setText(alignment, "2");
		assertEquals("2", alignment.getText());

		// do the search
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertTable(model, "00402434", "004024b0", "00402518", "004035e8", "00403870", "004038b0");
	}

	private void waitFor(Callback c) {

		taskListener.reset();
		c.call();
		waitForCondition(() -> taskListener.started());
		waitForBusyTool(tool);
	}

	@Test
	public void testAutoLabelOff() throws Exception {

		// do the search
		pressButton(search);
		waitForSwing();
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);
		assertEquals(8, model.getRowCount());

		// note: this button is disabled
		runSwing(() -> autoLabel.setSelected(false));

		// select a result and make a table
		selectRow(0, 0);
		waitFor(() -> pressButton(makeTable));

		SymbolTable st = program.getSymbolTable();

		assertEquals(0, st.getSymbols(addr("0x0401030")).length);

		Listing l = program.getListing();
		Data d = l.getDataAt(addr("0x401030"));
		assertTrue(d.getDataType() instanceof Pointer);
		assertEquals("DAT_00401014", st.getSymbols(d.getAddress(0))[0].getName());
		d = l.getDataAt(addr("0x401034"));
		assertTrue(d.getDataType() instanceof Pointer);
		assertEquals("DAT_00401019", st.getSymbols(d.getAddress(0))[0].getName());
		d = l.getDataAt(addr("0x401038"));
		assertTrue(d.getDataType() instanceof Pointer);
		assertEquals("DAT_0040101e", st.getSymbols(d.getAddress(0))[0].getName());
		d = l.getDataAt(addr("0x40103c"));
		assertTrue(d.getDataType() instanceof Pointer);
		assertEquals("DAT_00401023", st.getSymbols(d.getAddress(0))[0].getName());
	}

	@Test
	public void testCodeSelection() {

		// do the search
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertEquals(8, model.getRowCount());

		// create a selection
		AddressSet set = new AddressSet(addr("0x405000"), addr("0x405fff"));
		set.addRange(addr("0x404000"), addr("0x404fff"));
		ProgramSelection ps = new ProgramSelection(set);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", ps, program));
		waitForSwing();

		assertTrue(searchSelection.isEnabled());
		assertTrue(searchSelection.isSelected());

		// do the search again
		pressButton(search);
		waitForModel(model);

		assertEquals(0, model.getRowCount());

		setToggleButtonSelected(searchSelection, false);
		waitForSwing();
		pressButton(search);
		waitForModel(model);

		set = new AddressSet(addr("0x403504"), addr("0x4035ff"));
		ps = new ProgramSelection(set);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", ps, program));
		waitForSwing();
		waitForModel(model);

		assertTrue(searchSelection.isEnabled());
		assertTrue(searchSelection.isSelected());

		// not sure why, but there is some threading/timing issue with the button being enabled
		// after a search has finished...I'm too lazy to figure out exactly why, so this will
		// have to do
		waitForCondition(() -> search.isEnabled());

		pressButton(search);
		model = plugin.getModel();
		waitForModel(model);
		assertEquals(1, model.getRowCount());

	}

	/**
	 * Tests that the offset fields in the AddressTableDialog are enabled
	 * when they should be.
	 * <p>
	 * This class ensures that:
	 * <ul>
	 *     <li>the offset text field is enabled when there is a selection,
	 *     <li>the auto label checkbox is enabled when there is a selection, and
	 *     <li>the minimum offset is that of the lowest length of all the
	 *         selected rows when there is a multiple selection.
	 * </ul>
	 *
	 * @since Tracker Id 488, 489, 490
	 */
	@Test
	public void testOffsetFieldsEnabled() {

		Component[] offsetButtons = new Component[] { disassemble, makeTable };
		Component[] infoFields = new Component[] { autoLabel, offset };
		Component[] offsetPanelFields =
			new Component[] { disassemble, makeTable, autoLabel, offset };

		checkOffsetFieldsEnabledState(offsetPanelFields, false);

		// now search for data
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForCondition(() -> !model.isBusy(), "Table model never finished");

		// select a row
		table.getSelectionModel().setSelectionInterval(0, 0);

		// make sure the buttons are enabled
		checkOffsetFieldsEnabledState(offsetPanelFields, true);

		// clear the selections
		table.clearSelection();

		// make sure the buttons are disabled
		checkOffsetFieldsEnabledState(offsetPanelFields, false);

		// now check that an invalid entry into the offset field does not
		// improperly disable the fields
		table.getSelectionModel().setSelectionInterval(0, 0);

		// set the text to an invalid value, which will trigger an exception
		// and an error message
		setOffset(offset, "f");
		checkOffsetFieldsEnabledState(infoFields, true);
		checkOffsetFieldsEnabledState(offsetButtons, false);

		// make sure a selection with an invalid length is caught
		// for a single selection

		// get the selection and test
		int[] selectedRows = table.getSelectedRows();

		// make sure that only one row is selected in this test case
		assertEquals("There should be one row selected.", 1, selectedRows.length);

		// ensure that an invalid length disables the buttons
		int shortestRowsLength = getShortestRowsLength(selectedRows, model);
		setOffset(offset, Integer.toString(shortestRowsLength));
		checkOffsetFieldsEnabledState(offsetButtons, false);

		// now make sure that a valid value enables the buttons
		setOffset(offset, Integer.toString(shortestRowsLength - 1));
		checkOffsetFieldsEnabledState(offsetButtons, true);

		// now make sure that a valid value enables the buttons
		setOffset(offset, Integer.toString(0));
		checkOffsetFieldsEnabledState(offsetButtons, true);

		// make sure a selection with an invalid length is caught
		// for a multiple selection
		table.getSelectionModel().setSelectionInterval(1, 2);

		// get the selection and test
		selectedRows = table.getSelectedRows();

		// make sure that multiple rows are selected in this test case
		assertEquals("There should be one row selected.", 2, selectedRows.length);

		// ensure that an invalid length disables the buttons
		shortestRowsLength = getShortestRowsLength(selectedRows, model);
		setOffset(offset, Integer.toString(shortestRowsLength));
		checkOffsetFieldsEnabledState(offsetButtons, false);

		// now make sure that a valid value enables the buttons
		setOffset(offset, Integer.toString(shortestRowsLength - 1));
		checkOffsetFieldsEnabledState(offsetButtons, true);

		// now make sure that a valid value enables the buttons
		setOffset(offset, Integer.toString(0));
		checkOffsetFieldsEnabledState(offsetButtons, true);
	}

	@Test
	public void testSelectionNavigation() throws Exception {

		// do the search
		pressButton(search);
		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertEquals(8, model.getRowCount());
		runSwing(() -> table.clearSelection());

		int row = 0;
		changeSelectionToNavigate(table, row);
		Address currentAddress = cb.getCurrentAddress();

		AddressBasedLocation location =
			(AddressBasedLocation) runSwing(() -> table.getValueAt(row, 0));
		assertEquals("The code browser is not at the address of the selected row.", currentAddress,
			location.getAddress());

		int nextRow = row + 1;
		changeSelectionToNavigate(table, nextRow);
		currentAddress = cb.getCurrentAddress();
		location = (AddressBasedLocation) runSwing(() -> table.getValueAt(nextRow, 0));
		assertEquals("The code browser is not at the address of the selected row.", currentAddress,
			location.getAddress());

		int thirdRow = nextRow + 1;
		changeSelectionToNavigate(table, thirdRow);
		currentAddress = cb.getCurrentAddress();
		location = (AddressBasedLocation) runSwing(() -> table.getValueAt(thirdRow, 0));
		assertEquals("The code browser is not at the address of the selected row.", currentAddress,
			location.getAddress());
	}

	@Test
	public void testMakeSelection() throws Exception {

		pressButton(search);
		waitForSwing();

		AutoTableDisassemblerModel model = plugin.getModel();
		waitForModel(model);

		assertEquals(8, model.getRowCount());

		select("00401030", "004024ac", "00403870");

		// make the selection
		JButton button = getActionButton("Make Selection");
		assertNotNull(button);
		pressButton(button);

		CodeBrowserPlugin cbPlugin = getPlugin(tool, CodeBrowserPlugin.class);
		ProgramSelection currentSelection = cbPlugin.getCurrentSelection();

		AddressRangeIterator iter = currentSelection.getAddressRanges();
		assertNotNull(iter);

		// check each of the selected address ranges
		assertTrue(iter.hasNext());
		AddressRange ar = iter.next();
		assertEquals(program.getMinAddress().getNewAddress(0x401030), ar.getMinAddress());
		assertEquals(program.getMinAddress().getNewAddress(0x40103f), ar.getMaxAddress());

		assertTrue(iter.hasNext());
		ar = iter.next();
		assertEquals(program.getMinAddress().getNewAddress(0x4024ac), ar.getMinAddress());
		assertEquals(program.getMinAddress().getNewAddress(0x4024bb), ar.getMaxAddress());

		assertTrue(iter.hasNext());
		ar = iter.next();
		assertEquals(program.getMinAddress().getNewAddress(0x403870), ar.getMinAddress());
		assertEquals(program.getMinAddress().getNewAddress(0x403887), ar.getMaxAddress());
		assertTrue(!iter.hasNext());
	}

	private void changeSelectionToNavigate(GTable gTable, int row) {

		// Note: due to focus issues, we will call navigate directly

		runSwing(() -> ((GhidraTable) table).navigate(row, 0));
		waitForSwing();
	}

	private JButton getActionButton(String actionName) {
		Map<?, ?> actionMap = (Map<?, ?>) getInstanceField("actionMap", dialog);
		Set<?> entrySet = actionMap.entrySet();
		for (Object entry : entrySet) {
			Map.Entry<?, ?> mapEntry = (Map.Entry<?, ?>) entry;
			DockingAction action = (DockingAction) mapEntry.getKey();
			if (actionName.equals(action.getName())) {
				return (JButton) mapEntry.getValue();
			}
		}
		return null;
	}

	private void waitForModel(AutoTableDisassemblerModel model) {
		waitForTableModel(model);
		waitForSwing();
	}

	private void assertTable(AutoTableDisassemblerModel model, String... addrs) {
		List<String> modelAddresses = new ArrayList<>();
		int count = model.getRowCount();
		for (int i = 0; i < count; i++) {
			modelAddresses.add(model.getValueAt(i, 0).toString());
		}

		for (String addr : addrs) {
			assertTrue("Table model does not contain address table address: " + addr,
				modelAddresses.contains(addr));
		}
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(AutoTableDisassemblerPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		cb = getPlugin(tool, CodeBrowserPlugin.class);
		Plugin p = getPlugin(tool, AutoTableDisassemblerPlugin.class);
		searchAction = getAction(p, "Search for Address Tables");

		env.showTool();
		loadProgram();
	}

	private void loadProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("TestGhidraSearches", ProgramBuilder._X86);
		builder.createMemory(".text", "0x00401000", 0x3000);

		// table at 00401030 4 bytes
		builder.setBytes("0x00401024",
			"48 00 00 00 e8 53 00 00 00 33 c0 c3 14 10 40 00 19 10 40 00 1e 10 40 00 23 10 " +
				"40 00 33 c0 33 c9 03 c1 41 83 f9 04 7c f8 c3");

		// table at 00402434 3
		builder.setBytes("0x00402429",
			"40 00 90 ff 24 8d ac 24 40 00 90 40 24 40 00 6c 24 40 00 90 24 40 00 23 d1 8a " +
				"06 88 07  8a");

		// two tables at 004024ac 8 and at 004024b0 7 (alignment 2)
		builder.setBytes("0x004024a5",
			"18 25 40 00 8d 49 00 0f 25 40 00 fc 24 40 00 f4 24 40 00 ec 24 40 00 00 e4 24 " +
				"40 00 dc 24 40 00 cc 24 40 00 8b 44 8e e4 89 44 8f");

		// table at 00402518 4
		builder.setBytes("0x00402510",
			"24 95 18 25 40 00 8b ff 28 25 40 00 30 25 40 00 3c 25 40 00 50 25 40 00 8b 45 " +
				"08 5e 5f c9");

		// table at 004035e8 4
		builder.setBytes("0x004035df",
			"ff 24 95 e8 35 40 00 8b ff f8 35 40 00 00 36 40 00 0c 36 40 00 20 36 40 00 8b " +
				"45 08 5e 5f c9 c3 90");

		// table at 00403870 4
		builder.setBytes("0x0040386c",
			"40 00 00 00 88 38 40 00 8c 38 40 00 90 38 40 00 94 38 40 00 01 02 03 00 02 03 " +
				"01 00 00 00");

		// table at 004038b0 16
		builder.setBytes("0x004038ab",
			"00 00 00 00 00 f0 38 40 00 f4 38 40 00 f8 38 40 00 f0 38 40 00 fc 38 40 00 00 " +
				"39 40 00 f0 38 40 00 04 39 40 00 08 39 40 00 0c 39 40 00 10 39 40 00 1c 39 40 " +
				"00 14 39 40 00 18 39 40 00 20 39 40 00 f0 38 40 00 00 00 00 00 00");

		// some reference 'to' data
		builder.setBytes("0x00401014", "e8 27 00 00 00 e8 32 00 00 00 e8 4d 00 00 00");

		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private void setOffset(final JTextField offsetField, final String offsetValue) {
		runSwing(() -> offsetField.setText(offsetValue));
	}

	private int getShortestRowsLength(int[] selectedRows, AutoTableDisassemblerModel model) {
		int shortestLength = Integer.MAX_VALUE;
		for (int element : selectedRows) {
			int length = model.getTableLength(element);
			shortestLength = Math.min(shortestLength, length);
		}
		return shortestLength;
	}

	private void checkOffsetFieldsEnabledState(Component[] components, boolean expectedState) {
		for (Component element : components) {
			String enabledString = expectedState ? "not enabled" : "enabled";
			assertEquals(
				"One of the offset panel's fields is " + enabledString + " when it should not be.",
				expectedState, element.isEnabled());
		}
	}

	private void select(String... addrs) {
		List<Integer> rows = new ArrayList<>();
		for (String addr : addrs) {
			rows.add(getRow(addr));
		}

		ListSelectionModel model = table.getSelectionModel();
		model.clearSelection();
		for (Integer row : rows) {
			model.addSelectionInterval(row, row);
		}
	}

	private void select(String addr) {
		int row = getRow(addr);
		selectRow(row, row);
	}

	private int getRow(String addr) {
		int count = table.getRowCount();
		for (int i = 0; i < count; i++) {
			Object value = table.getValueAt(i, 0);
			if (addr.equals(value.toString())) {
				return i;
			}
		}

		Assert.fail("Could not find address in table " + addr);
		return -1;// can't get here
	}

	private void selectRow(final int rowStart, final int rowEnd) {
		waitForSwing();
		runSwing(() -> table.setRowSelectionInterval(rowStart, rowEnd));
	}

	private class TestTaskListener implements TrackedTaskListener {

		private AtomicInteger started = new AtomicInteger();

		@Override
		public void taskAdded(Task task) {
			started.incrementAndGet();
		}

		@Override
		public void taskRemoved(Task task) {
			// don't care
		}

		void reset() {
			started.set(0);
		}

		boolean started() {
			return started.get() > 0;
		}
	}
}
