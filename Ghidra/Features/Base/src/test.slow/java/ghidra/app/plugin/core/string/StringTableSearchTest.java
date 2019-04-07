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
package ghidra.app.plugin.core.string;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Container;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.widgets.table.TableSortState;
import docking.widgets.textfield.IntegerTextField;
import generic.test.TestUtils;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramSelection;
import ghidra.program.util.string.FoundString;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.table.field.CodeUnitTableCellData;

public class StringTableSearchTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private Listing listing;

	private StringTablePlugin plugin;
	private NavigatableContextAction searchAction;
	private SearchStringDialog dialog;

	int addressColumnIndex = 1;
	int labelColumnIndex = 2;
	int previewColumnIndex = 3;
	int asciiColumnIndex = 4;
	int stringTypeColumnIndex = 5;
	int isWordColumnIndex = 7;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(StringTablePlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		plugin = env.getPlugin(StringTablePlugin.class);

		ToyProgramBuilder builder = new ToyProgramBuilder("TestGhidraSearches", false);
		builder.createMemory("test", "0x401280", 30);
		builder.createMemory("test", "0x404300", 0x2000);

		builder.setBytes("0x4040c0", "53 49 4e 47 20 65 72 72 6f 72 0a 0d 00");

		// ascii
		builder.setBytes("0x401283", "00 00 00 59 59 68 20 50 40 00 68 1c 50 40 00 e8 19");

		builder.setBytes("0x401888", "44 53 55 56 57 68 00");

		// ascii
		builder.setBytes("0x4014b7", "80 3f 3d 74 22 55 e8 2e");

		builder.setBytes("0x404328", "4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 " +
			"6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 00 00 00 00");

		builder.setBytes("0x404350", "0a 0a 00 00");

		builder.setBytes("0x404354",
			"52 75 6e 74 69 6d 65 20 45 72 72 6f 72 21 0a 0a 50 72 6f 67 " +
				"72 61 6d 3a 20 00 00 00");

		builder.setBytes("0x404370", "2e 2e 2e 00");

		builder.setBytes("0x404f26", "ff 0a 00 0d 00 53 00 74 00 72 00 69 00 6e 00 67 " +
			"00 39 00 0a 00 0d 00 00 00 00 00");

		// unicode 16
		builder.setBytes("0x404f0f",
			"00 0a 00 0d 00 53 00 74 00 72 00 69 00 6e 00 67 00 39 00 0a 00 0d 00 ff");

		// unicode 16
		builder.setBytes("0x404f40",
			"00 0a 00 0d 00 53 00 74 00 72 00 69 00 6e 00 67 00 31 00 30 00 0a 00 0d 00 " +
				"00 00 00 00 00 00 00 00 00");

		// pascal
		builder.setBytes("0x404fdc",
			"00 00 0a 0d 53 74 72 69 6e 67 36 0a 0d 00 0a 0d 53 74 72 69 " +
				"6e 67 37 0a 0d 0a 0d 53 74 72 69 6e 67 38 0a 0d 00 00 00");

		// Create an existing Unicode string to make sure its presence doesn't mess up ASCII-based
		// NgramUtils. Length must be >= 3.
		byte[] unicodeBytes = new byte[] { (byte) 0xfd, (byte) 0xff, (byte) 0xfd, (byte) 0xff,
			(byte) 0xfd, (byte) 0xff, (byte) 0xfd, (byte) 0xff, 0x00, 0x00, 0x00, 0x00 };
		builder.setBytes("0x405000", unicodeBytes);
		builder.applyDataType("0x405000", new TerminatedUnicodeDataType(), 1);

		// a series of strings
		builder.setBytes("0x40503b", "00 53 74 72 69 6e 67 32 00 53 74 72 69 6e 67 33 00 53 74 " +
			"72 69 6e 67 34 00 53 74 72 69 6e 67 35 00");

		// unicode 32
		builder.setBytes("0x405420",
			"00 00 00 0a 00 00 00 0d 00 00 00 53 00 00 00 74 00 00 00 72 00 00 00 69 00 00 00 " +
				"6e 00 00 00 67 00 00 00 39 00 00 00 0a 00 00 00 0d 00 00 00 00 00 00 00 00 00 00");

		// pascal
		builder.setBytes("0x405d80", "05 54 65 73 74 31");

		// pascal
		builder.setBytes("0x405d91", "07 00 70 32 54 65 73 74 31 07 00");

		builder.setBytes("0x405d9a", "07 00 70 32 54 65 73 74 32 00 00");

		builder.setBytes("0x405db3", "00 75 00 6e 00 75 00 6c 00 6c 00");

		builder.setBytes("0x405dfd",
			"ff ff ff 08 00 70 00 75 00 6e 00 6f 00 6e 00 75 00 6c 00 32 00 ff ff ff ff");

		program = builder.getProgram();

		listing = program.getListing();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		searchAction = (NavigatableContextAction) getAction(plugin, "Search for Strings");
		env.showTool();
	}

	@After
	public void tearDown() throws Exception {
		dialog.close();
		env.dispose();
	}

	@Test
	public void testInitialDialog() throws Exception {
		assertTrue(searchAction.isEnabled());

		dialog = getDialog();
		Container container = dialog.getComponent();

		// verify that the search selection checkbox is disabled and not selected
		JRadioButton rb = (JRadioButton) findButton(container, "Search Selection");
		assertTrue(!rb.isEnabled());
		assertTrue(!rb.isSelected());

		// verify that alignment is 1 by default
		JTextField alignment = (JTextField) findComponentByName(container, "alignDefault");
		String alignmentDef = alignment.getText();
		assertEquals("1", alignmentDef);

		// verify null terminate is turned on by default
		JCheckBox nullTerminateCB = (JCheckBox) findButton(container, "Require Null Termination");
		assertTrue(nullTerminateCB.isSelected());

		// verify pascal strings is unchecked by default
		JCheckBox pascalStringCB = (JCheckBox) findButton(container, "Pascal Strings");
		assertTrue(!pascalStringCB.isSelected());

		// verify that the Minimum Length TextField is enabled
		JLabel minLen = (JLabel) findComponentByName(container, "minLen");
		assertTrue(minLen.isEnabled());

		// verify that the minimum search length is 5
		JTextField valueFld = (JTextField) findComponentByName(container, "minDefault");
		String defMin = valueFld.getText();
		assertEquals("5", defMin);

		// verify that the Search button is enabled
		JButton searchButton = (JButton) findButton(container, "Search");
		assertTrue(searchButton.isEnabled());

		// verify that the Cancel button is enabled
		JButton cancelButton = (JButton) findButton(container, "Cancel");
		assertTrue(cancelButton.isEnabled());
	}

	/*
	 * run a search on whole program and test that the correct number of strings were
	 * found and that the correct dialog message was displayed. Also, check the first and
	 * last addresses of the found strings
	 */
	@Test
	public void testSearchWholeProgramPascal() throws Exception {
		dialog = getDialog();
		Container container = dialog.getComponent();

		// turn on pascal
		JCheckBox cb = (JCheckBox) findButton(container, "Pascal Strings");
		cb.setSelected(true);

		// turn off null Terminate box
		cb = (JCheckBox) findButton(container, "Require Null Termination");
		cb.setSelected(false);

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		// test the results size and the first entry and the last unicode and last string entry
		// they are in the list in a different order than they are in the dialog
		// the dialog shows them in address order
		// the array list has all the regular strings first and then all the unicode - each set in address order

		// first entry
		assertEquals("00404f10", getModelValue(model, 0, addressColumnIndex).toString());

		// last entry
		assertEquals("00405e00",
			getModelValue(model, model.getRowCount() - 1, addressColumnIndex).toString());

		// check the table entries in some of the rows to make sure they are
		// populated correctly

		// row [0] should be Pascal Unicode
		assertEquals(null, getModelValue(model, 0, labelColumnIndex));
		CodeUnitTableCellData data =
			(CodeUnitTableCellData) getModelValue(model, 0, previewColumnIndex);
		assertEquals("?? 0Ah", data.getDisplayString());
		assertEquals("u\"\\rString9\\n\\r\"", getModelValue(model, 0, asciiColumnIndex));

		String stringData = (String) getModelValue(model, 0, isWordColumnIndex);
		assertEquals("true", stringData);

		// row [2] should be Pascal 255
		int row = findRow(model, addr(0x404fde));
		assertEquals("00404fde", getModelValue(model, row, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, row, labelColumnIndex));
		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("?? 0Ah", data.getDisplayString());
		assertEquals("\"\\rString6\\n\\r\"", getModelValue(model, row, asciiColumnIndex));

		stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("true", stringData);

		// row [5] should be Pascal
		row = findRow(model, addr(0x405d91));
		assertEquals("00405d91", getModelValue(model, row, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, row, labelColumnIndex));

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("?? 07h", data.getDisplayString());
		assertEquals("\"p2Test1\"", getModelValue(model, row, asciiColumnIndex));

		stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("false", stringData);

		//********************************************************
		//***********TEST SELECTING ROW IN TABLE*******************
		// ********* test that selecting a row does the following:
		//**********************************************************
		selectRow(table, 0);

		// test that the row is really selected
		int[] ts = table.getSelectedRows();
		assertEquals(1, ts.length);
		assertEquals(0, ts[0]);

		// is the make string button enabled (should be)
		JButton makeStringButton = (JButton) findButton(provider.getComponent(), "Make String");
		assertTrue(makeStringButton.isEnabled());

		// is the make ascii button enabled
		JButton makeAsciiButton = (JButton) findButton(provider.getComponent(), "Make Char Array");
		assertTrue(makeAsciiButton.isEnabled());

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		toggleDefinedStateButtons(provider, true, true, false, false);
		waitForTableModel(model);
		int selectedRow = table.getSelectedRow();

		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		Data d = listing.getDataAt(addr(0x404f10));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof PascalUnicodeDataType);

		// test that the string len is correct to get the end of chars
		assertEquals(22, d.getLength());

		// test that the label was made
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x404f10));
		assertEquals("pu__String9", sym.getName());

		AddressBasedLocation location =
			(AddressBasedLocation) getModelValue(model, selectedRow, addressColumnIndex);
		Address address = location.getAddress();
		if (address.getOffset() != 0x404f10) {
			TableSortState tableSortState = model.getTableSortState();
			Msg.debug(this, "sort state = " + tableSortState); // should be address column
			List<FoundString> modelData = model.getModelData();
			Msg.debug(this,
				"selected model row address is " + address.getOffset() + " expected " + 0x404f10);
			for (int i = 0; i < modelData.size(); i++) {
				Msg.debug(this,
					"row " + i + "  addr = " + getModelValue(model, i, addressColumnIndex));
			}
			Assert.fail();
		}

		// test that the table was updated with the label and preview
		assertEquals("pu__String9", getModelValue(model, selectedRow, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, selectedRow, previewColumnIndex);
		assertEquals("p_unicode u\"\\rString9\\n\\r\"", data.getDisplayString());

		stringData = (String) getModelValue(model, selectedRow, isWordColumnIndex);
		assertEquals("true", stringData);

		// test that the String Type is correct
		assertEquals("PascalUnicode",
			getModelValue(model, selectedRow, stringTypeColumnIndex).toString());

		// check that the selected row in the table moves to the next row
		ts = table.getSelectedRows();
		assertEquals(1, ts.length);
		assertEquals(selectedRow + 1, ts[0]);

		// Test Pascal 255
		// select the fourth row
		selectRows(table, addr(0x0405d80));
		selectedRow = table.getSelectedRow();
		performAction(makeStringAction, model);

		// test that the pascal 255 string was actually made correctly
		d = listing.getDataAt(addr(0x405d80));
		dt = d.getBaseDataType();
		assertTrue(dt instanceof PascalString255DataType);

		// test that the string len is correct to get the end of chars
		assertEquals(6, d.getLength());

		// test that the label was made
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x405d80));
		assertEquals("p_Test1", sym.getName());

		// test that the table was updated with the label and preview
		assertEquals("p_Test1", getModelValue(model, selectedRow, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, selectedRow, previewColumnIndex);
		assertEquals("p_string255 \"Test1\"", data.getDisplayString());

		stringData = (String) getModelValue(model, selectedRow, isWordColumnIndex);
		assertEquals("true", stringData);

		// test that the String Type is correct
		assertEquals("PascalString255",
			getModelValue(model, selectedRow, stringTypeColumnIndex).toString());

		// Test Pascal
		// select the sixth row
		selectRows(table, addr(0x405d91));
		selectedRow = table.getSelectedRow();
		performAction(makeStringAction, model);

		// test the dialog message once the run is finished
		// test that the pascal string was actually made correctly
		d = listing.getDataAt(addr(0x405d91));
		dt = d.getBaseDataType();
		assertTrue(dt instanceof PascalStringDataType);

		// test that the string len is correct to get the end of chars
		assertEquals(9, d.getLength());

		// test that the label was made
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x405d91));
		assertEquals("p_p2Test1", sym.getName());

		// test that the table was updated with the label and preview
		assertEquals("p_p2Test1", getModelValue(model, selectedRow, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, selectedRow, previewColumnIndex);
		assertEquals("p_string \"p2Test1\"", data.getDisplayString());

		stringData = (String) getModelValue(model, selectedRow, isWordColumnIndex);
		assertEquals("false", stringData);

		// test that the String Type is correct
		assertEquals("PascalString",
			getModelValue(model, selectedRow, stringTypeColumnIndex).toString());

	}

	/*
	 * Try to run a search with first an invalid string model, then no model, to ensure that
	 * the filter and columns related to high-confidence words are not shown.
	 */
	@Test
	public void testSetInvalidWordModel() throws Exception {
		dialog = getDialog();
		Container container = dialog.getComponent();

		// set word model to an invalid model
		JTextField tf = (JTextField) findComponentByName(container, "modelDefault");
		tf.setText("DoesNotExist.sng");

		pressButtonByText(dialog.getComponent(), "Search");
		String statusText = dialog.getStatusText();
		assertEquals("Select a valid model file (e.g., 'StringModel.sng') or leave blank.",
			statusText);

		// Setting the model file to blank (or spaces) indicates we don't want a model
		// file to be used and we don't care about filtering by high-confidence words.
		tf.setText("  ");

		StringTableProvider provider = performSearch();

		ToggleDockingAction showIsWordAction =
			(ToggleDockingAction) getInstanceField("showIsWordAction", provider);
		assertNull(showIsWordAction);

		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		waitForTableModel(model);

		// There won't be an "Is Word" column because we don't have a valid model.
		// Also verify that "Ascii" column should be there.
		assertEquals(-1, model.findColumn("Is Word"));
		assertEquals(4, model.findColumn("String View"));
	}

	/*
	 * run a search on whole program and test that the correct number of strings were
	 * found and that the correct dialog message was displayed. Also, check the first and
	 * last addresses of the found strings
	 */
	@Test
	public void testSearchWholeProgramNoNull() throws Exception {

		dialog = getDialog();
		Container container = dialog.getComponent();

		// turn off null Terminate box
		JCheckBox cb = (JCheckBox) findButton(container, "Require Null Termination");
		cb.setSelected(false);

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		// test the results size and the first entry and the last unicode and last string entry
		// they are in the list in a different order than they are in the dialog the
		// dialog shows them in address order the array list has all the regular
		// strings first and then all the unicode - each set in address order first entry
		assertEquals("00401286", getModelValue(model, 0, addressColumnIndex).toString());
		// last entry
		assertEquals("00405e02",
			getModelValue(model, model.getRowCount() - 1, addressColumnIndex).toString());

		// check the table entries in some of the rows to make sure they are
		// populated correctly
		assertEquals("00401286", getModelValue(model, 0, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, 0, labelColumnIndex));

		CodeUnitTableCellData data =
			(CodeUnitTableCellData) getModelValue(model, 0, previewColumnIndex);
		assertEquals("?? 59h    Y", data.getDisplayString());

		assertEquals("\"YYh P@\"", getModelValue(model, 0, asciiColumnIndex));
		assertEquals("string", getModelValue(model, 0, stringTypeColumnIndex));

		String debug_initial_word_value_at_401286 =
			(String) getModelValue(model, 0, isWordColumnIndex);

		assertEquals("004014b8", getModelValue(model, 1, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, 1, labelColumnIndex));

		data = (CodeUnitTableCellData) getModelValue(model, 1, previewColumnIndex);
		assertEquals("?? 3Fh    ?", data.getDisplayString());
		assertEquals("\"?=t\\\"U\"", getModelValue(model, 1, asciiColumnIndex));

		int row = findRow(model, addr(0x404f41));
		assertEquals("00404f41", getModelValue(model, row, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, row, labelColumnIndex));
		assertEquals("unicode", getModelValue(model, row, stringTypeColumnIndex));

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("?? 0Ah", data.getDisplayString());
		assertEquals("u\"\\n\\rString10\\n\\r\"", getModelValue(model, row, asciiColumnIndex));

		row = findRow(model, addr(0x405423));
		assertEquals("00405423", getModelValue(model, row, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, row, labelColumnIndex));
		assertEquals("unicode32", getModelValue(model, row, stringTypeColumnIndex));

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("?? 0Ah", data.getDisplayString());
		assertEquals("U\"\\n\\rString9\\n\\r\"", getModelValue(model, row, asciiColumnIndex));

		String stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("true", stringData);

		//*******************************************
		// ********* TEST MAKE STRING ***************
		//*******************************************
		selectRow(table, 0);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		Data d = listing.getDataAt(addr(0x401286));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof StringDataType);
		assertEquals("YYh P@", d.getValue());

		// test that the string len is correct to get the end of chars
		assertEquals(7, d.getLength());

		// test that the label was made
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x401286));
		assertEquals("s_YYh_P@", sym.getName());

		// test that the table was updated with the label and preview
		assertEquals("s_YYh_P@", getModelValue(model, 0, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, 0, previewColumnIndex);
		assertEquals("ds \"YYh P@\"", data.getDisplayString());

		stringData = (String) getModelValue(model, 0, isWordColumnIndex);

		// TODO this is debug for issue that is timing or real bug
		if ("true".equals(stringData)) {
			// the test is about to fail--diagnose
			System.out.println("Word value at 0x401286 is not true, but expected false.\nThe " +
				"initial value at the start of the test was " + debug_initial_word_value_at_401286);

		}

		// TODO debug
		System.out.println("\n\nWord value at 0x401286 is expected false.\n\tThe " +
			"initial value at the start of the test was " + debug_initial_word_value_at_401286 +
			"\n\tThe current value is: " + stringData);
		FoundStringWithWordStatus foundString =
			(FoundStringWithWordStatus) getModelRowObject(model, 0);

		System.out.println("Last-loaded model path: " + NGramUtils.getLastLoadedTrigramModelPath());

		StringAndScores candidateString = new StringAndScores(
			foundString.getString(program.getMemory()), NGramUtils.isLowerCaseModel());
		NGramUtils.scoreString(candidateString);
		boolean isWord = candidateString.isScoreAboveThreshold();
		double score = candidateString.getNgramScore();
		double threshold = candidateString.getScoreThreshold();
		System.out.println(
			"\tisWord? " + isWord + "\n\tscore: " + score + "\n\tthreshold: " + threshold + "\n\n");

		System.out.println("found string in model: " + foundString + "\n" + "StringAndScores: " +
			candidateString + "\n\n");

		assertEquals("false", stringData);

		// check that the selected row in the table moves to the next row
		int[] selectedRows = table.getSelectedRows();
		assertEquals(1, selectedRows.length);
		assertEquals(1, selectedRows[0]);

		//***********************************************************
		// ********* TEST MAKE ASCII ********************************
		//***********************************************************

		// select the second row
		selectRow(table, 1);

		DockingAction makeAsciiAction =
			(DockingAction) getInstanceField("makeCharArrayAction", provider);

		performAction(makeAsciiAction, model);

		// test that the ascii array was actually made correctly
		d = listing.getDataAt(addr(0x4014b8));
		dt = d.getBaseDataType();
		assertEquals("char[5]", dt.getName());

		// test to make sure that 5 ascii chars were created
		assertEquals(5, d.getLength());

		// test that the label was made
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x4014b8));
		assertEquals("s_?=t\"U", sym.getName());

		// test that the table was updated with the label and preview
		assertEquals("s_?=t\"U", getModelValue(model, 1, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, 1, previewColumnIndex);
		assertEquals("char[5] \"?=t\\\"U\"", data.getDisplayString());

		stringData = (String) getModelValue(model, 1, isWordColumnIndex);
		assertEquals("false", stringData);

		// check that the selected row in the table moves to the next row
		selectedRows = table.getSelectedRows();
		assertEquals(1, selectedRows.length);
		assertEquals(2, selectedRows[0]);

		//*************************************************************
		// ********* TEST MAKE unicode STRING      ********************
		//*************************************************************

		row = findRow(model, addr(0x404f41));
		selectRow(table, row);

		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		d = listing.getDataAt(addr(0x404f41));
		assertEquals(26, d.getLength());

		assertEquals("\n\rString10\n\r", d.getValue());

		dt = d.getBaseDataType();
		assertEquals("unicode", dt.getName());

		// test that the label was made correctly
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x404f41));
		assertEquals("u__String10", sym.getName());

		// test that the table was updated with the label and preview
		assertEquals("u__String10", getModelValue(model, row, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("unicode u\"\\n\\rString10\\n\\r\"", data.getDisplayString());

		stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("true", stringData);

		//*************************************************************
		// ********* TEST MAKE UNICODE32 STRING      ********************
		//*************************************************************

		row = findRow(model, addr(0x405423));
		selectRow(table, row);

		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		d = listing.getDataAt(addr(0x405423));
		assertEquals(48, d.getLength());

		assertEquals("\n\rString9\n\r", d.getValue());

		dt = d.getBaseDataType();
		assertEquals("unicode32", dt.getName());

		// test that the label was made correctly
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x405423));
		assertEquals("u__String9", sym.getName());

		// test that the table was updated with the label and preview
		assertEquals("u__String9", getModelValue(model, row, labelColumnIndex).toString());

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("unicode32 U\"\\n\\rString9\\n\\r\"", data.getDisplayString());

		stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("true", stringData);
	}

	/*
	 * Run a search on whole program with the 'Filter: Only Show High Confidence Word Strings'
	 * button toggled on. Test that the correct strings were found at the expected addresses.
	 */
	@Test
	public void testSearchWholeProgramOnlyWords() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);

		toggleDefinedStateButtons(provider, true, true, false, false, true);
		waitForTableModel(model);

		// first entry
		Address expectedAddress = addr(0x4040c0);
		AddressBasedLocation location =
			(AddressBasedLocation) getModelValue(model, 0, addressColumnIndex);
		if (!expectedAddress.equals(location.getAddress())) {
			printContents(model);
		}
		assertEquals(expectedAddress, location.getAddress());

		// last entry
		assertEquals("00405db4",
			getModelValue(model, model.getRowCount() - 1, addressColumnIndex).toString());

		// check the table entries in some of the rows to make sure they are
		// populated correctly

		// row [0]
		assertEquals(null, getModelValue(model, 0, labelColumnIndex));

		CodeUnitTableCellData data =
			(CodeUnitTableCellData) getModelValue(model, 0, previewColumnIndex);
		assertEquals("?? 53h    S", data.getDisplayString());
		assertEquals("\"SING error\\n\\r\"", getModelValue(model, 0, asciiColumnIndex));

		String stringData = (String) getModelValue(model, 0, isWordColumnIndex);
		assertEquals("true", stringData);

		// row [1]
		int row = findRow(model, addr(0x404328));
		assertEquals("00404328", getModelValue(model, row, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, row, labelColumnIndex));

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("?? 4Dh    M", data.getDisplayString());
		assertEquals("\"Microsoft Visual C++ Runtime Library\"",
			getModelValue(model, row, asciiColumnIndex));

		stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("true", stringData);

		// row [6]
		row = findRow(model, addr(0x404fde));
		assertEquals("00404fde", getModelValue(model, row, addressColumnIndex).toString());
		assertEquals(null, getModelValue(model, row, labelColumnIndex));

		data = (CodeUnitTableCellData) getModelValue(model, row, previewColumnIndex);
		assertEquals("?? 0Ah", data.getDisplayString());
		assertEquals("\"\\n\\rString6\\n\\r\"", getModelValue(model, row, asciiColumnIndex));

		stringData = (String) getModelValue(model, row, isWordColumnIndex);
		assertEquals("true", stringData);

		//********************************************************
		//***********TEST SELECTING ROW IN TABLE*******************
		// ********* test that selecting a row does the following:
		//**********************************************************
		selectRow(table, 0);

		// test that the row is really selected
		int[] ts = table.getSelectedRows();
		assertEquals(1, ts.length);
		assertEquals(0, ts[0]);

		// is the make string button enabled (should be)
		JButton makeStringButton = (JButton) findButton(provider.getComponent(), "Make String");
		assertTrue(makeStringButton.isEnabled());

		// is the make ascii button enabled
		JButton makeAsciiButton = (JButton) findButton(provider.getComponent(), "Make Char Array");
		assertTrue(makeAsciiButton.isEnabled());

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		int selectedRow = table.getSelectedRow();

		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		Data d = listing.getDataAt(addr(0x4040c0));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof StringDataType);

		// test that the string len is correct to get the end of chars
		assertEquals(13, d.getLength());

		// check that the selected row in the table moves to the next row
		ts = table.getSelectedRows();
		assertEquals(1, ts.length);
		assertEquals(selectedRow + 1, ts[0]);

		// select the fourth row
		selectRows(table, addr(0x0404f27));
		selectedRow = table.getSelectedRow();
		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		d = listing.getDataAt(addr(0x404f27));
		dt = d.getBaseDataType();
		assertTrue(dt instanceof UnicodeDataType);

		// test that the string len is correct to get the end of chars
		assertEquals(24, d.getLength());

		// test that the String Type is correct
		assertEquals("unicode",
			getModelValue(model, selectedRow, stringTypeColumnIndex).toString());
	}

	@Test
	public void testIncludeAlignmentBytes() throws Exception {
		/***************************************************************************/
		/* TEST 6 - test include alignment nulls with various sized alignments */
		/***********************************************************************/
		final AddressSet set = new AddressSet();
		set.addRange(addr(0x404328), addr(0x404375));

		// select the address set
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Test", new ProgramSelection(set), program));

		waitForPostedSwingRunnables();

		dialog = getDialog();
		Container container = dialog.getComponent();

		// check to make sure the search selection button is checked and enabled
		JRadioButton rb = (JRadioButton) findButton(container, "Search Selection");
		assertTrue(rb.isSelected());
		assertTrue(rb.isEnabled());

		setMinStringFieldValue(dialog, 2);

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);

		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);

		// verify that rows  points to the correct address
		assertEquals("00404328", getModelValue(model, 0, addressColumnIndex).toString());
		assertEquals("00404350", getModelValue(model, 1, addressColumnIndex).toString());
		assertEquals("00404354", getModelValue(model, 2, addressColumnIndex).toString());
		assertEquals("00404370", getModelValue(model, 3, addressColumnIndex).toString());
		selectRows(table, addr(0x404328), addr(0x404350), addr(0x404354), addr(0x404370));

		// select the Include Alignment Nulls option
		JCheckBox includeAlignNullsCB =
			(JCheckBox) findButton(provider.getComponent(), "Include Alignment Nulls");
		assertTrue(includeAlignNullsCB.isEnabled());
		assertTrue(!includeAlignNullsCB.isSelected());
		includeAlignNullsCB.setSelected(true);

		setAlignmentValue(provider, 4);

		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);

		waitForTableModel(model);

		performAction(makeStringAction, model);

		//Test that the correct amount of bytes get sucked up with the alignment option
		Data d = listing.getDataAt(addr(0x404370));
		assertEquals(4, d.getLength());

		d = listing.getDataAt(addr(0x404328));
		assertEquals(40, d.getLength());

		d = listing.getDataAt(addr(0x404350));
		assertEquals(4, d.getLength());

		d = listing.getDataAt(addr(0x404354));
		assertEquals(28, d.getLength());

	}

	/*
	 * run a search on whole program and test that the correct number of strings were
	 * found and that the correct dialog message was displayed. Also, check the first and
	 * last addresses of the found strings
	 */
	@Test
	public void testSearchWholeProgramNullAlligned() throws Exception {
		dialog = getDialog();

		// check to make sure the search selection button is checked and enabled
		setAlignmentFieldValue(dialog, 4);

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);

		// test the results size and the first entry and the last unicode and last string entry
		// they are in the list in a different order than they are in the dialog
		// the dialog shows them in address order
		// the array list has all the regular strings first and then all the unicode - each set in address order

		// first entry
		assertEquals("00401888", getModelValue(model, 0, addressColumnIndex).toString());
		// last entry
		assertEquals("00405db4",
			getModelValue(model, model.getRowCount() - 1, addressColumnIndex).toString());

	}

	@Test
	public void testOffsets() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);

		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		//*************************************************************
		// ********* test offsets with unicode string *****************
		//*************************************************************

		selectRows(table, addr(0x404f27));

		//	  ******* TEST MAKE UNICODE WITH VARIOUS OFFSETS

		// change the offset in the offset text field
		setOffsetFieldValue(provider, 1);

		Msg.debug(this, "selected row count: " + table.getSelectedRowCount());
		int selectedRow = table.getSelectedRow();
		Msg.debug(this, "selected row/item after setting offset: " + selectedRow + ", item: " +
			model.getRowObject(selectedRow));

		// verify that the text in the view text field is correct
		String previewText = getPreviewText(provider);
		assertEquals("u\"\\rString9\\n\\r\"", previewText);

		setOffsetFieldValue(provider, 9);
		previewText = getPreviewText(provider);
		assertEquals("u\"\\n\\r\"", previewText);

		// test that an invalid offset length causes an error message and clears the view text
		setOffsetFieldValue(provider, 12);
		previewText = getPreviewText(provider);
		assertEquals("", previewText);

		// change it back to a correct value to see if the status message clears
		setOffsetFieldValue(provider, 10);
		previewText = getPreviewText(provider);
		assertEquals("u\"\\r\"", previewText);

		// test the making of unicode strings with offsets
		setOffsetFieldValue(provider, 2);

		assertEquals("00404f27",
			getModelValue(model, table.getSelectedRow(), addressColumnIndex).toString());

		selectedRow = table.getSelectedRow();
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		Data d = listing.getDataAt(addr(0x404f2b));

		assertEquals(20, d.getLength());

		assertEquals("String9\n\r", d.getValue());

		DataType dt = d.getBaseDataType();
		assertEquals("unicode", dt.getName());

		// test that the label was made
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x404f2b));
		assertEquals("u_String9", sym.getName());

		// make sure the selection remains on the same row, as the item was removed
		assertEquals(selectedRow, table.getSelectedRow());

		//*************************************************************
		// ********* test offsets with Unicode32 string *****************
		//*************************************************************

		selectRows(table, addr(0x405423));

		//	  ******* TEST MAKE UNICODE WITH VARIOUS OFFSETS

		// change the offset in the offset text field
		setOffsetFieldValue(provider, 1);

		Msg.debug(this, "selected row count: " + table.getSelectedRowCount());
		selectedRow = table.getSelectedRow();
		Msg.debug(this, "selected row/item after setting offset: " + selectedRow + ", item: " +
			model.getRowObject(selectedRow));

		// verify that the text in the view text field is correct
		previewText = getPreviewText(provider);
		assertEquals("U\"\\rString9\\n\\r\"", previewText);

		setOffsetFieldValue(provider, 9);
		previewText = getPreviewText(provider);
		assertEquals("U\"\\n\\r\"", previewText);

		// test that an invalid offset length causes an error message and clears the view text
		setOffsetFieldValue(provider, 12);
		previewText = getPreviewText(provider);
		assertEquals("", previewText);

		// change it back to a correct value to see if the status message clears
		setOffsetFieldValue(provider, 10);
		previewText = getPreviewText(provider);
		assertEquals("U\"\\r\"", previewText);

		// test the making of unicode strings with offsets
		setOffsetFieldValue(provider, 2);

		selectedRow = table.getSelectedRow();

		assertEquals("00405423", getModelValue(model, selectedRow, addressColumnIndex).toString());

		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		d = listing.getDataAt(addr(0x40542b));

		assertEquals(40, d.getLength());

		assertEquals("String9\n\r", d.getValue());

		dt = d.getBaseDataType();
		assertEquals("unicode32", dt.getName());

		// test that the label was made
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x40542b));
		assertEquals("u_String9", sym.getName()); // duplicate label causes address to be appended

		// make sure the selection remains on the same row, as the item was removed
		assertEquals(selectedRow, table.getSelectedRow());

		//*************************************************************
		// ********* test offsets with regular string *****************
		//*************************************************************

		selectRows(table, addr(0x404fde));

		// change the offset in the offset text field
		setOffsetFieldValue(provider, 1);

		previewText = getPreviewText(provider);
		assertEquals("\"\\rString6\\n\\r\"", previewText);

		// test that an invalid offset length causes an error message and clears the view text
		setOffsetFieldValue(provider, 12);
		previewText = getPreviewText(provider);
		assertEquals("", previewText);

		// change it back to a correct value to see if the status message clears
		setOffsetFieldValue(provider, 11);
		previewText = getPreviewText(provider);
		assertEquals("\"\"", previewText);
	}

	/*
	 * test the search selection option
	 */
	@Test
	public void testSearchSelection() throws Exception {
		// select an area known to have some strings
		AddressSet set = new AddressSet();
		set.addRange(addr(0x405d80), addr(0x405dc0));

		// select the address set
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Test", new ProgramSelection(set), program));

		waitForPostedSwingRunnables();

		dialog = getDialog();
		Container container = dialog.getComponent();

		// check to make sure the search selection button is checked and enabled
		JRadioButton rb = (JRadioButton) findButton(container, "Search Selection");
		assertTrue(rb.isSelected());
		assertTrue(rb.isEnabled());

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);

		assertEquals(3, model.getRowCount());

		// test the results size and that the correct strings are found
		int row = findRow(model, addr(0x405d81));
		assertEquals("00405d81", getModelValue(model, row, addressColumnIndex).toString());
		row = findRow(model, addr(0x405d9c));
		assertEquals("00405d9c", getModelValue(model, row, addressColumnIndex).toString());
		row = findRow(model, addr(0x405db4));
		assertEquals("00405db4", getModelValue(model, row, addressColumnIndex).toString());
	}

	/*
	 * change the min search len - use selection of code not whole thing
	 */
	@Test
	public void testSearchWithLargeMinLength() throws Exception {
		dialog = getDialog();
		setMinStringFieldValue(dialog, 100);

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		toggleDefinedStateButtons(provider, true, true, true, true);
		waitForTableModel(model);

		assertRowCount(model, 0);
	}

	@Test
	public void testSearchWithTooSmallMinLength() throws Exception {
		dialog = getDialog();
		setMinStringFieldValue(dialog, 1);

		pressButtonByText(dialog.getComponent(), "Search");

		String status = dialog.getStatusText();
		assertEquals("Please enter a valid minimum search length. Must be > 1", status);
	}

	// check that deselecting/reselecting the auto label works
	// the tests above test that the labels are correct when initially selected
	@Test
	public void testMakeLabelOnExistingString() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		selectRows(table, addr(0x405044));
		assertEquals("00405044",
			getModelValue(model, table.getSelectedRow(), addressColumnIndex).toString());
		// verify string already exists

		// make string with auto label selected
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		// make sure that even though a string already exists that the default label gets updated
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x405044));
		assertEquals("s_String3", sym.getName());
	}

	@Test
	public void testNoMakeLabelOnExistingString() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);

		// *************************************************************************
		// make sure that no label is made when auto label is disabled but that the string is
		// *******************************************************************************
		setAutoLabelCheckbox(provider, false);

		// select row Address 404fde: \n\rString6\n\r)
		selectRows(table, addr(0x404fde));
		assertEquals("00404fde",
			getModelValue(model, table.getSelectedRow(), addressColumnIndex).toString());

		// make string with auto label selected
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		// make sure label not created but the string is
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x404fde));
		assertEquals(null, sym);

		Data d = listing.getDataAt(addr(0x404fde));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof StringDataType);
		assertEquals("\n\rString6\n\r", d.getValue());

	}

	@Test
	public void testAutoLabelDoesntOverwriteUserLabel() throws Exception {
		// *****TEST4********************************************************************************************
		// make sure that when there is a user-defined label, no data yet - label not changed but string created
		//*******************************************************************************************************

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		// select row (Address 40503c - String2)
		selectRows(table, addr(0x40503c));
		assertEquals("0040503c",
			getModelValue(model, table.getSelectedRow(), addressColumnIndex).toString());

		// make a user-defined label
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x40503c));
		assertEquals(null, sym);
		int txId = program.startTransaction("Create Label");
		boolean commit;
		try {
			program.getSymbolTable().createLabel(addr(0x40503c), "testLabel",
				SourceType.USER_DEFINED);
			commit = true;
		}
		catch (InvalidInputException exc) {
			commit = false;
		}
		program.endTransaction(txId, commit);

		// the createSymbol call will trigger notifications in the Swing thread that we need
		// to finish before we can move on
		waitForPostedSwingRunnables();
		// make string with auto label selected
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		// make sure new label is made primary and second label is still there as secondary one
		sym = program.getSymbolTable().getPrimarySymbol(addr(0x40503c));
		assertEquals("s_String2", sym.getName());
		Symbol symArray[] = program.getSymbolTable().getSymbols(addr(0x40503c));
		assertEquals(2, symArray.length);
		assertEquals("s_String2", symArray[0].getName());
		assertEquals("testLabel", symArray[1].getName());

		Data d = listing.getDataAt(addr(0x40503c));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof StringDataType);
		assertEquals("String2", d.getValue());
	}

	@Test
	public void testIncludeAlignmentBytesPascal() throws Exception {
		/***************************************************************************/
		/* TEST 6 - test include alignment nulls with various sized alignments */
		/***********************************************************************/
		final AddressSet set = new AddressSet();
		set.addRange(addr(0x405d99), addr(0x405daa));

		// select the address set
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Test", new ProgramSelection(set), program));
		waitForPostedSwingRunnables();

		dialog = getDialog();

		// turn on pascal
		JCheckBox cb = (JCheckBox) findButton(dialog.getComponent(), "Pascal Strings");
		cb.setSelected(true);

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);

		// verify that rows  points to the correct address
		assertEquals("00405d9a", getModelValue(model, 0, addressColumnIndex).toString());

		selectRow(table, 0);

		// select the Include Alignment Nulls option
		JCheckBox includeAlignNullsCB =
			(JCheckBox) getInstanceField("addAlignmentBytesCheckbox", provider);
		includeAlignNullsCB.setSelected(true);
		setAlignmentValue(provider, 2);

		// make string
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		//Test that p_string made with one align byte after it
		Data d = listing.getDataAt(addr(0x405d9a));
		assertEquals(9, d.getLength());
		d = listing.getDataAt(addr(0x405da3));
		assertEquals(1, d.getLength());

	}

	@Test
	public void testMakeStringWhileFilteredForSCR_5689() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		toggleDefinedStateButtons(provider, false, true, false, false);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		filter("SING", provider);
		waitForTableModel(model);

		selectRow(table, 0);

		// make string
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x4040c0));
		assertEquals("s_SING_error", sym.getName());
	}

	@Test
	public void testMakeCollision() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		// select row with String4
		selectRows(table, addr(0x40504c));
		assertTrue(table.getSelectedRow() >= 0);

		// make string
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model);

		// test that the string was actually made correctly
		Data d = listing.getDataAt(addr(0x40504c));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof StringDataType);
		assertEquals("String4", d.getValue());

		// test that the length of the string created was correct to make
		// sure that the \n and 00 was included in the created data
		assertEquals(8, d.getLength());

		// test that the label was made
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x40504c));
		assertEquals("s_String4", sym.getName());
		waitForPostedSwingRunnables();

		// try to make char array
		//	select row with String4
		// select row with String4
		selectRows(table, addr(0x40504c));

		DockingAction makeCharArrayAction =
			(DockingAction) getInstanceField("makeCharArrayAction", provider);
		assertTrue(!makeCharArrayAction.isEnabledForContext(null));

	}

	@Test
	public void testMakeStringOverUndefined() throws Exception {

		StringTableProvider provider = performSearch();
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		waitForTableModel(model);
		setAutoLabelCheckbox(provider, true);

		// select row with String4
		Address addr = addr(0x40504c);
		selectRows(table, addr);
		assertTrue(table.getSelectedRow() >= 0);

		// make undefined
		int id = program.startTransaction("Create Data");
		listing.createData(addr, Undefined.getUndefinedDataType(1));
		program.endTransaction(id, true);
		Data data = listing.getDefinedDataAt(addr);
		assertNotNull(data);

		// make string
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, model, false);

		// test that the string was actually made correctly
		Data d = listing.getDataAt(addr(0x40504c));
		DataType dt = d.getBaseDataType();
		assertTrue(dt instanceof StringDataType);
		assertEquals("String4", d.getValue());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void printContents(StringTableModel model) {
		StringBuilder buffy = new StringBuilder();
		int rows = model.getRowCount();
		int cols = model.getColumnCount();
		for (int row = 0; row < rows; row++) {
			buffy.append("row " + row + ": ");
			for (int col = 0; col < cols; col++) {
				Object columnValue = getModelValue(model, row, col);
				buffy.append(columnValue).append(", ");
			}
			buffy.append('\n');
		}
		System.out.println("model contents = ");
		System.out.println(buffy.toString());
	}

	private void setAutoLabelCheckbox(final StringTableProvider provider, final boolean b) {
		runSwing(() -> {
			JCheckBox autoLabelCB = (JCheckBox) getInstanceField("autoLabelCheckbox", provider);
			autoLabelCB.setSelected(b);
		});
	}

	private Address addr(int offset) {
		return addr(offset & 0xffffffffL);
	}

	private Address addr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private Object getModelValue(final StringTableModel model, final int row, final int column) {
		final AtomicReference<Object> result = new AtomicReference<>();
		runSwing(() -> {
			Object valueAt = model.getValueAt(row, column);
			result.set(valueAt);
		});
		return result.get();
	}

	private FoundString getModelRowObject(final StringTableModel model, final int row) {
		final AtomicReference<Object> result = new AtomicReference<>();
		runSwing(() -> {
			Object valueAt = model.getRowObject(row);
			result.set(valueAt);
		});
		return (FoundString) result.get();
	}

	private void setMinStringFieldValue(final SearchStringDialog dialog, final int minLength) {
		runSwing(() -> {
			IntegerTextField offsetField =
				(IntegerTextField) getInstanceField("minLengthField", dialog);
			offsetField.setValue(minLength);
		});
	}

	private void setOffsetFieldValue(final StringTableProvider provider, final int offset) {
		runSwing(() -> {
			IntegerTextField offsetField =
				(IntegerTextField) getInstanceField("offsetField", provider);
			offsetField.setValue(offset);
		});
	}

	private void setAlignmentFieldValue(final SearchStringDialog dialog, final int alignment) {
		runSwing(() -> {
			IntegerTextField alignmentField =
				(IntegerTextField) getInstanceField("alignField", dialog);
			alignmentField.setValue(alignment);
		});
	}

	private void setAlignmentValue(StringTableProvider provider, int alignment) {
		StringTableOptions options = (StringTableOptions) getInstanceField("options", provider);
		options.setAlignment(alignment);
	}

	private SearchStringDialog getDialog() throws Exception {
		dialog = getDialogComponent(SearchStringDialog.class);

		CodeBrowserPlugin cbp = env.getPlugin(CodeBrowserPlugin.class);
		CodeViewerProvider provider = cbp.getProvider();

		if (dialog == null) { // not yet shown
			SwingUtilities.invokeLater(() -> searchAction.actionPerformed(
				new NavigatableActionContext(provider, provider)));
			waitForSwing();
		}

		dialog = getDialogComponent(SearchStringDialog.class);
		return dialog;
	}

	private StringTableProvider performSearch() throws Exception {
		dialog = getDialog();
		pressButtonByText(dialog.getComponent(), "Search");

		// make sure the correct column is sorted--assumes the provider has already been shown
		@SuppressWarnings("unchecked")
		StringTableProvider provider =
			((List<StringTableProvider>) getInstanceField("transientProviders", plugin)).get(0);
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);

		waitForTableModel(model);// let the initial load finish (if not, the sort may be wrong)

		sortOnAddress(model);

		waitForTableModel(model);
		return provider;
	}

	private void sortOnAddress(final StringTableModel model) {
		runSwing(() -> model.setTableSortState(
			TableSortState.createDefaultSortState(addressColumnIndex, true)));
	}

	private AbstractButton findButton(Container container, String text) {
		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton) &&
				((AbstractButton) element).getText().equals(text)) {
				return (AbstractButton) element;
			}
			else if (element instanceof Container) {
				AbstractButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	private String getPreviewText(StringTableProvider provider) {
		final JTextField previewField = (JTextField) getInstanceField("preview", provider);
		final AtomicReference<String> result = new AtomicReference<>();
		runSwing(() -> result.set(previewField.getText()));
		return result.get();
	}

	private void selectRow(GhidraTable table, int row) {
		table.clearSelection();
		table.addRowSelectionInterval(row, row);
	}

	private void selectRows(GhidraTable table, Address... addrs) {
		table.clearSelection();
		for (Address address : addrs) {
			StringTableModel model = (StringTableModel) table.getModel();
			int row = findRow(model, address);
			table.addRowSelectionInterval(row, row);
		}
		waitForPostedSwingRunnables();
	}

	private int findRow(StringTableModel model, Address address) {
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {
			FoundString string = model.getRowObject(i);
			if (string.getAddress().equals(address)) {
				return i;
			}
		}
		return -1;
	}

	private void toggleDefinedStateButtons(final StringTableProvider provider,
			final boolean defined, final boolean undefined, final boolean partial,
			final boolean conflicting) {
		runSwing(() -> {
			ToggleDockingAction showUndefinedAction =
				(ToggleDockingAction) getInstanceField("showUndefinedAction", provider);
			ToggleDockingAction showDefinedAction =
				(ToggleDockingAction) getInstanceField("showDefinedAction", provider);
			ToggleDockingAction showPartialAction =
				(ToggleDockingAction) getInstanceField("showPartialDefinedAction", provider);
			ToggleDockingAction showConflictingAction =
				(ToggleDockingAction) getInstanceField("showConflictsAction", provider);

			setActionState(showUndefinedAction, undefined);
			setActionState(showDefinedAction, defined);
			setActionState(showPartialAction, partial);
			setActionState(showConflictingAction, conflicting);
		});
	}

	private void toggleDefinedStateButtons(final StringTableProvider provider,
			final boolean defined, final boolean undefined, final boolean partial,
			final boolean conflicting, final boolean isWord) {
		runSwing(() -> {
			ToggleDockingAction showUndefinedAction =
				(ToggleDockingAction) getInstanceField("showUndefinedAction", provider);
			ToggleDockingAction showDefinedAction =
				(ToggleDockingAction) getInstanceField("showDefinedAction", provider);
			ToggleDockingAction showPartialAction =
				(ToggleDockingAction) getInstanceField("showPartialDefinedAction", provider);
			ToggleDockingAction showConflictingAction =
				(ToggleDockingAction) getInstanceField("showConflictsAction", provider);
			ToggleDockingAction showIsWordAction =
				(ToggleDockingAction) getInstanceField("showIsWordAction", provider);

			setActionState(showUndefinedAction, undefined);
			setActionState(showDefinedAction, defined);
			setActionState(showPartialAction, partial);
			setActionState(showConflictingAction, conflicting);

			// This button will not exist if the model is invalid/missing.
			if (showIsWordAction != null) {
				setActionState(showIsWordAction, isWord);
			}
		});
	}

	private void setActionState(ToggleDockingAction action, boolean state) {
		action.setSelected(state);
		action.actionPerformed(null);
	}

	private void filter(String text, StringTableProvider provider) {
		@SuppressWarnings("rawtypes")
		GhidraTableFilterPanel panel =
			(GhidraTableFilterPanel) TestUtils.getInstanceField("filterPanel", provider);
		panel.setFilterText("SING"); // this should match only one row
		waitForSwing();
	}

	private void performAction(DockingAction action, StringTableModel model) throws Exception {
		performAction(action, model, true);
	}

	private void performAction(DockingAction action, StringTableModel model,
			boolean waitForCompletion) throws Exception {
		performAction(action, waitForCompletion);

		// trigger domain events to go out, which will trigger either a task launcher or a full
		// reload()
		program.flushEvents();
		waitForTasks();
		waitForTableModel(model);
	}

	private void assertRowCount(StringTableModel model, int expected) {
		int rowCount = model.getRowCount();
		if (expected != rowCount) {
			Msg.debug(this, "Row count does not match expected, expected " + expected +
				", but got " + rowCount);
			Assert.fail("model row count not as expected. See System.out for more info");

		}
		assertEquals(expected, model.getRowCount());
	}

}
