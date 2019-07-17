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
package ghidra.app.plugin.core.instructionsearch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Container;
import java.awt.Window;
import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.List;

import javax.swing.table.TableModel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.dnd.GClipboard;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject;
import ghidra.app.plugin.core.instructionsearch.model.MaskSettings;
import ghidra.app.plugin.core.instructionsearch.ui.*;
import ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.table.GhidraTable;

/**
 * Test of the instruction pattern search functionality.
 */
public class InstructionSearchTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private InstructionSearchPlugin plugin;

	private DockingActionIf openSearchDialogAction;

	private InstructionSearchDialog dialog;
	private Container component;
	private GhidraTable instructionTable;
	private GTable previewTable;

	/**
	 * Test setup.  Each test will start with a simple program having a selection
	 * encompassing the entire range.
	 */
	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(InstructionSearchPlugin.class);
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);

		// Open the main dialog.
		openSearchDialogAction = getAction(plugin, "Search Instruction Patterns");
		ActionContext context = runSwing(() -> cb.getProvider().getActionContext(null));
		performAction(openSearchDialogAction, context, true);

		// Grab the dialog and components for the window; all tests need them.
		dialog = waitForDialogComponent(InstructionSearchDialog.class);
		component = dialog.getComponent();

		// Now create a selection that encompasses the entire range.
		loadSelection("0x004065e1", "0x004065f2");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/**
	 * This builds a small program based on a section of WinHelloCpp.exe.  The specific
	 * section disassembles as follows:
	 * 
	 *	    004065e1 47              INC        EDI 
	 *	    004065e2 57              PUSH       EDI
	 *	    004065e3 8d 45 08        LEA        EAX=>_Ch,[EBP + 0x8]
	 *	    004065e6 50              PUSH       EAX
	 *	    004065e7 ff 75 0c        PUSH       [EBP + _File]
	 *	    004065ea e8 84 2c        CALL       __write                                           
	 *	             00 00
	 *	    004065ef 83 c4 0c        ADD        ESP,nope
	 *	    004065f2 89 45 fc        MOV        [EBP + local_8],EAX
	 *	
	 * @throws Exception
	 */
	private Program buildProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x004065e1), 0x6600);

		builder.setBytes("004065e1", "47 57 8d 45 08 50 ff 75 0c e8 84 2c 00 00 83 c4 0c 89 45 fc");
		builder.disassemble("004065e1", 20, true);

		return builder.getProgram();
	}

	/**
	 * Tests that selected instructions are properly loaded into the {@link InstructionTable}.
	 */
	@Test
	public void testLoadInstructions() {

		assertEquals(dialog.getSearchData().getInstructions().size(), 8);

		// Make sure the instruction table has the correct number of rows and columns.
		assertEquals(instructionTable.getRowCount(), 8);
		assertEquals(instructionTable.getColumnCount(), 3);

		// And verify the contents of each cell.
		InstructionTableDataObject obj00 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 0);
		InstructionTableDataObject obj10 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 0);
		InstructionTableDataObject obj20 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(2, 0);
		InstructionTableDataObject obj30 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(3, 0);
		InstructionTableDataObject obj40 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(4, 0);
		InstructionTableDataObject obj50 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(5, 0);
		InstructionTableDataObject obj60 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(6, 0);
		InstructionTableDataObject obj70 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(7, 0);

		InstructionTableDataObject obj01 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 1);
		InstructionTableDataObject obj11 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 1);
		InstructionTableDataObject obj21 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(2, 1);
		InstructionTableDataObject obj31 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(3, 1);
		InstructionTableDataObject obj41 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(4, 1);
		InstructionTableDataObject obj51 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(5, 1);
		InstructionTableDataObject obj61 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(6, 1);
		InstructionTableDataObject obj71 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(7, 1);

		InstructionTableDataObject obj02 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 2);
		InstructionTableDataObject obj12 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 2);
		InstructionTableDataObject obj22 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(2, 2);
		InstructionTableDataObject obj32 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(3, 2);
		InstructionTableDataObject obj42 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(4, 2);
		InstructionTableDataObject obj52 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(5, 2);
		InstructionTableDataObject obj62 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(6, 2);
		InstructionTableDataObject obj72 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(7, 2);

		assertEquals("INC", obj00.getData());
		assertEquals("PUSH", obj10.getData());
		assertEquals("LEA", obj20.getData());
		assertEquals("PUSH", obj30.getData());
		assertEquals("PUSH", obj40.getData());
		assertEquals("CALL", obj50.getData());
		assertEquals("ADD", obj60.getData());
		assertEquals("MOV", obj70.getData());

		assertEquals("EDI", obj01.getData());
		assertEquals("EDI", obj11.getData());
		assertEquals("EAX", obj21.getData());
		assertEquals("EAX", obj31.getData());
		assertEquals("dword ptr [EBP + 0xc]", obj41.getData());
		assertEquals("0x00409273", obj51.getData());
		assertEquals("ESP", obj61.getData());
		assertEquals("dword ptr [EBP + -0x4]", obj71.getData());

		assertEquals("", obj02.getData());
		assertEquals("", obj12.getData());
		assertEquals("[EBP + 0x8]", obj22.getData());
		assertEquals("", obj32.getData());
		assertEquals("", obj42.getData());
		assertEquals("", obj52.getData());
		assertEquals("0xc", obj62.getData());
		assertEquals("EAX", obj72.getData());
	}

	/**
	 * Tests that the {@link PreviewTable} is properly loaded when instructions are selected.
	 */
	@Test
	public void testLoadPreview() {

		// Make sure it has the number of rows and columns.
		assertEquals(previewTable.getRowCount(), 8);
		assertEquals(previewTable.getColumnCount(), 1);

		// Verify the contents of the table
		InstructionTableDataObject obj00 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(0, 0);
		InstructionTableDataObject obj10 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(1, 0);
		InstructionTableDataObject obj20 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(2, 0);
		InstructionTableDataObject obj30 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(3, 0);
		InstructionTableDataObject obj40 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(4, 0);
		InstructionTableDataObject obj50 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(5, 0);
		InstructionTableDataObject obj60 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(6, 0);
		InstructionTableDataObject obj70 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(7, 0);

		assertEquals(obj00.getData().trim(), "47");
		assertEquals(obj10.getData().trim(), "57");
		assertEquals(obj20.getData().trim(), "8d 45 08");
		assertEquals(obj30.getData().trim(), "50");
		assertEquals(obj40.getData().trim(), "ff 75 0c");
		assertEquals(obj50.getData().trim(), "e8 84 2c 00 00");
		assertEquals(obj60.getData().trim(), "83 c4 0c");
		assertEquals(obj70.getData().trim(), "89 45 fc");
	}

	/**
	 * Tests the mask all scalars tool.
	 */
	@Test
	public void testMaskScalars() {

		// Verify the contents of the table
		InstructionTableDataObject cell00 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(6, 0);
		assertEquals(cell00.getData().trim(), "83 c4 0c");

		// Now activate the scalar mask tool, which should mask out the last param
		// of the ADD instruction.
		pressButtonByName(component, "mask scalars button");

		// Wait for the button select to finish.
		dialog.waitForCurrentTask();

		// Now grab the preview panel content and check again.  If the last param
		// is masked then it worked.
		cell00 = (InstructionTableDataObject) previewTable.getModel().getValueAt(6, 0);
		assertEquals(cell00.getData().trim(), "83 c4 [........]");
	}

	/**
	 * Tests the mask all operands tool.
	 */
	@Test
	public void testMaskOperands() {

		// First switch to binary view to make sure we're testing for the right values.
		setToggleButtonSelected(component, "binary view button", true);

		waitForSwing();

		InstructionTableDataObject cell00 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(0, 0);
		assertEquals(cell00.getData().trim(), "01000111");

		InstructionTableDataObject cell10 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(1, 0);
		assertEquals(cell10.getData().trim(), "01010111");

		InstructionTableDataObject cell20 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(2, 0);
		assertEquals(cell20.getData().trim(), "10001101 01000101 00001000");

		InstructionTableDataObject cell30 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(3, 0);
		assertEquals(cell30.getData().trim(), "01010000");

		InstructionTableDataObject cell40 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(4, 0);
		assertEquals(cell40.getData().trim(), "11111111 01110101 00001100");

		InstructionTableDataObject cell50 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(5, 0);
		assertEquals(cell50.getData().trim(), "11101000 10000100 00101100 00000000 00000000");

		InstructionTableDataObject cell60 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(6, 0);
		assertEquals(cell60.getData().trim(), "10000011 11000100 00001100");

		InstructionTableDataObject cell70 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(7, 0);
		assertEquals(cell70.getData().trim(), "10001001 01000101 11111100");

		// Now activate the address mask tool, which should mask out the last param
		// of the ADD instruction.
		pressButtonByName(component, "mask operands button");

		// Wait for the button select to finish.
		dialog.waitForCurrentTask();

		// Now grab the preview panel content and check again.
		cell00 = (InstructionTableDataObject) previewTable.getModel().getValueAt(0, 0);
		assertEquals(cell00.getData().trim(), "01000...");

		cell10 = (InstructionTableDataObject) previewTable.getModel().getValueAt(1, 0);
		assertEquals(cell10.getData().trim(), "01010...");

		cell20 = (InstructionTableDataObject) previewTable.getModel().getValueAt(2, 0);
		assertEquals(cell20.getData().trim(), "10001101 01...... ........");

		cell30 = (InstructionTableDataObject) previewTable.getModel().getValueAt(3, 0);
		assertEquals(cell30.getData().trim(), "01010...");

		cell40 = (InstructionTableDataObject) previewTable.getModel().getValueAt(4, 0);
		assertEquals(cell40.getData().trim(), "11111111 01110... ........");

		cell50 = (InstructionTableDataObject) previewTable.getModel().getValueAt(5, 0);
		assertEquals(cell50.getData().trim(), "11101000 ........ ........ ........ ........");

		cell60 = (InstructionTableDataObject) previewTable.getModel().getValueAt(6, 0);
		assertEquals(cell60.getData().trim(), "10000011 11000... ........");

		cell70 = (InstructionTableDataObject) previewTable.getModel().getValueAt(7, 0);
		assertEquals(cell70.getData().trim(), "10001001 01...... ........");
	}

	/**
	 * Tests the mask all addresses tool.
	 */
	@Test
	public void testMaskAddresses() {

		InstructionTableDataObject cell50 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(5, 0);
		assertEquals(cell50.getData().trim(), "e8 84 2c 00 00");

		// Now activate the address mask tool, which should mask out the last param
		// of the ADD instruction.
		pressButtonByName(component, "mask addresses button");

		// Wait for the button select to finish.
		dialog.waitForCurrentTask();

		// Now grab the preview panel content and check again.
		cell50 = (InstructionTableDataObject) previewTable.getModel().getValueAt(5, 0);
		assertEquals(cell50.getData().trim(), "e8 [........] [........] [........] [........]");
	}

	/**
	 * Test that toggling a cell causes the preview screen to show the
	 * correct mask.
	 */
	@Test
	public void testMaskToggle() {

		// First get a cell and verify it has the correct starting value.
		InstructionTableDataObject cell21 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(1, 0);
		assertEquals(cell21.getData().trim(), "57");

		// Now mask it by getting the cell in the instruction table and changing its state.
		InstructionTableDataObject cell21Toggle =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 1);
		cell21Toggle.setState(OperandState.MASKED, true);

		// Wait for the gui to finish updating.
		dialog.waitForCurrentTask();

		// Verify it has the correct masked value.
		assertEquals(cell21.getData().trim(), "[01010...]");

		// Now unmask it.
		cell21Toggle.setState(OperandState.NOT_MASKED, true);

		// Wait for the gui to finish updating.
		dialog.waitForCurrentTask();

		// And check that it's in good shape again.
		assertEquals(cell21.getData().trim(), "57");
	}

	/**
	 * Tests that the full search string is generated properly from
	 * the preview table.  To do this we'll execute the "copy preview string"
	 * tool from the toolbar and check the results.
	 */
	@Test
	public void testGenerateFullSearchString() {

		// Invoke the copy button, which will generate the search string and copy it to
		// the clipboard.
		pressButtonByName(component, "Copy Preview Button");

		// Wait for swing to finish.
		dialog.waitForCurrentTask();

		// Grab the contents of the clipboard.
		Clipboard clip = GClipboard.getSystemClipboard();

		// Now check the clipboard contents against what we know the search string should be.
		try {
			String searchString = (String) clip.getData(DataFlavor.stringFlavor);
			assertEquals(searchString.trim(),
				"47 57 8d 45 08 50 ff 75 0c e8 84 2c 00 00 83 c4 0c 89 45 fc");
		}
		catch (UnsupportedFlavorException | IOException e) {
			failWithException("Unexpected", e);
		}
	}

	/**
	 * Test that we can search for results only within the currently-selected
	 * region.  
	 */
	@Test
	public void testSearchCurrentSelection() {

		// Make sure "current selection is selected.
		setToggleButtonSelected(component, "Search Selection", true);

		// Wait for the gui to finish updating.
		dialog.waitForCurrentTask();

		// Now do an initial search that should return a single result.  This is the case where
		// we're searching for a set of instructions that matches exactly our selection.
		pressSearchAll();

		// Wait for the results window and verify the result count
		assertResultsTableRowCount(1);
	}

	/**
	 * Tests that we can perform a search over the entire memory space and return a single
	 * result.
	 */
	@Test
	public void testSearchEntireProgramSingleResult() {

		// Make sure the "entire program" button is selected.
		setToggleButtonSelected(component, "Entire Program", true);

		// Wait for the gui to finish updating.
		dialog.waitForCurrentTask();

		// Now get the search button and execute it.
		pressSearchAll();

		// Wait for the results window and verify the result count
		assertResultsTableRowCount(1);
	}

	/**
	 * Tests that we can perform a search over the entire memory space and return multiple
	 * results. To do this we're going to have to select the "PUSH EDI" instruction and mask
	 * out the operand, which should yield 2 matches.
	 * @throws Exception 
	 */
	@Test
	public void testSearchEntireProgramMultipleResults() throws Exception {

		// Load a new selection, consisting of only the PUSH EDI instruction.
		loadSelection("0x004065e2", "0x004065e2");

		// Now mask it by getting the cell in the instruction table and changing its state.
		InstructionTableDataObject cell11Toggle =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 1);
		cell11Toggle.setState(OperandState.MASKED, true);

		// Wait for the gui to finish updating.
		dialog.waitForCurrentTask();

		// Make sure the "entire program" button is selected.
		setToggleButtonSelected(component, "Entire Program", true);

		// Wait for the gui to finish updating.
		dialog.waitForCurrentTask();

		// Now get the search button and execute it.
		pressSearchAll();

		assertResultsTableRowCount(2);
	}

	/**
	 * Tests the the hex view button correctly switches the preview table to hex, and that
	 * the hex is formatted correctly when masking.
	 */
	@Test
	public void testHexView() {

		setToggleButtonSelected(component, "Hex View Button", true);

		// Wait for the button select to finish; the select fires an event that causes
		// the preview panel to change to hex.
		dialog.waitForCurrentTask();

		// Now grab the preview panel content and check again.
		InstructionTableDataObject cell00 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(0, 0);
		assertEquals(cell00.getData().trim(), "47");

		InstructionTableDataObject cell10 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(1, 0);
		assertEquals(cell10.getData().trim(), "57");

		InstructionTableDataObject cell20 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(2, 0);
		assertEquals(cell20.getData().trim(), "8d 45 08");

		InstructionTableDataObject cell30 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(3, 0);
		assertEquals(cell30.getData().trim(), "50");

		InstructionTableDataObject cell40 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(4, 0);
		assertEquals(cell40.getData().trim(), "ff 75 0c");

		InstructionTableDataObject cell50 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(5, 0);
		assertEquals(cell50.getData().trim(), "e8 84 2c 00 00");

		InstructionTableDataObject cell60 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(6, 0);
		assertEquals(cell60.getData().trim(), "83 c4 0c");

		InstructionTableDataObject cell70 =
			(InstructionTableDataObject) previewTable.getModel().getValueAt(7, 0);
		assertEquals(cell70.getData().trim(), "89 45 fc");
	}

	/**
	 * Tests that the hex view correctly formats the preview panel when masking a part
	 * of a byte.
	 * 
	 * ie: [01010...]
	 */
	@Test
	public void testHexViewMaskFormat() {

		setToggleButtonSelected(component, "Hex View Button", true);

		// Wait for the button select to finish; the select fires an event that causes
		// the preview panel to change to hex.
		dialog.waitForCurrentTask();

		// Get the instruction table and grab a cell that we want to mask.  Use the
		// DataObject to mask it directly, then view the results.
		InstructionTableDataObject cell21 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(2, 1);
		cell21.setState(OperandState.MASKED, true);

		// Wait for the cell select to finish; the select fires an event that causes
		// the preview panel to update, so we need to be patient.
		dialog.waitForCurrentTask();

		// And finally make sure the preview panel has been updated with the correct
		// hex/binary hybrid string.
		cell21 = (InstructionTableDataObject) previewTable.getModel().getValueAt(2, 0);
		assertEquals(cell21.getData().trim(), "8d [01...101] 08");
	}

	/**
	 * Tests the external API method that does a simple search with no masking.
	 */
	@Test
	public void testApi_SearchByRange() {
		InstructionSearchApi api = new InstructionSearchApi();

		AddressFactory addressFactory = program.getAddressFactory();
		Address min = addressFactory.getAddress("004065e2");
		Address max = addressFactory.getAddress("004065e2");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);
		try {
			List<Address> results = api.search(program, addrSet.getFirstRange());
			assertEquals(results.size(), 1);
		}
		catch (InvalidInputException e) {
			failWithException("Unexpected", e);
		}
	}

	/**
	 * Tests the external API method that searches for an instruction with masking, to return
	 * multiple results.
	 */
	@Test
	public void testApi_SearchByRangeWithMask() {
		InstructionSearchApi api = new InstructionSearchApi();

		AddressFactory addressFactory = program.getAddressFactory();
		Address min = addressFactory.getAddress("004065e2");
		Address max = addressFactory.getAddress("004065e2");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);

		MaskSettings maskSettings = new MaskSettings(true, true, true);

		try {
			List<Address> results = api.search(program, addrSet.getFirstRange(), maskSettings);
			assertEquals(results.size(), 2);
		}
		catch (InvalidInputException e) {
			failWithException("Unexpected", e);
		}
	}

	/**
	 * Verify that hex data entered into the manual input field is processed properly.
	 * 
	 * Note, all bytes must be input in hex format.
	 */
	@Test
	public void testManualInsert() {

		loadBytes("8d 45 08 50");

		instructionTable = dialog.getTablePanel().getTable();
		previewTable = dialog.getPreviewTablePanel().getTable();
		assertEquals(2, dialog.getSearchData().getInstructions().size());
		assertEquals(2, instructionTable.getRowCount());
		assertEquals(3, instructionTable.getColumnCount());

		InstructionTableDataObject obj00 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 0);
		InstructionTableDataObject obj10 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 0);

		InstructionTableDataObject obj01 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 1);
		InstructionTableDataObject obj11 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 1);

		InstructionTableDataObject obj02 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 2);

		assertEquals("LEA", obj00.getData());
		assertEquals("PUSH", obj10.getData());
		assertEquals("EAX", obj01.getData());
		assertEquals("EAX", obj11.getData());
		assertEquals("[EBP + 0x8]", obj02.getData());
	}

	/**
	 * Verify that an invalid entry into the manual input field is rejected.
	 */
	@Test
	public void testManualInsert_Invalid() {

		loadBytes("0000 abcd efgh 01011");

		instructionTable = dialog.getTablePanel().getTable();
		previewTable = dialog.getPreviewTablePanel().getTable();

		assertEquals(0, dialog.getSearchData().getInstructions().size());
		assertEquals(0, instructionTable.getRowCount());

		Window errorDialog = waitForWindowByTitleContaining("Input Error");
		assertNotNull(errorDialog);
		runSwing(() -> errorDialog.setVisible(false));
	}

	/**
	 * Verify that users can use the {@link InstructionSearchApi} to bring up the 
	 * {@link InstructionSearchDialog} loaded with instructions derived from a given string
	 * of bytes (hex format only).
	 * 
	 */
	@Test
	public void testApi_LoadSearchDialog_Bytes() {

		closeDialog();// using new search dialog below

		InstructionSearchApi api = new InstructionSearchApi();

		String bytes = "10011011";

		runSwing(() -> api.loadInstructions(bytes, plugin.getTool()));

		waitForSwing();

		dialog = waitForDialogComponent(InstructionSearchDialog.class);
		component = dialog.getComponent();

		instructionTable = dialog.getTablePanel().getTable();
		previewTable = dialog.getPreviewTablePanel().getTable();

		assertEquals(2, dialog.getSearchData().getInstructions().size());
		assertEquals(2, instructionTable.getRowCount());
		assertEquals(3, instructionTable.getColumnCount());

		InstructionTableDataObject obj00 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 0);
		assertEquals("ADC", obj00.getData());
	}

	/**
	 * Verify that users can use the {@link InstructionSearchApi} to bring up the 
	 * {@link InstructionSearchDialog} loaded with instructions derived from the given address
	 * set, which should correspond to addresses in the currently-loaded program.
	 */
	@Test
	public void testApi_LoadSearchDialog_Addresses() {

		closeDialog();// using new search dialog below

		InstructionSearchApi api = new InstructionSearchApi();

		AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
		Address min = addressFactory.getAddress("004065ea");
		Address max = addressFactory.getAddress("004065f2");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);

		runSwing(() -> api.loadInstructions(addrSet, plugin.getTool()));

		waitForSwing();

		dialog = waitForDialogComponent(InstructionSearchDialog.class);
		component = dialog.getComponent();

		instructionTable = dialog.getTablePanel().getTable();
		previewTable = dialog.getPreviewTablePanel().getTable();

		assertEquals(3, dialog.getSearchData().getInstructions().size());
		assertEquals(3, instructionTable.getRowCount());
		assertEquals(3, instructionTable.getColumnCount());

		InstructionTableDataObject obj00 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(0, 0);
		assertEquals("CALL", obj00.getData());

		InstructionTableDataObject obj10 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(1, 0);
		assertEquals("ADD", obj10.getData());

		InstructionTableDataObject obj20 =
			(InstructionTableDataObject) instructionTable.getModel().getValueAt(2, 0);
		assertEquals("MOV", obj20.getData());
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	private void closeDialog() {
		runSwing(() -> dialog.close());
		waitForSwing();
	}

	private void loadBytes(String byteString) {

		runSwing(() -> {
			dialog.clear();
			dialog.loadBytes(byteString);
		});

		// the call above uses an invokeLater
		waitForSwing();
	}

	private void assertResultsTableRowCount(int rowCount) {

		// Wait for the results window...
		Window window = waitForWindowByTitleContaining("Addresses");
		GhidraTable gTable = findComponent(window, GhidraTable.class, true);

		// (the results dialog is shown using the TableService, which uses a ThreadedTableModel)
		TableModel model = gTable.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		// Verify that we got a single result.
		assertEquals(rowCount, gTable.getRowCount());
	}

	private void pressSearchAll() {
		pressButtonByText(component, "Search All");
		waitForSwing();
	}

	/**
	 * Creates a {@link ProgramSelection} with the given address range.
	 * 
	 * @param min lower range address (ie: 0x000000);
	 * @param max higher range address (ie: 0x100000);
	 */
	private void createSelection(String min, String max) {
		Address minAddr = program.getAddressFactory().getAddress(min);
		Address maxAddr = program.getAddressFactory().getAddress(max);
		ProgramSelection programSelection = new ProgramSelection(minAddr, maxAddr);
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("IPS Test", programSelection, program));
		waitForSwing();
	}

	/**
	 * Loads the instructions in the given range into the instruction table.
	 * 
	 * @param addr1 address in the form "0x01234567"
	 * @param addr2 address in the form "0x01234567"
	 * @throws Exception 
	 */
	private void loadSelection(String addr1, String addr2) throws Exception {

		// Now create a selection that encompasses the entire range.
		createSelection(addr1, addr2);

		// And finally, hit the reload button on the GUI to force it to load the selection.
		pressButtonByName(component, "reload");

		// Wait for the load to take effect...
		waitForSwing();
		waitForTasks();

		instructionTable = dialog.getTablePanel().getTable();
		previewTable = dialog.getPreviewTablePanel().getTable();
	}
}
