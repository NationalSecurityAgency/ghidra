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

import java.util.*;

import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.GhidraOptions;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.OperandFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.AssertException;
import ghidra.util.table.GhidraTable;

/**
 * Tests the Equate Plugin functionality.
 */
public class EquatePlugin1Test extends AbstractGhidraHeadedIntegrationTest {

	private Listing listing;
	private EquatePlugin equatePlugin;
	private CodeBrowserPlugin cb;
	private DockingActionIf setAction;
	private DockingActionIf renameAction;
	private DockingActionIf removeAction;
	private Program program;
	private TestEnv env;
	private PluginTool tool;

	private final static String SHOW_BLOCK_NAME_OPTION = GhidraOptions.OPERAND_GROUP_TITLE +
		Options.DELIMITER + GhidraOptions.OPTION_SHOW_BLOCK_NAME;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();
		env = new TestEnv();
		tool = env.showTool(program);

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(EquateTablePlugin.class.getName());
		tool.addPlugin(EquatePlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		cb = getPlugin(tool, CodeBrowserPlugin.class);
		equatePlugin = getPlugin(tool, EquatePlugin.class);

		listing = program.getListing();

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		options.getBoolean(SHOW_BLOCK_NAME_OPTION, false);
		setAction = getAction(equatePlugin, "Set Equate");
		renameAction = getAction(equatePlugin, "Rename Equate");
		removeAction = getAction(equatePlugin, "Remove Equate");
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("sample", ProgramBuilder._X86);
		builder.createMemory("test", "0x01001000", 0x100);
		builder.createMemory("test", "0x01002000", 0x100);
		builder.createMemory("test", "0x01003000", 0x4000);

		// for selection containing a function stack address
		builder.setBytes("0x01004bbd", "c2 08 00"); // return of previous function
		builder.setBytes("0x01004bc0", "53 8b 5c 24 08 56 8b 35 b8 10 00 01 57 ff 35 78 80 00 01 " +
			"53 ff d6 8b 3d e0 10 00 01 53 ff d7 8d 5c 43 02 68 9c 13 00 01 53 ff d6 53 ff d7 " +
			"ff 35 7c 80 00 01 8d 5c 43 02 53 ff d6 53 ff d7 8d 5c 43 02 68 e0 17 00 01 53 ff " +
			"d6 53 ff d7 66 83 64 43 02 00 8d 44 43 02 5f 5e 5b c2 04 00");
		builder.disassemble(new AddressSet(builder.getProgram(), builder.addr("0x01004bc0"),
			builder.addr("0x01004c1a")), true);
		builder.createFunction("0x01004bc0");

		//
		// Add bytes that result in instructions containing scalar values for X86
		//
		builder.setBytes("0x010018d6", "6a 02", true);
		builder.setBytes("0x010062d6", "83 c0 05", true);
		builder.setBytes("0x01002a83", "6a 01", true);
		builder.setBytes("0x01002a8e", "c2 10 00", true);

		// not an equate - for testing action enablement
		builder.setBytes("0x01003359", "74 4c", true);
		builder.setBytes("0x01003a94", "6a fd", true);

		builder.setBytes("0x010035be", "6a 02", true);
		builder.setBytes("0x0100364c", "6a 02", true);

		builder.setBytes("0x01004ad6", "6a 02", true);
		builder.setBytes("0x01004bbd", "c2 08 00", true);
		builder.setBytes("0x01004e4a", "6a 5a", true);

		builder.setBytes("0x01005128", "68 b7 00 00 00", true);
		builder.setBytes("0x0100519f", "6a 02", true);
		builder.setBytes("0x01005a01", "3d b7 00 00 00", true);
		builder.setBytes("0x01005e9d", "68 b7 00 00 00", true);
		builder.setBytes("0x010059ef", "83 f8 ff", true);
		builder.setBytes("0x01004c20", "6a 02", true);
		builder.setBytes("0x01003384", "ff ff", true);

		builder.setBytes("0x010060f0", "6a 01", true);
		builder.createEquate("0x010060f0", "ANOTHER_ONE", 1, 0);

		builder.setBytes("0x01006133", "68 b7 00 00 00", true);
		builder.setBytes("0x01006245", "68 b7 00 00 00", true);
		builder.setBytes("0x010063da", "f6 45 fc 02", true);
		builder.setBytes("0x0100649a", "a1 c0 85 00 01", true);
		builder.setBytes("0x010064c5", "83 c4 08", true);
		builder.setBytes("0x010064a3", "68 10 66 00 01", true);
		builder.setBytes("0x010064ae", "83 c4 04", true);
		builder.setBytes("0x01006500", "83 c4 08", true);
		builder.setBytes("0x010065a7", "c7 45 fc ff ff ff ff", true);
		builder.setBytes("0x010065b0", "c7 45 fc ff ff ff ff", true);
		builder.createEquate("0x010064c5", "EIGHT", 8, 1);
		builder.createEquate("0x01006500", "EIGHT", 8, 1);

		builder.setBytes("0x01006455", "83 c4 04", true);
		builder.createEquate("0x01006455", "FOUR", 4, 1);
		builder.createEquate("0x010064ae", "FOUR", 4, 1);

		builder.setBytes("0x01006140", "6a 01", true);
		builder.setBytes("0x01006147", "6a 01", true);
		builder.setBytes("0x0100621d", "6a 01", true);
		builder.setBytes("0x010063f4", "6a 01", true);
		builder.createEquate("0x01006140", "ONE", 1, 0);
		builder.createEquate("0x01006147", "ONE", 1, 0);
		builder.createEquate("0x0100621d", "ONE", 1, 1);
		builder.createEquate("0x010063f4", "ONE", 1, 1);

		builder.setBytes("0x010061a2", "6a 30", true);
		builder.createEquate("0x010061a2", "THIRTY", 0x30, 0);

		builder.setBytes("0x01006252", "6a 02", true);
		builder.setBytes("0x0100644d", "6a 02", true);
		builder.createEquate("0x01006252", "TWO", 2, 0);
		builder.createEquate("0x010063da", "TWO", 2, 1);
		builder.createEquate("0x0100644d", "TWO", 2, 0);

		builder.setBytes("0x010060b2", "6a 02", true);
		builder.setBytes("0x01006254", "6a 02", true);
		builder.createEquate("0x010060b2", "TWO_alt", 2, 1);
		builder.createEquate("0x01006254", "TWO_alt", 2, 0);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/*
	 * Tests that the set equate menu option is enabled when the cursor is on a valid scalar.
	 */
	@Test
	public void testSetEquateActionEnabled() {
		assertNotNull(setAction);
		assertNotNull(renameAction);
		assertNotNull(removeAction);

		// Set Equate should be in the popup if the location is over a scalar operand.
		putCursorOnOperand(0x01002a83, 0);
		assertTrue(setAction.isEnabledForContext(getListingContext()));
		//rename and remove should not be in popup in this case
		assertFalse(renameAction.isEnabledForContext(getListingContext()));
		assertFalse(removeAction.isEnabledForContext(getListingContext()));
	}

	/*
	 * Tests that the rename menu option is enabled when the cursor is on an address with
	 * a valid equate set.
	 */
	@Test
	public void testRenameActionEnabled() {

		putCursorOnOperand(0x010060f0, 0);

		// Rename and remove Equate should be in the popup if the location is over an existing equate.
		assertTrue(renameAction.isEnabledForContext(getListingContext()));
		assertTrue(removeAction.isEnabledForContext(getListingContext()));

		//set equate action should not be in the popup in this case
		assertFalse(setAction.isEnabledForContext(getListingContext()));
	}

	/*
	 * Tests that the remove menu option is available when the cursor is on an address
	 * with a valid equate set.
	 */
	@Test
	public void testRemoveActionEnabled() {

		putCursorOnOperand(0x010064c5, 1);

		// Remove Equate should be in the popup if the location is over an existing equate.
		assertTrue(renameAction.isEnabledForContext(getListingContext()));
		assertTrue(removeAction.isEnabledForContext(getListingContext()));

		//set equate action should not be in the popup in this case
		assertFalse(setAction.isEnabledForContext(getListingContext()));
	}

	@Test
	public void testSetEquate() throws Exception {

		putCursorOnOperand(0x01002a8e, 0);
		assertTextUnderCursor("0x10");

		SetEquateDialog d = showSetEquateDialog();

		// 	the dialog should show the value of the equate being created.
		JLabel label = (JLabel) findComponentByName(d.getComponent(), "EquateField");
		assertNotNull(label);
		assertEquals("Scalar Value:  0x10 (16)", label.getText());

		String name = "MY_EQUATE";
		pickEquate(d, name);

		assertTextUnderCursor(name);

		// make sure the browser reverts back to showing the scalar value
		undo(program);

		assertTextUnderCursor("0x10");

		redo(program);

		assertTextUnderCursor(name);
	}

	@Test
	public void testSetEquate_ApplyToCurrentSelection_and_OverwriteInSelection() throws Exception {

		// put the cursor on a scalar
		putCursorOnOperand(0x01006245, 0);

		// make a selection containing the scalar above
		AddressSet scalarAddresses = selectScalars_0xb7();

		// grab the dialog and select the radio button for 'apply to current selection'
		SetEquateDialog d = showSetEquateDialog();
		String name = "Bob";
		pickEquate(d, name);

		// verify all scalars in selection were changed and those not in selection were not changed
		assertEquateAt(name, scalarAddresses);
		assertNoEquateAt("1005128", "0xb7");
		assertNoEquateAt("1005a01", "EAX,0xb7");

		// run again on selection including all the named scalars and one non-named scalars run
		// without overwrite
		putCursorOnOperand(0x1005128, 0);
		AddressSet newScalarAddresses =
			selectSetAndInvalidAddress(scalarAddresses, addr("1005128"));

		d = showSetEquateDialog();

		pressButtonByText(d, "Current selection");

		String newEquateText = "Cat";
		pickEquate(d, newEquateText);

		// only the one originally not a named scalar should be named "Cat"
		AddressSet newSet = new AddressSet();
		newSet.add(addr("1005128"));

		assertEquateAt(name, scalarAddresses); // these should be Bob
		assertEquateAt(newEquateText, newSet); // this should be Cat
		assertNoEquateAt("1005a01", "EAX,0xb7"); // this was not in selection; should be no equate

		undo(program);

		//
		// Test overwrite
		//
		putCursorOnOperand(0x1005128, 0);

		newScalarAddresses = selectSetAndInvalidAddress(scalarAddresses, addr("1005128"));

		d = showSetEquateDialog();

		pressButtonByText(d, "Current selection");
		pressButtonByText(d, "Overwrite existing equates");

		newEquateText = "Cat";
		pickEquate(d, newEquateText);

		// verify all scalars in selection were changed and those not in selection were not changed
		assertEquateAt(newEquateText, newScalarAddresses);
		assertNoEquateAt("1005a01", "EAX,0xb7");
	}

	@Test
	public void testSetEquate_ApplyToCurrentSelectionContainingScalarInStackAdd_NewName()
			throws Exception {

		putCursorOnOperand(0x01004bbd, 0);

		// make a selection containing the scalar above
		makeSelection(tool, program, toAddressSet(addr("1004bbd"), addr("1004bc5")));

		SetEquateDialog d = showSetEquateDialog();
		String name = "Bob";
		pickEquate(d, name);

		Address addr = addr(0x1004bc1);
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(addr);
		assertEquals(1, equates.size());
		assertEquals("Bob", equates.get(0).getName());
	}

	@Test
	public void testSetEquate_ApplyToWholeProgram() throws Exception {

		putCursorOnOperand(0x010018d6, 0);

		SetEquateDialog d = showSetEquateDialog();
		pressButtonByText(d, "Entire program");
		String name = "bob";
		pickEquate(d, name);

		AddressSet scalarAddresses = new AddressSet();
		scalarAddresses.add(addr("10035be"));
		scalarAddresses.add(addr("100364c"));
		scalarAddresses.add(addr("1004ad6"));
		assertEquateAt(name, scalarAddresses);
	}

	@Test
	public void testSetEquate_BlankEquateNameRemove() throws Exception {

		int equateAddr = 0x010018d6;
		createEquate(equateAddr, 0, "bob", 0x2);
		EquateTable equateTable = program.getEquateTable();
		assertNotNull(equateTable.getEquate(addr(equateAddr), 0, 0x2));

		putCursorOnOperand(equateAddr, 0);
		SetEquateDialog d = showRenameEquatesDialog();
		String name = "";
		pickEquate(d, name);

		assertNull(equateTable.getEquate(addr(equateAddr), 0, 0x2));
	}

	@Test
	public void testSetEqute_ChooseExistingEquateName() throws Exception {

		putCursorOnOperand(0x010018d6, 0);

		SetEquateDialog d = showSetEquateDialog();

		// 	the dialog should show the value of the equate being created.
		JLabel label = (JLabel) findComponentByName(d.getComponent(), "EquateField");
		assertNotNull(label);
		assertEquals("Scalar Value:  0x2 (2)", label.getText());

		GhidraTable table = findComponent(d.getComponent(), GhidraTable.class);
		assertNotNull(table);

		clickTableCell(table, 1, 0, 2);

		JTextField filterField = findComponent(d.getComponent(), JTextField.class);
		triggerEnter(filterField);
		flushProgramEvents();

		String name = "TWO_alt";
		assertTextUnderCursor(name);

		undo(program);

		assertTextUnderCursor("0x2");

		redo(program);

		assertTextUnderCursor(name);
	}

	@Test
	public void testSetEquate_Overwrite_ApplyToWholeProgram() throws Exception {

		// put the cursor on a scalar
		putCursorOnOperand(0x01006245, 0);

		// grab the dialog and select the radio button for 'apply to current location'
		SetEquateDialog d = showSetEquateDialog();
		pressButtonByText(d, "Current location");
		String equateText = "Bob";
		pickEquate(d, equateText);

		// verify that the equate Bob was applied correctly
		AddressSet oneAddrInSet = new AddressSet();
		oneAddrInSet.add(addr("1006245"));

		assertEquateAt(equateText, oneAddrInSet);

		//run again putting cursor on new location and choosing "entire program" and not choosing "overwrite"
		putCursorOnOperand(0x1005128, 0);

		d = showSetEquateDialog();

		pressButtonByText(d, "Entire program");

		String newEquateText = "Cat";
		pickEquate(d, newEquateText);

		// All but the one originally called Bob should be named "Cat"
		AddressSet newSet = new AddressSet();
		newSet.add(addr("1005128"));
		newSet.add(addr("1005e9d"));
		newSet.add(addr("1006133"));
		newSet.add(addr("1005a01"));

		assertEquateAt(equateText, oneAddrInSet); //this one should still be Bob bc we didn't choose overwrite

		//undo
		undo(program);

		//run again with overwrite
		putCursorOnOperand(0x1005128, 0);

		d = showSetEquateDialog();

		pressButtonByText(d, "Entire program");
		pressButtonByText(d, "Overwrite existing equates");
		newEquateText = "Cat";
		pickEquate(d, newEquateText);

		// all in program should now be "Cat"
		AddressSet newestSet = new AddressSet();
		newSet.add(addr("1005128"));
		newSet.add(addr("1005e9d"));
		newSet.add(addr("1006133"));
		newSet.add(addr("1006245"));
		newSet.add(addr("1005a01"));

		assertEquateAt(newEquateText, newestSet);
	}

	@Test
	public void testSetEquate_WithMultipleEntriesForValue_One() throws Exception {

		//
		// Tests that we can apply an equate from an enum that has multiple names mapped to a
		// single value.
		//

		/*
		 	enum TestEnum {
			    One = 0x0
			    Two_a = 0x1
			    Two_b = 0x1
			    Two_c = 0x1
			    Three = 0x2
			}
		 */
		createEnumWithMultipleNamesForValue();

		Address address = addr(0x01002a83);
		putCursorOnOperand(address, 0);

		// pick first name with that value
		SetEquateDialog d = showSetEquateDialog();
		String name = "Two_a";
		pickEquate(d, name);

		assertTextUnderCursor(name);
	}

	@Test
	public void testSetEquate_WithMultipleEntriesForValue_Two() throws Exception {

		//
		// Tests that we can apply an equate from an enum that has multiple names mapped to a
		// single value.
		//

		/*
		 	enum TestEnum {
			    One = 0x0
			    Two_a = 0x1
			    Two_b = 0x1
			    Two_c = 0x1
			    Three = 0x2
			}
		 */
		createEnumWithMultipleNamesForValue();

		Address address = addr(0x01002a83);
		putCursorOnOperand(address, 0);

		// pick first name with that value
		SetEquateDialog d = showSetEquateDialog();
		String name = "Two_b";
		pickEquate(d, name);

		assertTextUnderCursor(name);
	}

	@Test
	public void testRenameEquate() throws Exception {
		putCursorOnOperand(0x010064c5, 1);

		SetEquateDialog d = showRenameEquatesDialog();

		// 	the dialog should show the value of the equate being created.
		JLabel label = (JLabel) findComponentByName(d.getComponent(), "EquateField");

		// Verify the location in the code browser -- should have the
		// equate name in the operand field.
		assertNotNull(label);
		assertEquals("Scalar Value:  0x8 (8)", label.getText());

		JTextField tf = findComponent(d.getComponent(), JTextField.class);
		assertNotNull(tf);
		assertEquals("", tf.getText());
		setText(tf, "MY_EQUATE");
		triggerEnter(tf);

		flushProgramEvents();

		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("ESP,MY_EQUATE", f.getText());

		undo(program);

		// make sure the browser reverts back to showing the scalar value
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("ESP,EIGHT", f.getText());

		redo(program);

		f = (ListingTextField) cb.getCurrentField();
		assertEquals("ESP,MY_EQUATE", f.getText());

	}

	@Test
	public void testDuplicateName() throws Exception {
		// set an equate using an existing equate name, but with a different
		// value; should get a message in the status area of the dialog.

		putCursorOnOperand(0x010018d6, 0);

		SetEquateDialog d = showSetEquateDialog();

		// 	the dialog should show the value of the equate being created.
		JTextField tf = findComponent(d.getComponent(), JTextField.class);
		setText(tf, "THIRTY");
		triggerEnter(tf);

		JLabel label = (JLabel) findComponentByName(d.getComponent(), "statusLabel");
		assertNotNull(label);
		assertEquals("Equate THIRTY exists with value 0x30 (48)", label.getText());
		cancel(d);
	}

	@Test
	public void testMultipleEquatesSameValue() throws Exception {

		createSameValueDifferentNameEquates();

		putCursorOnOperand(0x010062d6, 1);

		SetEquateDialog d = showSetEquateDialog();

		GhidraTable table = findComponent(d.getComponent(), GhidraTable.class);
		assertNotNull(table);

		TableModel model = table.getModel();
		assertEquals(5, model.getRowCount());
		for (int i = 0; i < 5; i++) {
			String value = (String) model.getValueAt(i, 0);
			assertTrue(value.startsWith("MY_EQUATE_"));
		}

		cancel(d);
	}

	@Test
	public void testRemoveEquate() throws Exception {

		putCursorOnOperand(0x010063da, 1);
		performAction(removeAction, cb.getProvider(), true);

		waitForBusyTool(tool);

		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("0x2", f.getFieldElement(0, 22).getText());

		undo(program);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("TWO", f.getFieldElement(0, 22).getText());

		redo(program);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("0x2", f.getFieldElement(0, 22).getText());
	}

	/*
	 * Tests that the user is prompted before attempting to remove an equate within
	 * a selection.
	 *
	 * @throws Exception
	 */
	@Test
	public void testRemoveSelection() throws Exception {

		// Place the cursor on a known scalar.
		putCursorOnOperand(0x01006455, 1);

		// Make a selection containing the scalar above.
		makeSelection(tool, program, addr("1004bbd"), addr("1004bc5"));

		// Call the action to remove the equate(s).
		performAction(removeAction, cb.getProvider(), false);

		// Wait for the confirmation dialog to pop up and verify.
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		close(d);
	}

	@Test
	public void testProgramClosed() {
		putCursorOnOperand(0x010063da, 1);

		env.close(program);

		assertFalse(setAction.isEnabledForContext(new DefaultActionContext()));
	}

	/*
	 * Tests that the user cannot set an equate on a scalar that is
	 * undefined (the equate option is not made available).
	 */
	@Test
	public void testUndefinedData() {

		// First put the cursor at a location with known scalar data.
		putCursorOnOperand(0x010062d6, 1);

		// Verify that the set equate option is available.
		assertTrue(setAction.isEnabledForContext(getListingContext()));

		// Now call the clear() function to set the data to undefined  ("??").
		ClearCmd cmd = new ClearCmd(new AddressSet(addr(0x010062d6)));
		applyCmd(program, cmd);

		// Verify that the menu option for setting an equate is not enabled.
		assertFalse(setAction.isEnabledForContext(getListingContext()));
	}

	@Test
	public void testConvertActionsEnabled() {
		// convert action should be enabled only over a scalar value in an operand
		putCursorOnOperand(0x01003359, 0);
		assertConvertActionsInPopup(false);

		putCursorOnOperand(0x0100649a, 0);
		assertConvertActionsInPopup(false);

		putCursorOnOperand(0x010064ae, 1);
		assertConvertNonSignedActionsInPopup();

		putCursorOnOperand(0x010064a3, 0);
		assertConvertNonCharNonSignedActionsInPopup();

		putCursorOnOperand(0x01003a94, 0);
		assertNonFloatConvertActionsInPopup();
	}

	@Test
	public void testConvertInSelection() {

		Address min = addr("01004bee");
		Address max = addr("01004c20");
		Address addr1 = addr("01004bf4");
		Address addr2 = addr("01004c0d");
		Address addr3 = addr("01004c20");
		Address addr4 = addr("01004c1a");
		Address addr5 = addr("01004c02");
		selectRange(min, max);
		putCursorOnOperand(0x01004c20, 0);

		DockingActionIf action = getAction(equatePlugin, "Convert To Unsigned Octal");
		performAction(action, getListingContext(), true);
		waitForTasks();

		// These are the 0x2 values in the selection that should have been converted.
		EquateTable et = program.getEquateTable();
		assertFalse("Couldn't find equate", et.getEquates(addr1, 1).isEmpty());
		assertFalse("Couldn't find equate", et.getEquates(addr2, 0).isEmpty());
		assertFalse("Couldn't find equate", et.getEquates(addr3, 0).isEmpty());

		// These are not 0x2 values in the selection that should not have been converted.
		assertTrue("Equate should't have been made", et.getEquates(addr2, 1).isEmpty());
		assertTrue("Equate should't have been made", et.getEquates(addr4, 0).isEmpty());
		assertTrue("Equate should't have been made", et.getEquates(addr5, 0).isEmpty());
	}

	@Test
	public void testConvertOnSignedData() throws Exception {
		Address addr = addr(0x01003384);
		createSignedData(addr);
		Data data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof SignedWordDataType);

		goTo(addr);
		DockingActionIf action = getAction(equatePlugin, "Convert To Unsigned Decimal");
		performAction(action, getListingContext(), true);
		waitForTasks();

		data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof WordDataType);
	}

	@Test
	public void testConvertOnUnsignedData() throws Exception {
		Address addr = addr(0x01003384);
		createUnsignedData(addr);
		Data data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof WordDataType);

		goTo(addr);
		DockingActionIf action = getAction(equatePlugin, "Convert To Signed Decimal");
		performAction(action, getListingContext(), true);
		waitForTasks();

		data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof SignedWordDataType);
	}

	@Test
	public void testNoConvertOnData() throws Exception {
		Address addr = addr(0x01003384);

		// action should not apply to BooleanDataType which produces Scalar value
		createData(addr, BooleanDataType.dataType);
		Data data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof BooleanDataType);

		goTo(addr);
		DockingActionIf action = getAction(equatePlugin, "Convert To Signed Decimal");

		assertFalse(action.isAddToPopup(getListingContext()));
		assertFalse(action.isEnabledForContext(getListingContext()));

		// action should not apply to Enum which produces Scalar value
		EnumDataType myEnum = new EnumDataType("Joe", 2);
		myEnum.add("ValFFFF", -1);

		createData(addr, myEnum);
		data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof Enum);

		goTo(addr);

		assertFalse(action.isAddToPopup(getListingContext()));
		assertFalse(action.isEnabledForContext(getListingContext()));
	}

	@Test
	public void testConvertPickSameDatatype() throws Exception {
		Address addr = addr(0x01003384);
		createSignedData(addr);
		Data data = program.getListing().getDataAt(addr);
		assertTrue(data.getDataType() instanceof SignedWordDataType);

		goTo(addr);
		DockingActionIf action = getAction(equatePlugin, "Convert To Signed Decimal");
		performAction(action, getListingContext(), true);
		waitForTasks();

		assertEquals(data.getDataType(), program.getListing().getDataAt(addr).getDataType());
		assertTrue(data.getDataType() instanceof SignedWordDataType);
	}

	@Test
	public void testConvertMenuItemText1() {

		putCursorOnOperand(0x010064ae, 1);

		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		int found = 0;
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (!name.startsWith("Convert") || !action.isAddToPopup(getListingContext())) {
				continue;
			}
			MenuData popupMenuData = action.getPopupMenuData();
			String[] popupPath = popupMenuData.getMenuPath();
			assertEquals(2, popupPath.length);

			if (name.indexOf("Unsigned Decimal") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Decimal"));
				assertTrue(popupPath[1].endsWith(" 4"));
			}
			else if (name.indexOf("Unsigned Octal") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Octal"));
				assertTrue(popupPath[1].endsWith(" 4o"));
			}
			else if (name.indexOf("Unsigned Binary") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Binary"));
				assertTrue(popupPath[1].endsWith(" 00000000000000000000000000000100b"));
			}
			else if (name.indexOf("Unsigned Hex") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Hex"));
				assertTrue(popupPath[1].endsWith(" 0x4"));
			}
			else if (name.indexOf("Char") >= 0) {
				assertTrue(popupPath[1].startsWith("Char"));
			}
			else if (name.indexOf("Double") >= 0) {
				assertTrue(popupPath[1].startsWith("Double"));
				assertTrue(popupPath[1].endsWith(" 1.976262583364986E-323"));
			}
			else if (name.indexOf("Float") >= 0) {
				assertTrue(popupPath[1].startsWith("Float"));
				assertTrue(popupPath[1].endsWith(" 5.6051939E-45"));
			}
			else {
				fail("Unhandled Convert item: " + name);
			}
			++found;
		}
		assertEquals("Did not find convert actions expected", 7, found);
	}

	@Test
	public void testConvertMenuItemText2() {
		putCursorOnOperand(0x010064a3, 0);

		int found = 0;
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (!name.startsWith("Convert") || !action.isAddToPopup(getListingContext())) {
				continue;
			}
			MenuData popupMenuData = action.getPopupMenuData();
			String[] popupPath = popupMenuData.getMenuPath();
			assertEquals(2, popupPath.length);

			if (name.indexOf("Unsigned Decimal") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Decimal"));
				assertTrue(popupPath[1].endsWith(" 16803344"));
			}
			else if (name.indexOf("Signed Decimal") > 0) {
				assertTrue(popupPath[1].startsWith("Signed Decimal"));
				assertTrue(popupPath[1].endsWith(" 16803344"));
			}
			else if (name.indexOf("Unsigned Octal") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Octal"));
				assertTrue(popupPath[1].endsWith(" 100063020o"));
			}
			else if (name.indexOf("Unsigned Hex") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Hex"));
				assertTrue(popupPath[1].endsWith(" 0x1006610"));
			}
			else if (name.indexOf("Char") >= 0) {
				assertTrue(popupPath[1].startsWith("Char"));
			}
			else if (name.indexOf("Unsigned Binary") >= 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Binary"));
			}
			else if (name.indexOf("Float") >= 0) {
				assertTrue(popupPath[1].startsWith("Float"));
			}
			else if (name.indexOf("Double") >= 0) {
				assertTrue(popupPath[1].startsWith("Double"));
			}
			else {
				fail("Unhandled Convert item: " + name);
			}
			++found;
		}
		assertEquals("Did not find convert actions expected", 7, found);
	}

	@Test
	public void testConvertMenuItemText3() {

		putCursorOnOperand(0x01003a94, 0);

		int found = 0;
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (!name.startsWith("Convert") || !action.isAddToPopup(getListingContext())) {
				continue;
			}
			MenuData popupMenuData = action.getPopupMenuData();
			String[] popupPath = popupMenuData.getMenuPath();
			assertEquals(2, popupPath.length);

			if (name.indexOf("Unsigned Decimal") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Decimal"));
				assertTrue(popupPath[1].endsWith(" 4294967293"));
			}
			else if (name.indexOf("Signed Decimal") > 0) {
				assertTrue(popupPath[1].startsWith("Signed Decimal"));
				assertTrue(popupPath[1].endsWith(" -3"));
			}
			else if (name.indexOf("Unsigned Binary") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Binary"));
				assertTrue(popupPath[1].endsWith(" 11111111111111111111111111111101b"));
			}
			else if (name.indexOf("Unsigned Octal") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Octal"));
				assertTrue(popupPath[1].endsWith(" 37777777775o"));
			}
			else if (name.indexOf("Signed Hex") > 0) {
				assertTrue(popupPath[1].startsWith("Signed Hex"));
				assertTrue(popupPath[1].endsWith(" -0x3"));
			}
			else if (name.indexOf("Unsigned Hex") > 0) {
				assertTrue(popupPath[1].startsWith("Unsigned Hex"));
				assertTrue(popupPath[1].endsWith(" 0xFFFFFFFD"));
			}
			else if (name.indexOf("Char") >= 0) {
				assertTrue(popupPath[1].startsWith("Char"));
			}
			else {
				fail("Unhandled Convert item: " + name);
			}
			++found;
		}
		assertEquals("Did not find convert actions expected", 7, found);
	}

	@Test
	public void testConvertToSignedDecimal() {
		// create a signed decimal as the equate name
		putCursorOnOperand(0x01003a94, 0);

		Instruction inst = listing.getInstructionAt(addr(0x01003a94));
		Scalar scalar = inst.getScalar(0);

		DockingActionIf sdAction = getAction(equatePlugin, "Convert To Signed Decimal");
		performAction(sdAction, cb.getProvider(), true);
		waitForTasks();
		cb.updateNow();

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getSignedValue(), 10),
			tf.getFieldElement(0, 11).getText());

		DockingActionIf octAction = getAction(equatePlugin, "Convert To Unsigned Octal");
		performAction(octAction, cb.getProvider(), true);
		waitForTasks();
		cb.updateNow();
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getUnsignedValue(), 8) + "o",
			tf.getFieldElement(0, 11).getText());

		undo(program);
		// should revert back to signed decimal
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getSignedValue(), 16),
			tf.getFieldElement(0, 11).getText());

		redo(program);
		// should be set To Unsigned Octal
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getUnsignedValue(), 8) + "o",
			tf.getFieldElement(0, 11).getText());

		undo(program);
		undo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-0x3", tf.getFieldElement(0, 11).getText());
	}

	@Test
	public void testConvertToUnsignedDecimal() {
		// create an unsigned decimal as the equate name
		putCursorOnOperand(0x010059ef, 1);
		ComponentProvider provider = cb.getProvider();

		Instruction inst = listing.getInstructionAt(addr(0x010059ef));
		Scalar scalar = inst.getScalar(1);

		DockingActionIf action = getAction(equatePlugin, "Convert To Unsigned Decimal");
		performAction(action, provider, true);
		waitForTasks();

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getUnsignedValue(), 10),
			tf.getFieldElement(0, 11).getText());

		undo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("-0x1", tf.getFieldElement(0, 11).getText());

		redo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("4294967295", tf.getFieldElement(0, 11).getText());
	}

	@Test
	public void testConvertOctal() {

		putCursorOnOperand(0x01005a01, 1);

		Instruction inst = listing.getInstructionAt(addr(0x01005a01));
		Scalar scalar = inst.getScalar(1);

		performAction("Convert To Unsigned Octal");

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getUnsignedValue(), 8) + "o",
			tf.getFieldElement(0, 11).getText());

		undo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("0x" + Long.toString(scalar.getSignedValue(), 16),
			tf.getFieldElement(0, 11).getText());

		redo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals(Long.toString(scalar.getUnsignedValue(), 8) + "o",
			tf.getFieldElement(0, 11).getText());

	}

	@Test
	public void testConvertToUnsignedHex() {

		putCursorOnOperand(0x010065a7, 1);

		Instruction inst = listing.getInstructionAt(addr(0x010065a7));
		Scalar scalar = inst.getScalar(1);

		performAction("Convert To Unsigned Hex");

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("0x" + Long.toString(scalar.getUnsignedValue(), 16),
			tf.getFieldElement(0, 23).getText());

		undo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("0x" + Long.toString(scalar.getUnsignedValue(), 16),
			tf.getFieldElement(0, 23).getText());

		redo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("0x" + Long.toString(scalar.getUnsignedValue(), 16),
			tf.getFieldElement(0, 23).getText());
	}

	@Test
	public void testConvertChar() {
		putCursorOnOperand(0x01004e4a, 0);

		Instruction inst = listing.getInstructionAt(addr(0x01004e4a));
		Scalar scalar = inst.getScalar(0);

		performAction("Convert To Char");

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("'" + new String(new byte[] { (byte) scalar.getUnsignedValue() }) + "'",
			tf.getFieldElement(0, 11).getText());

		undo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("0x" + Long.toString(scalar.getUnsignedValue(), 16),
			tf.getFieldElement(0, 11).getText());

		redo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("'" + new String(new byte[] { (byte) scalar.getUnsignedValue() }) + "'",
			tf.getFieldElement(0, 11).getText());
	}

	@Test
	public void testConvertCharUnprintable() {
		putCursorOnOperand(0x0100519f, 0);

		Instruction inst = listing.getInstructionAt(addr(0x0100519f));
		Scalar scalar = inst.getScalar(0);
		assertEquals(2, scalar.getUnsignedValue());

		performAction("Convert To Char");

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("02h", tf.getFieldElement(0, 11).getText());

		undo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("0x" + Long.toString(scalar.getUnsignedValue(), 16),
			tf.getFieldElement(0, 11).getText());

		redo(program);
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("02h", tf.getFieldElement(0, 11).getText());
	}

	@Test
	public void testConvertOn0xffffff() {
		// Specifically test this because it has been problematic in the past.
		putCursorOnOperand(0x010065a7, 1);
		Address addr1 = addr(0x010065a7);
		Address addr2 = addr(0x010065b0);
		selectRange(addr1, addr2);

		performAction("Convert To Unsigned Octal");

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("37777777777o", tf.getFieldElement(0, 24).getText());

		putCursorOnOperand(0x010065b0, 1);

		ListingTextField tf2 = (ListingTextField) cb.getCurrentField();
		assertEquals(tf.toString(), tf2.toString());
		assertEquals("37777777777o", tf.getFieldElement(0, 24).getText());
	}

//==================================================================================================
// Private methods
//==================================================================================================

	private ListingActionContext getListingContext() {
		ActionContext context = cb.getProvider().getActionContext(null);
		return (ListingActionContext) context;
	}

	private void pickEquate(SetEquateDialog dialog, String name) {
		JTextField tf = findComponent(dialog.getComponent(), JTextField.class);
		assertNotNull(tf);
		assertEquals("", tf.getText());
		setText(tf, name);
		triggerEnter(tf);

		flushProgramEvents();
	}

	private void assertTextUnderCursor(String text) {
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(text, f.getText());
	}

	private Enum createEnumWithMultipleNamesForValue() {

		EnumDataType edt = new EnumDataType(new CategoryPath("/"), "TestEnum", 3);
		edt.add("One", 0);
		edt.add("Two_a", 1);
		edt.add("Two_b", 1);
		edt.add("Two_c", 1);
		edt.add("Three", 2);
		edt.setDescription("Test Enum with multiple names for a value");
		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

		return modifyProgram(program, p -> {
			return (Enum) dtm.addDataType(edt, null);
		});
	}

	private void performAction(String name) {
		ComponentProvider provider = cb.getProvider();
		DockingActionIf action = getAction(equatePlugin, name);
		performAction(action, provider, true);
		waitForTasks();
	}

	private void assertConvertActionsInPopup(boolean inPopup) {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String actionName = action.getName();
			if (actionName.startsWith("Convert")) {
				assertEquals("Unexpected popup menu item state: " + actionName, inPopup,
					action.isAddToPopup(getListingContext()));
			}
		}
	}

	private void assertNonFloatConvertActionsInPopup() {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String actionName = action.getName();
			if (actionName.startsWith("Convert")) {
				boolean inPopup =
					!(actionName.indexOf("Double") > 0 || actionName.indexOf("Float") > 0);
				assertEquals("Unexpected popup menu item state: " + actionName, inPopup,
					action.isAddToPopup(getListingContext()));
			}
		}
	}

	private void assertConvertNonCharNonSignedActionsInPopup() {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf element : actions) {
			String name = element.getName();
			if (name.startsWith("Convert") &&
				(name.indexOf("Char") < 0 && name.indexOf("Signed") < 0)) {
				assertTrue(element.isAddToPopup(getListingContext()));
			}
		}
	}

	private void assertConvertNonSignedActionsInPopup() {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (name.startsWith("Convert") && name.indexOf("Signed") < 0) {
				assertTrue(action.isAddToPopup(getListingContext()));
			}
		}
	}

	private void createEquate(long address, int opIndex, String equateName, long equateValue)
			throws Exception {
		EquateTable equateTable = program.getEquateTable();

		int transactionID = program.startTransaction("Test - Create Equate at " + address);
		Equate equate = equateTable.createEquate(equateName, equateValue);
		equate.addReference(addr(address), opIndex);
		program.endTransaction(transactionID, true);

		flushProgramEvents();
	}

	private void cancel(SetEquateDialog d) {
		pressButtonByText(d.getComponent(), "Cancel");
	}

	private SetEquateDialog showSetEquateDialog() {
		performAction(setAction, cb.getProvider(), false);
		SetEquateDialog d = waitForDialogComponent(SetEquateDialog.class);
		assertEquals("Set Equate", d.getTitle());
		return d;
	}

	private void createSameValueDifferentNameEquates() {

		tx(program, () -> {
			EquateTable eqTable = program.getEquateTable();
			for (int i = 0; i < 5; i++) {
				eqTable.createEquate("MY_EQUATE_" + i, 5);
			}
		});
	}

	private void assertNoEquateAt(String addressString, String scalarText) {
		Address address = program.getAddressFactory().getAddress(addressString);
		cb.goToField(address, OperandFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(scalarText, f.getText());
	}

	private void assertEquateAt(String equateText, AddressSet scalarAddresses) {
		for (AddressRange addressRange : scalarAddresses) {
			Address address = addressRange.getMinAddress();
			cb.goToField(address, OperandFieldFactory.FIELD_NAME, 0, 0);
			ListingTextField f = (ListingTextField) cb.getCurrentField();
			assertEquals("Equate \"" + equateText + "\" not applied @ " + address, equateText,
				f.getText());
		}
	}

	private AddressSet selectScalars_0xb7() {
		AddressSet addrs = toAddressSet(0x1006245, 0x1006133, 0x1005e9d);
		makeSelection(tool, program, addrs);
		return addrs;
	}

	private AddressSet selectRange(Address start, Address end) {
		AddressSet addrs = toAddressSet(start, end);
		makeSelection(tool, program, addrs);
		return addrs;
	}

	private AddressSet selectSetAndInvalidAddress(AddressSet addAddrSet, Address addr) {

		AddressSet addrs = new AddressSet();

		addrs.add(addAddrSet);
		addrs.add(addr);

		makeSelection(tool, program, addrs);
		return addrs;
	}

	private void fireOperandFieldLocationEvent(Address addr, int opIndex) {
		Instruction inst = listing.getInstructionAt(addr);
		if (inst == null) {
			fail("Must have a code unit to use this method");
		}

		String str = CodeUnitFormat.DEFAULT.getOperandRepresentationString(inst, opIndex);
		OperandFieldLocation loc =
			new OperandFieldLocation(program, addr, null, null, str, opIndex, 0);
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));

		waitForSwing();
	}

	private void putCursorOnOperand(long offset, int opIndex) {
		Address addr = addr(offset);
		fireOperandFieldLocationEvent(addr, opIndex);
		waitForBusyTool(tool);
	}

	private void putCursorOnOperand(Address addr, int opIndex) {
		fireOperandFieldLocationEvent(addr, opIndex);
		waitForBusyTool(tool);
	}

	private SetEquateDialog showRenameEquatesDialog() {
		performAction(renameAction, cb.getProvider(), false);
		SetEquateDialog d = waitForDialogComponent(SetEquateDialog.class);
		assertEquals("Rename Equate", d.getTitle());
		return d;
	}

	private void flushProgramEvents() {
		program.flushEvents();
		waitForBusyTool(tool);
	}

	private void createSignedData(Address addr) throws Exception {
		createData(addr, SignedWordDataType.dataType);
	}

	private void createUnsignedData(Address addr) throws Exception {
		createData(addr, WordDataType.dataType);
	}

	private void createData(Address addr, DataType dt) throws Exception {
		int id = program.startTransaction("Test - Create Data");

		dt = dt.clone(program.getDataTypeManager());
		int length = dt.getLength();
		assertTrue("", length > 0);
		listing.clearCodeUnits(addr, addr.add(length - 1), true);
		program.getListing().createData(addr, dt);

		program.endTransaction(id, true);
	}

	private Address addr(long offset) {
		return addr(program, offset);
	}

	private Address addr(String offset) {
		return addr(program, offset);
	}

	private Address addr(Program p, long offset) {
		AddressFactory addrMap = program.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private Address addr(Program p, String offset) {
		AddressFactory addrMap = p.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		try {
			return space.getAddress(offset);
		}
		catch (AddressFormatException e) {
			throw new AssertException("Unable to create address from String '" + offset + "'", e);
		}
	}

	private void goTo(Address a) {
		goTo(tool, program, a);
	}

	private AddressSet toAddressSet(long... offsets) {
		List<Address> list = addrs(offsets);
		AddressSet addrs = toAddressSet(list);
		return addrs;
	}

	private List<Address> addrs(long... offsets) {
		List<Address> result = new ArrayList<>();
		for (long offset : offsets) {
			result.add(addr(offset));
		}
		return result;
	}

}
