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

import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.Test;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.app.util.datatype.ApplyEnumDialog;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.UniversalID;
import ghidra.util.table.GhidraTable;

/**
 * Tests the Equate Plugin functionality.
 */
public class EquatePlugin1Test extends AbstractEquatePluginTest {

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
	public void testApplyToOptions_SetEquate() {
		putCursorOnOperand(0x01002a8e, 0);

		SetEquateDialog d = showSetEquateDialog();

		JRadioButton applyToCurrentButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToCurrent");
		JRadioButton applyToSelectionButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToSelection");
		final JRadioButton applyToAllButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToAll");
		JCheckBox overwriteExistingEquatesButton =
			(JCheckBox) findComponentByName(d.getComponent(), "Overwrite");

		//dialog should come up with "current location" enabled and selected in all cases (even if a selection)		
		assertNotNull(applyToCurrentButton);
		assertTrue(applyToCurrentButton.isEnabled());
		assertTrue(applyToCurrentButton.isSelected());

		//no selection in this case so should be disabled and not selected
		assertNotNull(applyToSelectionButton);
		assertFalse(applyToSelectionButton.isEnabled());
		assertFalse(applyToSelectionButton.isSelected());

		//entire program should be enabled but not selected
		assertNotNull(applyToAllButton);
		assertTrue(applyToAllButton.isEnabled());
		assertFalse(applyToAllButton.isSelected());

		//overwrite existing should be visible but not be enabled or selected
		assertTrue(overwriteExistingEquatesButton.isVisible());
		assertFalse(overwriteExistingEquatesButton.isEnabled());
		assertFalse(overwriteExistingEquatesButton.isSelected());

		//select applyToAll and verify that the other buttons respond accordingly
		applyToAllButton.setSelected(true);
		runSwing(
			() -> applyToAllButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		assertTrue(applyToAllButton.isSelected());
		assertFalse(applyToCurrentButton.isSelected());
		assertFalse(applyToSelectionButton.isSelected());
		assertTrue(overwriteExistingEquatesButton.isEnabled());
		assertFalse(overwriteExistingEquatesButton.isSelected());

		close(d);
	}

	/*
	 * Tests that the current selection button is the default option on the 
	 * Set Equate dialog if there is a range of addresses selected.
	 * 
	 * @throws InterruptedException
	 * @throws InvocationTargetException
	 */
	@Test
	public void testApplyToOptions_SetEquate_Selection() {

		// put the cursor on a scalar 
		putCursorOnOperand(0x1004bbd, 0);

		// make a selection containing the scalar above.
		makeSelection(tool, program, addr("1004bbd"), addr("1004bc5"));

		SetEquateDialog d = showSetEquateDialog();

		JRadioButton applyToCurrentButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToCurrent");
		final JRadioButton applyToSelectionButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToSelection");
		final JRadioButton applyToAllButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToAll");
		JCheckBox overwriteExistingEquatesButton =
			(JCheckBox) findComponentByName(d.getComponent(), "Overwrite");

		//change as of 7.0 - dialog should come up with "current location" enabled.
		assertNotNull(applyToCurrentButton);
		assertTrue(applyToCurrentButton.isEnabled());
		assertFalse(applyToCurrentButton.isSelected());

		//have selection in this case so should be enabled but not selected
		assertNotNull(applyToSelectionButton);
		assertTrue(applyToSelectionButton.isEnabled());
		assertTrue(applyToSelectionButton.isSelected());

		//entire program should be enabled but not selected
		assertNotNull(applyToAllButton);
		assertTrue(applyToAllButton.isEnabled());
		assertFalse(applyToAllButton.isSelected());

		//overwrite existing should be visible and enabled, but not selected
		assertTrue(overwriteExistingEquatesButton.isVisible());
		assertTrue(overwriteExistingEquatesButton.isEnabled());
		assertFalse(overwriteExistingEquatesButton.isSelected());

		//select applyToSelection and verify that the other buttons respond accordingly
		applyToSelectionButton.setSelected(true);
		runSwing(
			() -> applyToSelectionButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		assertFalse(applyToAllButton.isSelected());
		assertFalse(applyToCurrentButton.isSelected());
		assertTrue(applyToSelectionButton.isSelected());
		assertTrue(overwriteExistingEquatesButton.isEnabled());
		assertFalse(overwriteExistingEquatesButton.isSelected());

		close(d);
	}

	@Test
	public void testApplyToOptions_RenameEquate() {
		putCursorOnOperand(0x010064c5, 1);

		performAction(renameAction, cb.getProvider(), false);
		SetEquateDialog d =
			waitForDialogComponent(SetEquateDialog.class);
		assertNotNull(d);

		JRadioButton applyToCurrentButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToCurrent");
		JRadioButton applyToSelectionButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToSelection");
		JRadioButton applyToAllButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToAll");
		JCheckBox overwriteExistingEquatesButton =
			(JCheckBox) findComponentByName(d.getComponent(), "Overwrite");

		//no selection so should come up selected
		assertNotNull(applyToCurrentButton);
		assertTrue(applyToCurrentButton.isEnabled());
		assertTrue(applyToCurrentButton.isSelected());

		//no selection in this case so should be disabled and not selected
		assertNotNull(applyToSelectionButton);
		assertFalse(applyToSelectionButton.isEnabled());
		assertFalse(applyToSelectionButton.isSelected());

		//entire program should be enabled but not selected
		assertNotNull(applyToAllButton);
		assertTrue(applyToAllButton.isEnabled());
		assertFalse(applyToAllButton.isSelected());

		//overwrite existing should not be visible, enabled, or selected
		assertFalse(overwriteExistingEquatesButton.isVisible());
		assertFalse(overwriteExistingEquatesButton.isEnabled());
		assertFalse(overwriteExistingEquatesButton.isSelected());

		close(d);
	}

	@Test
	public void testApplyToOptions_RenameEquate_Selection() {

		putCursorOnOperand(0x010064c5, 1);

		selectRange(addr("10064c5"), addr("10064ce"));

		performAction(renameAction, cb.getProvider(), false);
		SetEquateDialog d =
			waitForDialogComponent(SetEquateDialog.class);
		assertNotNull(d);

		JRadioButton applyToCurrentButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToCurrent");
		JRadioButton applyToSelectionButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToSelection");
		JRadioButton applyToAllButton =
			(JRadioButton) findComponentByName(d.getComponent(), "applyToAll");
		JCheckBox overwriteExistingEquatesButton =
			(JCheckBox) findComponentByName(d.getComponent(), "Overwrite");

		//change as of 7.0 - dialog should come up with "current location" enabled.
		assertNotNull(applyToCurrentButton);
		assertTrue(applyToCurrentButton.isEnabled());
		assertFalse(applyToCurrentButton.isSelected());

		//have selection in this case so should be enabled but not selected
		assertNotNull(applyToSelectionButton);
		assertTrue(applyToSelectionButton.isEnabled());
		assertTrue(applyToSelectionButton.isSelected());

		//entire program should be enabled but not selected
		assertNotNull(applyToAllButton);
		assertTrue(applyToAllButton.isEnabled());
		assertFalse(applyToAllButton.isSelected());

		//overwrite existing should not be visible, enabled, or selected
		assertFalse(overwriteExistingEquatesButton.isVisible());
		assertFalse(overwriteExistingEquatesButton.isEnabled());
		assertFalse(overwriteExistingEquatesButton.isSelected());

		close(d);
	}

	@Test
	public void testSetEquate() throws Exception {
		putCursorOnOperand(0x01002a8e, 0);

		SetEquateDialog d = showSetEquateDialog();

		// 	the dialog should show the value of the equate being created.			

		JLabel label = (JLabel) findComponentByName(d.getComponent(), "EquateField");
		// Verify the location in the code browser -- should have the
		// equate name in the operand field.
		assertNotNull(label);
		assertEquals("Scalar Value:  0x10 (16)", label.getText());

		JTextField tf = findComponent(d.getComponent(), JTextField.class);
		assertNotNull(tf);
		assertEquals("", tf.getText());
		setText(tf, "MY_EQUATE");
		triggerEnter(tf);

		flushProgramEvents();

		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("MY_EQUATE", f.getText());

		undo(program);
		// make sure the browser reverts back to showing the scalar value
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("0x10", f.getText());

		redo(program);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("MY_EQUATE", f.getText());

	}

	@Test
	public void testSetEquate_ApplyToCurrentSelection_and_OverwriteInSelection() throws Exception {

		// put the cursor on a scalar 
		putCursorOnOperand(0x01006245, 0);

		// make a selection containing the scalar above
		AddressSet scalarAddresses = selectScalars_0xb7();

		// grab the dialog and select the radio button for 'apply to current selection'
		SetEquateDialog d = getSetEquatesDialog();
		pressButtonByText(d, "Current selection");
		String equateText = "Bob";
		setEquateString(equateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

		// verify all scalars in selection were changed and those not in selection were not changed
		assertEquateAt(equateText, scalarAddresses);
		assertNoEquateAt("1005128", "0xb7");
		assertNoEquateAt("1005a01", "EAX,0xb7");

		//run again on selection including all the named scalars and one non-named scalars 
		//run without overwrite
		putCursorOnOperand(0x1005128, 0);
		AddressSet newScalarAddresses =
			selectSetAndInvalidAddress(scalarAddresses, addr("1005128"));

		d = getSetEquatesDialog();

		pressButtonByText(d, "Current selection");

		String newEquateText = "Cat";
		setEquateString(newEquateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

		// only the one originally not a named scalar should be named "Cat"	
		AddressSet newSet = new AddressSet();
		newSet.add(addr("1005128"));

		assertEquateAt(equateText, scalarAddresses); //these should be Bob
		assertEquateAt(newEquateText, newSet); //this should be Cat
		assertNoEquateAt("1005a01", "EAX,0xb7"); // this was not in selection so should be no equate at all

		undo(program);

		// Test overwrite
		putCursorOnOperand(0x1005128, 0);

		newScalarAddresses = selectSetAndInvalidAddress(scalarAddresses, addr("1005128"));

		d = getSetEquatesDialog();

		pressButtonByText(d, "Current selection");
		pressButtonByText(d, "Overwrite existing equates");
		newEquateText = "Cat";
		setEquateString(newEquateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

		// verify all scalars in selection were changed and those not in selection were not changed
		assertEquateAt(newEquateText, newScalarAddresses);
		assertNoEquateAt("1005a01", "EAX,0xb7");
	}

	@Test
	public void testSetEquate_ApplyToCurrentSelectionContainingScalarInStackAdd_NewName()
			throws Exception {

		// put the cursor on a scalar 
		putCursorOnOperand(0x01004bbd, 0);

		// make a selection containing the scalar above
		makeSelection(tool, program, toAddressSet(addr("1004bbd"), addr("1004bc5")));

		// grab the dialog and select the radio button for 'apply to current selection'
		SetEquateDialog d = getSetEquatesDialog();
		pressButtonByText(d, "Current selection");
		String equateText = "Bob";
		setEquateString(equateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

		// verify all scalars in selection were changed and those not in selection were not changed
		Address addr = addr(0x1004bc1);
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(addr);
		assertEquals(1, equates.size());
		assertEquals("Bob", equates.get(0).getName());
	}

	@Test
	public void testSetEquate_ApplyToWholeProgram() throws Exception {

		// put the cursor on a scalar 
		putCursorOnOperand(0x010018d6, 0);

		// grab the dialog and select the radio button for 'apply to whole program'
		SetEquateDialog d = getSetEquatesDialog();
		pressButtonByText(d, "Entire program");
		String equateText = "Bob";
		setEquateString(equateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

		// verify all scalars were changed
		AddressSet scalarAddresses = new AddressSet();
		scalarAddresses.add(addr("10035be"));
		scalarAddresses.add(addr("100364c"));
		scalarAddresses.add(addr("1004ad6"));

		assertEquateAt(equateText, scalarAddresses);
	}

	@Test
	public void testSetEquate_BlankEquateNameRemove() throws Exception {

		int equateAddr = 0x010018d6;
		createEquate(equateAddr, 0, "bob", 0x2);
		EquateTable equateTable = program.getEquateTable();
		assertNotNull(equateTable.getEquate(addr(equateAddr), 0, 0x2));

		putCursorOnOperand(equateAddr, 0);
		SetEquateDialog d = showRenameEquatesDialog();
		JButton btn = findButtonByText(d, "OK");
		assertNotNull(btn);
		pressButton(btn);

		flushProgramEvents();

		assertNull(equateTable.getEquate(addr(equateAddr), 0, 0x2));
	}

	@Test
	public void testSetEqute_ChooseExistingEquateName() throws Exception {
		putCursorOnOperand(0x010018d6, 0);

		SetEquateDialog d = showSetEquateDialog();

		// 	the dialog should show the value of the equate being created.			
		JLabel label = (JLabel) findComponentByName(d.getComponent(), "EquateField");

		// Verify the location in the code browser -- should have the
		// equate name in the operand field.
		assertNotNull(label);
		assertEquals("Scalar Value:  0x2 (2)", label.getText());

		GhidraTable table = findComponent(d.getComponent(), GhidraTable.class);
		assertNotNull(table);

		clickTableCell(table, 1, 0, 2);

		JTextField filterField = findComponent(d.getComponent(), JTextField.class);
		triggerEnter(filterField);

		flushProgramEvents();

		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("TWO_alt", f.getText());

		undo(program);
		// make sure the browser reverts back to showing the scalar value
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("0x2", f.getText());

		redo(program);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("TWO_alt", f.getText());
	}

	@Test
	public void testSetEquate_Overwrite_ApplyToWholeProgram() throws Exception {

		// put the cursor on a scalar 
		putCursorOnOperand(0x01006245, 0);

		// grab the dialog and select the radio button for 'apply to current location'
		SetEquateDialog d = getSetEquatesDialog();
		pressButtonByText(d, "Current location");
		String equateText = "Bob";
		setEquateString(equateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

		// verify that the equate Bob was applied correctly
		AddressSet oneAddrInSet = new AddressSet();
		oneAddrInSet.add(addr("1006245"));

		assertEquateAt(equateText, oneAddrInSet);

		//run again putting cursor on new location and choosing "entire program" and not choosing "overwrite"
		putCursorOnOperand(0x1005128, 0);

		d = getSetEquatesDialog();

		pressButtonByText(d, "Entire program");

		String newEquateText = "Cat";
		setEquateString(newEquateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

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

		d = getSetEquatesDialog();

		pressButtonByText(d, "Entire program");
		pressButtonByText(d, "Overwrite existing equates");
		newEquateText = "Cat";
		setEquateString(newEquateText, d);
		pressButtonByText(d, "OK");

		flushProgramEvents();

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

		assertFalse(setAction.isEnabledForContext(new ActionContext()));
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
				assertTrue(popupPath[1].endsWith(" 5.605194E-45"));
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
		ComponentProvider provider = tool.getComponentProvider(PluginConstants.CODE_BROWSER);

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

	@Test
	public void testApplyEnumInSelection_DoOnSubOperands() throws Exception {
		Address addr1 = addr(0x01004bdd);
		Address addr2 = addr(0x01004c1f);
		selectRange(addr1, addr2);

		EquateTable et = program.getEquateTable();
		UniversalID id = createEnum_myEnum().getUniversalID();

		createEquate(0x01004c0d, 1, "bob", 0x0);
		assertNotNull(et.getEquate(addr(0x01004c0d), 1, 0x0));

		ApplyEnumDialog d = performApplyEnum();

		setToggleButtonSelected(d.getComponent(), "subOpCB", true);

		DropDownSelectionTextField<DataType> textField = d.getEditor().getDropDownTextField();
		triggerText(textField, "myEnum");
		waitForSwing();
		triggerEnter(textField);
		waitForTasks();

		assertFalse(et.getEquate(addr(0x01004c0d), 1, 0x0).getName().equals("bob"));
		assertEquatesAppliedFromEnum(id, 0, 2, 4);
		assertEquatesNotApplied(id, 3, 5);

		// Special cases right below
		String errorMsg = "Equate not applied from Enum . No equate for ";
		Address twoSameScalarAddress = addr(0x01004bdf);
		assertNotNull(errorMsg, et.getEquate(twoSameScalarAddress, 1, 0x2));

		Address twoDifferentScalarsAddress = addr(0x01004c0d);
		assertNotNull(errorMsg, et.getEquate(twoDifferentScalarsAddress, 0, 0x2));
		assertNotNull(errorMsg, et.getEquate(twoDifferentScalarsAddress, 1, 0x0));
	}

	@Test
	public void testApplyEnumInSelection_DontDoOnSubOperands() throws Exception {
		Address addr1 = addr(0x01004c0b);
		Address addr2 = addr(0x01004c17);
		selectRange(addr1, addr2);

		UniversalID id = createEnum_myEnum().getUniversalID();

		ApplyEnumDialog d = performApplyEnum();

		setToggleButtonSelected(d.getComponent(), "subOpCB", false);

		DropDownSelectionTextField<DataType> textField = d.getEditor().getDropDownTextField();
		triggerText(textField, "myEnum");
		waitForSwing();
		triggerEnter(textField);

		assertEquatesAppliedFromEnum(id, 0);
		assertEquatesNotApplied(id, 2);
	}
}
