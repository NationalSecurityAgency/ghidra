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

import javax.swing.JCheckBox;
import javax.swing.JRadioButton;

import org.junit.Before;
import org.junit.Test;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.DropDownSelectionTextField;
import ghidra.GhidraOptions;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.app.util.datatype.ApplyEnumDialog;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.OperandFieldLocation;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.UniversalID;

/**
 * Tests the Equate Plugin functionality.
 */
public class EquatePlugin2Test extends AbstractProgramBasedTest {

	private final static String SHOW_BLOCK_NAME_OPTION = GhidraOptions.OPERAND_GROUP_TITLE +
		Options.DELIMITER + GhidraOptions.OPTION_SHOW_BLOCK_NAME;

	private DockingActionIf setAction;
	private DockingActionIf renameAction;
	private EquatePlugin equatePlugin;
	private CodeBrowserPlugin cb;
	private Listing listing;

	@Before
	public void setUp() throws Exception {

		initialize();

		equatePlugin = getPlugin(tool, EquatePlugin.class);

		cb = codeBrowser;

		listing = program.getListing();

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		options.getBoolean(SHOW_BLOCK_NAME_OPTION, false);
		setAction = getAction(equatePlugin, "Set Equate");
		renameAction = getAction(equatePlugin, "Rename Equate");
	}

	@Override
	public String getProgramName() {
		return "sample";
	}

	@Override
	public Program getProgram() throws Exception {

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

	private SetEquateDialog showSetEquateDialog() {
		performAction(setAction, cb.getProvider(), false);
		SetEquateDialog d = waitForDialogComponent(SetEquateDialog.class);
		assertEquals("Set Equate", d.getTitle());
		return d;
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

	private void assertEquatesAppliedFromEnum(UniversalID id, int... values) {
		EquateTable et = program.getEquateTable();
		for (int value : values) {
			String fullName = EquateManager.formatNameForEquate(id, value);
			assertNotNull("Equate not applied from Enum . No equate for " + fullName,
				et.getEquate(fullName));
		}
	}

	private void assertEquatesNotApplied(UniversalID id, int... values) {
		EquateTable et = program.getEquateTable();

		for (int value : values) {
			String fullName = EquateManager.formatNameForEquate(id, value);
			assertNull("Equate should not have been applied " + fullName, et.getEquate(fullName));
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

	private AddressSet selectRange(Address start, Address end) {
		AddressSet addrs = toAddressSet(start, end);
		makeSelection(tool, program, addrs);
		return addrs;
	}

	private void flushProgramEvents() {
		program.flushEvents();
		waitForBusyTool(tool);
	}

	private Enum createEnum_myEnum() {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		int id = dataTypeManager.startTransaction("EquatePluginTest enum");
		Enum enumm = new EnumDataType("myEnum", 1);
		enumm.add("zeroScalar", 0);
		enumm.add("oneScalar", 1);
		enumm.add("twoScalar", 2);
		enumm.add("threeScalar", 3);
		enumm.add("fourScalar", 4);
		enumm.add("fiveScalar", 5);

		enumm = (Enum) dataTypeManager.addDataType(enumm, null);
		dataTypeManager.endTransaction(id, true);

		return enumm;
	}

	private ApplyEnumDialog performApplyEnum() {
		ComponentProvider provider = cb.getProvider();
		DockingActionIf action = getAction(equatePlugin, "Apply Enum");
		performAction(action, provider, false);
		ApplyEnumDialog d = waitForDialogComponent(ApplyEnumDialog.class);
		return d;
	}

}
