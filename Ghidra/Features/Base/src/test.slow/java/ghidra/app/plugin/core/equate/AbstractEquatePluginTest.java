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

import java.util.Set;

import javax.swing.JTextField;

import org.junit.After;
import org.junit.Before;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.GhidraOptions;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.app.util.datatype.ApplyEnumDialog;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.OperandFieldLocation;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Tests the Equate Plugin functionality.
 */
public abstract class AbstractEquatePluginTest extends AbstractProgramBasedTest {

	protected Listing listing;
	protected EquatePlugin equatePlugin;
	protected CodeBrowserPlugin cb;
	protected DockingActionIf setAction;
	protected DockingActionIf renameAction;
	protected DockingActionIf removeAction;
	protected DockingActionIf applyEnumAction;

	protected final static String SHOW_BLOCK_NAME_OPTION = GhidraOptions.OPERAND_GROUP_TITLE +
		Options.DELIMITER + GhidraOptions.OPTION_SHOW_BLOCK_NAME;

	/**
	 * Sets up the plugins and actions for the tests.
	 * 
	 * @throws Exception
	 */
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
		removeAction = getAction(equatePlugin, "Remove Equate");
		applyEnumAction = getAction(equatePlugin, "Apply Enum");
	}

	@Override
	protected String getProgramName() {
		return "notepad";
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	/**
	 * Builds a program and sets equates.
	 * 
	 * @return
	 * @throws Exception
	 */
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86);
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

	@Override
	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

//=================================================================================================
// Private Methods
//=================================================================================================

	protected ListingActionContext getListingContext() {
		ActionContext context = cb.getProvider().getActionContext(null);
		return (ListingActionContext) context;
	}

	protected ApplyEnumDialog performApplyEnum() {
		ComponentProvider provider = tool.getComponentProvider(PluginConstants.CODE_BROWSER);
		DockingActionIf action = getAction(equatePlugin, "Apply Enum");
		performAction(action, provider, false);
		ApplyEnumDialog d = waitForDialogComponent(ApplyEnumDialog.class);
		return d;
	}

	protected void performAction(String name) {
		ComponentProvider provider = cb.getProvider();
		DockingActionIf action = getAction(equatePlugin, name);
		performAction(action, provider, true);
		waitForTasks();
	}

	protected void assertConvertActionsInPopup(boolean inPopup) {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String actionName = action.getName();
			if (actionName.startsWith("Convert")) {
				assertEquals("Unexpected popup menu item state: " + actionName, inPopup,
					action.isAddToPopup(getListingContext()));
			}
		}
	}

	protected void assertNonFloatConvertActionsInPopup() {
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

	protected void assertConvertNonCharNonSignedActionsInPopup() {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf element : actions) {
			String name = element.getName();
			if (name.startsWith("Convert") &&
				(name.indexOf("Char") < 0 && name.indexOf("Signed") < 0)) {
				assertTrue(element.isAddToPopup(getListingContext()));
			}
		}
	}

	protected void assertConvertNonSignedActionsInPopup() {
		Set<DockingActionIf> actions = getActionsByOwner(tool, "EquatePlugin");
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (name.startsWith("Convert") && name.indexOf("Signed") < 0) {
				assertTrue(action.isAddToPopup(getListingContext()));
			}
		}
	}

	protected void createEquate(long address, int opIndex, String equateName, long equateValue)
			throws Exception {
		EquateTable equateTable = program.getEquateTable();

		int transactionID = program.startTransaction("Test - Create Equate at " + address);
		Equate equate = equateTable.createEquate(equateName, equateValue);
		equate.addReference(addr(address), opIndex);
		program.endTransaction(transactionID, true);

		flushProgramEvents();
	}

	protected void assertEquatesAppliedFromEnum(UniversalID id, int... values) {
		EquateTable et = program.getEquateTable();
		for (int value : values) {
			String fullName = EquateManager.formatNameForEquate(id, value);
			assertNotNull("Equate not applied from Enum . No equate for " + fullName,
				et.getEquate(fullName));
		}
	}

	protected void assertEquatesNotApplied(UniversalID id, int... values) {
		EquateTable et = program.getEquateTable();

		for (int value : values) {
			String fullName = EquateManager.formatNameForEquate(id, value);
			assertNull("Equate should not have been applied " + fullName, et.getEquate(fullName));
		}
	}

	protected void cancel(SetEquateDialog d) {
		pressButtonByText(d.getComponent(), "Cancel");
	}

	protected SetEquateDialog showSetEquateDialog() {
		performAction(setAction, cb.getProvider(), false);
		SetEquateDialog d =
			waitForDialogComponent(tool.getToolFrame(), SetEquateDialog.class, 2000);
		assertNotNull(d);
		assertEquals("Set Equate", d.getTitle());
		return d;
	}

	protected void createSameValueDifferentNameEquates()
			throws DuplicateNameException, InvalidInputException {
		EquateTable eqTable = program.getEquateTable();

		int transactionID =
			program.startTransaction("Test - Create Equate - Same Value/Different Name");
		for (int i = 0; i < 5; i++) {
			eqTable.createEquate("MY_EQUATE_" + i, 5);
		}
		program.endTransaction(transactionID, true);

		flushProgramEvents();
	}

	protected void assertNoEquateAt(String addressString, String scalarText) {
		Address address = program.getAddressFactory().getAddress(addressString);
		cb.goToField(address, OperandFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(scalarText, f.getText());
	}

	protected void assertEquateAt(String equateText, AddressSet scalarAddresses) {
		for (AddressRange addressRange : scalarAddresses) {
			Address address = addressRange.getMinAddress();
			cb.goToField(address, OperandFieldFactory.FIELD_NAME, 0, 0);
			ListingTextField f = (ListingTextField) cb.getCurrentField();
			assertEquals("Equate \"" + equateText + "\" not applied @ " + address, equateText,
				f.getText());
		}
	}

	protected Enum createEnum_myEnum() {

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

	protected void setEquateString(String equateText, SetEquateDialog d) {
		JTextField tf = findComponent(d.getComponent(), JTextField.class);
		assertNotNull(tf);
		assertEquals("", tf.getText());
		setText(tf, equateText);
	}

	protected SetEquateDialog getSetEquatesDialog() {
		SetEquateDialog d = showSetEquateDialog();
		return d;
	}

	protected AddressSet selectScalars_0xb7() {
		AddressSet addrs = toAddressSet(0x1006245, 0x1006133, 0x1005e9d);
		makeSelection(tool, program, addrs);
		return addrs;
	}

	protected AddressSet selectRange(Address start, Address end) {
		AddressSet addrs = toAddressSet(start, end);
		makeSelection(tool, program, addrs);
		return addrs;
	}

	protected AddressSet selectSetAndInvalidAddress(AddressSet addAddrSet, Address addr) {

		AddressSet addrs = new AddressSet();

		addrs.add(addAddrSet);
		addrs.add(addr);

		makeSelection(tool, program, addrs);
		return addrs;
	}

	protected void fireOperandFieldLocationEvent(Address addr, int opIndex) {
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

	protected void putCursorOnOperand(long offset, int opIndex) {
		Address addr = addr(offset);
		fireOperandFieldLocationEvent(addr, opIndex);
		waitForBusyTool(tool);
	}

	protected SetEquateDialog showRenameEquatesDialog() {
		performAction(renameAction, cb.getProvider(), false);
		SetEquateDialog d =
			waitForDialogComponent(tool.getToolFrame(), SetEquateDialog.class, 2000);
		assertNotNull(d);
		assertEquals("Rename Equate", d.getTitle());
		return d;
	}

	protected void flushProgramEvents() {
		program.flushEvents();
		waitForBusyTool(tool);
	}

	protected void createSignedData(Address addr) throws Exception {
		createData(addr, SignedWordDataType.dataType);
	}

	protected void createUnsignedData(Address addr) throws Exception {
		createData(addr, WordDataType.dataType);
	}

	protected void createData(Address addr, DataType dt) throws Exception {
		int id = program.startTransaction("Test - Create Data");

		dt = dt.clone(program.getDataTypeManager());
		int length = dt.getLength();
		assertTrue("", length > 0);
		listing.clearCodeUnits(addr, addr.add(length - 1), true);
		program.getListing().createData(addr, dt);

		program.endTransaction(id, true);
	}

}
