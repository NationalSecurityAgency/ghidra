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
package help.screenshot;

import java.awt.Rectangle;

import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.equate.EquatePlugin;
import ghidra.app.plugin.core.equate.EquateTableProvider;
import ghidra.app.plugin.core.flowarrow.FlowArrowPlugin;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.app.util.datatype.ApplyEnumDialog;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Generates screenshots associated with Equate dialog.
 */
public class EquatePluginScreenShots extends GhidraScreenShotGenerator {

	private CodeBrowserPlugin cb;
	private DockingActionIf setAction;
	private EquatePlugin equatePlugin;
	private Listing listing;
	private DockingActionIf removeAction;
	private DockingActionIf applyEnum;

	@Override
	public void tearDown() throws Exception {
		closeAllWindows();
		super.tearDown();
	}

	@Override
	public void setUp() throws Exception {

		super.setUp();

		FlowArrowPlugin flowArrowPlugin = getPlugin(tool, FlowArrowPlugin.class);
		tool.removePlugins(new Plugin[] { flowArrowPlugin });

		equatePlugin = getPlugin(tool, EquatePlugin.class);
		cb = getPlugin(tool, CodeBrowserPlugin.class);

		env.showTool(program);

		setAction = getAction(equatePlugin, "Set Equate");
		removeAction = getAction(equatePlugin, "Remove Equate");
		applyEnum = getAction(equatePlugin, "Apply Enum");

		listing = program.getListing();

		createEquateData();
	}

	private void createEquateData() throws Exception {
		int txId = program.startTransaction("TEST");

		// Set some equates.  These address must contain valid scalars or the equates
		// will fail to be set and our tests will not operate as expected.  So make
		// sure these locations are defined.
		CreateDataCmd cmd = new CreateDataCmd(addr(0x0040e00d), new ByteDataType());
		cmd.applyTo(program);
		cmd = new CreateDataCmd(addr(0x00401013), new ByteDataType());
		cmd.applyTo(program);
		cmd = new CreateDataCmd(addr(0x00401031), new ByteDataType());
		cmd.applyTo(program);
		cmd = new CreateDataCmd(addr(0x00401053), new ByteDataType());
		cmd.applyTo(program);
		cmd = new CreateDataCmd(addr(0x0040c27c), new ByteDataType()); //Bad equate addr
		cmd.applyTo(program);
		cmd = new CreateDataCmd(addr(0x0040c238), new ByteDataType()); //Enum based equate addr
		cmd.applyTo(program);

		// Now set some equates...
		setEquate(0x0040e00d, "EQ_1");
		setEquate(0x00401013, "EQ_2");
		setEquate(0x00401031, "EQ_3");
		setEquate(0x00401053, "EQ_4");
		setEquate(0x0040c27c, "dtID:0123456789012345678:0");
		setEquate(0x0040c238, "__FAVOR_ATOM");

		program.endTransaction(txId, true);
	}

	/**
	 * Captures the Equate Table dialog.
	 */
	@Test
	public void testEquatesTable() {
		showProvider(EquateTableProvider.class);
		captureIsolatedProvider(EquateTableProvider.class, 611, 345);
	}

	/**
	 * Captures the confirmation dialog that is shown before allowing a delete from
	 * the Equate Table.
	 */
	@Test
	public void testConfirmEquateDelete() {
		showProvider(EquateTableProvider.class);
		performAction("Delete Equate", "EquateTablePlugin", false);

		waitForDialogComponent(OptionDialog.class);
		captureDialog(OptionDialog.class);
	}

	/**
	 * Captures the info dialog that is shown when the user attempts to remove an
	 * equate on a selection.
	 *
	 * @throws Exception
	 */
	@Test
	public void testRemoveSelection() throws Exception {

		// Place the cursor on a known scalar.
		Address addr = program.getMinAddress().getNewAddress(0x0040e00d);
		fireOperandFieldLocationEvent(addr, 0);

		// Make a selection containing the scalar above.
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSet addressSet = new AddressSet();
		addressSet.addRange(addressFactory.getAddress("0040e00d"),
			addressFactory.getAddress("0040e00f"));
		ProgramSelection programSelection = new ProgramSelection(addressSet);
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Test Scalar Selection", programSelection, program));

		// Call the action to remove the equates from the selection.
		performAction(removeAction, cb.getProvider(), false);

		// Capture the confirmation dialog.
		waitForDialogComponent(OptionDialog.class);
		captureDialog(OptionDialog.class);
	}

	/**
	 * Captures the Set Equate dialog.
	 */
	@Test
	public void testSetEquate() {
		goToListing(0x0040c238, "Operands", true);
		performAction(setAction, cb.getProvider(), false);
		SetEquateDialog d = waitForDialogComponent(SetEquateDialog.class);

		JTextField tf = findComponent(d.getComponent(), JTextField.class);
		setText(tf, "E");
		captureDialog(SetEquateDialog.class);
	}

	/**
	 * Captures the listing before the apply enum action is executed.
	 */
	@Test
	public void testBeforeApplyEnum() {
		createEnum_myEnum();
		AddressFactory addrFactory = program.getAddressFactory();
		Address addr1 = addrFactory.getAddress("004019ac");
		Address addr2 = addrFactory.getAddress("004019c2");
		selectRange(addr1, addr2);
		positionListingTop(0x004019aa);

		long start = 0x004019aa;
		long end = 0x004019c8;
		captureListingRange(start, end, 630);

		// remove sidebar from image
		int h = image.getHeight(null);
		int w = image.getWidth(null);
		crop(new Rectangle(40, 0, w, h));
	}

	@Test
	public void testApplyEnum() throws Exception {

		DataTypeManager dtm = program.getDataTypeManager();
		ApplyEnumDialog dialog = new ApplyEnumDialog(tool, dtm);
		runSwing(() -> tool.showDialog(dialog), false);
		waitForSwing();
		captureDialog(dialog);
	}

	/**
	 * Captures the listing after the apply enum action is executed.
	 */
	@Test
	public void testAfterApplyEnum() {
		createEnum_myEnum();
		AddressFactory addrFactory = program.getAddressFactory();
		Address addr1 = addrFactory.getAddress("004019ac");
		Address addr2 = addrFactory.getAddress("004019c2");
		selectRange(addr1, addr2);
		performAction(applyEnum, cb.getProvider(), false);
		ApplyEnumDialog dialog = waitForDialogComponent(ApplyEnumDialog.class);
		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "myEnum");
		triggerEnter(tf);
		positionListingTop(0x004019aa);

		long start = 0x004019aa;
		long end = 0x004019c8;
		captureListingRange(start, end, 630);

		// remove sidebar from image
		int h = image.getHeight(null);
		int w = image.getWidth(null);
		crop(new Rectangle(40, 0, w, h));
	}

	/**
	 * Captures the Rename Equate dialog.
	 *
	 * @throws Exception
	 */
	@Test
	public void testRenameEquate() throws Exception {
		setEquate(0x0040c279, "EQ_1");
		goToListing(0x0040c238, "Operands", true);
		performAction("Rename Equate", "EquatePlugin", false);
		captureDialog();
	}

	/**
	 * Sets an equate on the given address.
	 *
	 * @param address the address of the equate
	 * @param name the equate name to set
	 * @throws Exception
	 */
	private void setEquate(long address, String name) throws Exception {
		goToListing(address, "Operands", true);

		performAction(setAction, cb.getProvider(), false);
		SetEquateDialog d = waitForDialogComponent(SetEquateDialog.class);

		final JTextField tf = findComponent(d.getComponent(), JTextField.class);
		setText(tf, name);

		SwingUtilities.invokeAndWait(() -> tf.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
	}

	/**
	 * Sets the cursor to point to the given address and operand.
	 *
	 * @param addr the address to point to
	 * @param opIndex the specific operand index
	 */
	private void fireOperandFieldLocationEvent(Address addr, int opIndex) {
		CodeUnit cu = listing.getCodeUnitAt(addr);

		String str = CodeUnitFormat.DEFAULT.getOperandRepresentationString(cu, opIndex);

		OperandFieldLocation loc =
			new OperandFieldLocation(program, addr, null, null, str, opIndex, 0);
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));

		waitForPostedSwingRunnables();
	}

	private AddressSet selectRange(Address start, Address end) {
		AddressSet addressSet = new AddressSet();
		addressSet.addRange(start, end);
		ProgramSelection programSelection = new ProgramSelection(addressSet);
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Test Scalar Selection", programSelection, program));

		return addressSet;
	}

	private void createEnum_myEnum() {
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		int id = dataTypeManager.startTransaction("EquatePluginTest enum");
		EnumDataType enumm = new EnumDataType("myEnum", 3);
		enumm.add("zeros", 0x0);
		enumm.add("oneTwoThree", 0x123);
		enumm.add("oneC", 0x1c);

		dataTypeManager.addDataType(enumm, null);
		dataTypeManager.endTransaction(id, true);
	}

}
