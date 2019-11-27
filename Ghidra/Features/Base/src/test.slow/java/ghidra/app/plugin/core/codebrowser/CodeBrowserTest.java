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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.*;

import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.*;
import java.math.BigInteger;

import javax.swing.*;

import org.junit.*;

import docking.DockingUtils;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.table.GTable;
import generic.test.TestUtils;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.symtable.SymbolTablePlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.InteriorSelection;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.table.AddressPreviewTableModel;

public class CodeBrowserTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private FieldPanel fp;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setUpCodeBrowserTool(tool);

		program = buildProgram();
		addrFactory = program.getAddressFactory();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		NextPrevAddressPlugin np = env.getPlugin(NextPrevAddressPlugin.class);
		getAction(np, "Previous Location in History");
		getAction(np, "Clear History Buffer");
		cb = env.getPlugin(CodeBrowserPlugin.class);
		fp = cb.getFieldPanel();

		adjustFieldPanelSize(15);
		env.showTool();
		cb.updateNow();

		// ensure our mouse dragging works correctly, regardless of focus
		removeFocusListeners(cb.getListingPanel().getFieldPanel());
	}

	private void removeFocusListeners(JComponent c) {
		FocusListener[] listeners = c.getFocusListeners();
		for (FocusListener l : listeners) {
			c.removeFocusListener(l);
		}
	}

	private void adjustFieldPanelSize(int numRows) {
		JViewport vp = (JViewport) fp.getParent().getParent();
		cb.updateNow();
		int rowSize = getRowSize();
		final int desiredViewportHeight = rowSize * numRows;
		final Dimension d = vp.getExtentSize();
		if (d.height != desiredViewportHeight) {
			runSwing(() -> {
				JFrame f = tool.getToolFrame();
				Dimension d2 = f.getSize();
				d2.height += desiredViewportHeight - d.height;
				f.setSize(d2);
				fp.invalidate();
				f.validate();
			});
		}
		cb.updateNow();

	}

	private int getRowSize() {
		int rowHeight = 0;
		LayoutModel layoutModel = fp.getLayoutModel();
		Layout layout = layoutModel.getLayout(BigInteger.ZERO);
		for (int i = 0; i < layout.getNumFields(); i++) {
			Field field = layout.getField(i);
			int numRows = field.getNumRows();
			int fieldRowHeight = field.getHeight() / numRows;
			rowHeight = Math.max(rowHeight, fieldRowHeight);
		}
		return rowHeight;
	}

	private void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		addPlugin(tool, SymbolTablePlugin.class);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.createMemory(".bound_import.table", "0xf0000428", 0xa8);
		builder.createMemory(".debug_data", "0xf0001300", 0x1c);
		builder.applyDataType("f000130d", new DoubleDataType(), 1);
		builder.applyDataType("1001000", new Pointer32DataType(), 7);
		builder.disassemble("0x10036a2", 1);
		return builder.getProgram();
	}

	@Test
	public void testTableFromSelection() {
		ProgramSelection ps = dragToMakeSelection();

		DockingActionIf createTableAction = getAction(cb, "Create Table From Selection");
		performAction(createTableAction, true);

		TableComponentProvider<?> tableProvider =
			waitForComponentProvider(tool.getToolFrame(), TableComponentProvider.class, 2000);
		Object threadedPanel = TestUtils.getInstanceField("threadedPanel", tableProvider);
		GTable table = (GTable) TestUtils.getInstanceField("table", threadedPanel);
		ListSelectionModel selectionModel = table.getSelectionModel();

		// select all the rows
		selectionModel.setSelectionInterval(0, table.getRowCount() - 1);
		AddressPreviewTableModel addressModel = (AddressPreviewTableModel) tableProvider.getModel();

		// get a selection from the model and make sure it matches the original selection
		ProgramSelection tableProgramSelection =
			addressModel.getProgramSelection(table.getSelectedRows());

		AddressIterator addresses = tableProgramSelection.getAddresses(true);
		for (; addresses.hasNext();) {
			Address address = addresses.next();
			assertTrue(ps.contains(address));
		}
	}

	@Test
	public void testSimpleDragToCreateSelection() {
		ProgramSelection ps = dragToMakeSelection();

		// test click removes selection
		clickMouse(fp, 1, 0, 0, 1, 0);
		ps = getCurrentSelection();
		assertEquals(0, ps.getNumAddresses());
	}

	@Test
	public void testSelectionOnStructureInOffcutView_SCR_8089() throws DataTypeConflictException {
		// create offcut view, the view will contain 3 bytes, but the structure will be 4 bytes
		cb.getListingPanel().setView(new AddressSet(addr("0100101c"), addr("0100101e")));

		// create a structure that is 4 bytes and a single element of the struct spans the view
		// boundary
		StructureDataType dt = new StructureDataType("Test", 0);
		dt.add(new WordDataType());
		dt.add(new WordDataType());
		CreateDataCmd cmd = new CreateDataCmd(addr("0100101c"), dt);
		tool.execute(cmd, program);

		// open the structure
		cb.goToField(addr("0x100101c"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();

		// generate a selection on the structure element that spans view boundary.
		cb.goToField(addr("0x100101e"), "Bytes", 0, 4);
		cb.updateNow();
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x100101e"), "Field Name", 0, 0, 2, false);
		cb.updateNow();
		Point p2 = getCursorPoint();
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);
		waitForSwing();

		// verify that the program selection is correct
		ProgramSelection currentSelection = getCurrentSelection();
		assertEquals(addr("0100101e"), currentSelection.getMinAddress());
		assertEquals(addr("0100101f"), currentSelection.getMaxAddress());

		// verify that the fieldPanel selection was updated to fill out the element.
		FieldPanel fieldPanel = cb.getFieldPanel();
		FieldSelection selection = fieldPanel.getSelection();
		FieldRange fieldRange = selection.getFieldRange(0);
		FieldLocation start = fieldRange.getStart();
		FieldLocation end = fieldRange.getEnd();
		assertEquals(2, start.getIndex().intValue());
		assertEquals(0, start.getFieldNum());
		assertEquals(0, start.getCol());
		assertEquals(3, end.getIndex().intValue());
		assertEquals(0, start.getFieldNum());
		assertEquals(0, start.getCol());

	}

	@Test
	public void testShiftClickToSelect() {
		cb.goToField(addr("0x1003a50"), "Bytes", 0, 4);
		cb.goToField(addr("0x1003a44"), "Address", 0, 0, 0, false);
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1003a53"), "Mnemonic", 0, 0, 2, false);
		Point p2 = getCursorPoint();
		cb.goToField(addr("0x1003a5e"), "Mnemonic", 0, 0, 2, false);
		Point p3 = getCursorPoint();

		clickMouse(fp, 1, p2.x, p2.y, 1, 0);
		clickMouse(fp, 1, p3.x, p3.y, 1, InputEvent.SHIFT_DOWN_MASK);
		clickMouse(fp, 1, p1.x, p1.y, 1, InputEvent.SHIFT_DOWN_MASK);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(27, ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());
		assertEquals(addr("0x1003a44"), ps.getMinAddress());
	}

	@Test
	public void testCtrlClickToSelect() {
		cb.goToField(addr("0x1003a50"), "Bytes", 0, 4);
		cb.goToField(addr("0x1003a44"), "Address", 0, 0, 0, false);
		cb.updateNow();
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1003a53"), "Mnemonic", 0, 0, 2, false);
		cb.updateNow();
		Point p2 = getCursorPoint();
		cb.goToField(addr("0x1003a5e"), "Mnemonic", 0, 0, 2, false);
		cb.updateNow();
		Point p3 = getCursorPoint();

//		SymbolTablePlugin stp = getPlugin(tool, SymbolTablePlugin.class);
//		invokeInstanceMethod("openSymbolProvider", stp);

		dragMouse(fp, 1, p1.x, p1.y, p3.x, p3.y + 1, 0);

		clickMouse(fp, 1, p2.x, p2.y, 1, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

// TODO		
		ProgramSelection ps = getCurrentSelection();
		assertEquals(26, ps.getNumAddresses());
//		assertEquals(2, ps.getNumAddressRanges());
//
//		clickMouse(fp, 1, p2.x, p2.y, 1, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
//
//		ps = getCurrentSelection();
//		assertEquals(27, ps.getNumAddresses());
//		assertEquals(1, ps.getNumAddressRanges());

	}

	@Test
	public void testShiftDragToSelect() throws Exception {
		cb.goToField(addr("0x1003a50"), "Bytes", 0, 4);
		Point p1 = getCursorPoint();
		ViewerPosition vp1 = fp.getViewerPosition();

		postEvent(new MouseEvent(fp, MouseEvent.MOUSE_PRESSED, System.currentTimeMillis(),
			InputEvent.BUTTON1_DOWN_MASK, p1.x, p1.y, 1, false, MouseEvent.BUTTON1));
		postEvent(new MouseEvent(fp, MouseEvent.MOUSE_DRAGGED, System.currentTimeMillis(),
			InputEvent.BUTTON1_DOWN_MASK, p1.x, p1.y + 1000, 1, false, MouseEvent.BUTTON1));

		// let the drag keep happening in the Swing thread until we send the released event
		Thread.sleep(250);

		postEvent(new MouseEvent(fp, MouseEvent.MOUSE_RELEASED, System.currentTimeMillis(),
			InputEvent.BUTTON1_DOWN_MASK, p1.x, p1.y, 1, false, MouseEvent.BUTTON1));

		ViewerPosition vp2 = fp.getViewerPosition();
		assertTrue(!vp1.equals(vp2));

		ProgramSelection ps = getCurrentSelection();
		assertTrue(50 < ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());

	}

	@Test
	public void testSelectionConnectedBrowsers() throws Exception {
		PluginTool tool2 = env.launchAnotherDefaultTool();
		setUpCodeBrowserTool(tool2);
		ProgramManager pm = tool2.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		CodeBrowserPlugin cb2 = getPlugin(tool2, CodeBrowserPlugin.class);

		env.connectTools(tool, tool2);

		cb.goToField(addr("0x1003a50"), "Bytes", 0, 4);
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1003a5e"), "Mnemonic", 0, 0, 2, false);
		Point p2 = getCursorPoint();
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(15, ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());
		assertEquals(addr("0x1003a50"), ps.getMinAddress());

		ProgramSelection ps2 = cb2.getCurrentSelection();
		assertEquals(ps, ps2);

		// test click removes selection
		clickMouse(fp, 1, 0, 0, 1, 0);
		ps = getCurrentSelection();
		assertEquals(0, ps.getNumAddresses());
		ps2 = cb2.getCurrentSelection();
		assertEquals(0, ps2.getNumAddresses());

	}

	@Test
	public void testSelectionInStructure() {
		StructureDataType struct = new StructureDataType("fred", 7);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), struct);
		tool.execute(cmd, program);
		cb.goToField(addr("0x1007000"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();

		cb.goToField(addr("0x1007002"), "Address", 0, 0);
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1007004"), "Mnemonic", 0, 0, 2, false);
		Point p2 = getCursorPoint();
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(3, ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());
		assertEquals(addr("0x1007002"), ps.getMinAddress());
		InteriorSelection is = ps.getInteriorSelection();
		assertNotNull(is);

	}

	@Test
	public void testArrayDisplayIsFourPerLine() {
		ArrayDataType array = new ArrayDataType(new ByteDataType(), 20, 1);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), array);
		tool.execute(cmd, program);
		cb.goToField(addr("0x1007000"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();

		assertAddressInArray(addr("0x1007000"));
		assertAddressInArray(addr("0x1007004"));
		assertAddressInArray(addr("0x1007008"));
		assertAddressInArray(addr("0x100700c"));
		assertAddressInArray(addr("0x1007010"));

	}

	@Test
	public void testSelectionInArray() {
		ArrayDataType array = new ArrayDataType(new ByteDataType(), 20, 1);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), array);
		tool.execute(cmd, program);
		cb.goToField(addr("0x1007000"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();

		cb.goToField(addr("0x1007004"), "Address", 0, 0);
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1007008"), "Address", 0, 0, 2, false);
		Point p2 = getCursorPoint();
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(20, ps.getNumAddresses());

	}

	@Test
	public void testSelectionIntoStructure() {
		StructureDataType fred = new StructureDataType("fred", 7);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), fred);

		tool.execute(cmd, program);

		cb.goToField(addr("0x1007000"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();

		cb.goToField(addr("0x1006ffe"), "Address", 0, 0);
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1007002"), "Mnemonic", 0, 0, 2, false);
		Point p2 = getCursorPoint();
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(9, ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());
		assertEquals(addr("0x1006ffe"), ps.getMinAddress());

	}

	@Test
	public void testSelectionInMultiLevelStructure() {
		StructureDataType fred = new StructureDataType("fred", 7);
		StructureDataType bob = new StructureDataType("bob", 10);
		bob.replace(2, fred, 7);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x1007000"), bob);
		tool.execute(cmd, program);
		waitForBusyTool(tool);

		cb.goToField(addr("0x1007000"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();
		cb.updateNow();
		cb.goToField(addr("0x1007002"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();
		cb.updateNow();

		assertTrue(cb.goToField(addr("0x1007001"), "Address", 0, 0));
		Point p1 = getCursorPoint();
		assertNotNull(p1);
		assertTrue(cb.goToField(addr("0x1007005"), "Mnemonic", 0, 0, 2, false));
		Point p2 = getCursorPoint();
		assertNotNull(p2);
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(10, ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());
		assertEquals(addr("0x1007000"), ps.getMinAddress());

	}

	@Test
	public void testSelectAll() {
		DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);
		ProgramSelection ps = getCurrentSelection();
		AddressSet set1 = new AddressSet(program.getMemory());
		AddressSet set2 = new AddressSet(ps);
		assertEquals(set1, set2);
	}

	@Test
	public void testSelectComplementOnAllProgram() {
		DockingActionIf action = getAction(cb, "Select Complement");
		ProgramSelection allSelection = new ProgramSelection(program.getMemory());
		ProgramSelection noneSelection = new ProgramSelection();
		assertEquals(noneSelection, cb.getCurrentSelection());

		// Select All From None

		performAction(action, cb.getProvider(), true);
		assertEquals(allSelection, cb.getCurrentSelection());

		// Select None From All
		performAction(action, cb.getProvider(), true);
		assertEquals(noneSelection, cb.getCurrentSelection());
	}

	@Test
	public void testSelectComplementOnAllView() {
		DockingActionIf action = getAction(cb, "Select Complement");
		AddressSet viewSet = new AddressSet(addr("0x1001000"), addr("0x10012ff"));
		setView(viewSet);
		ProgramSelection allSelection = new ProgramSelection(viewSet);
		ProgramSelection noneSelection = new ProgramSelection();
		assertEquals(noneSelection, cb.getCurrentSelection());
		// Select All From None
		performAction(action, cb.getProvider(), true);
		assertEquals(allSelection, cb.getCurrentSelection());
		// Select None From All
		performAction(action, cb.getProvider(), true);
		assertEquals(noneSelection, cb.getCurrentSelection());
	}

	@Test
	public void testSelectComplementOnSomeOfProgram() {
		DockingActionIf action = getAction(cb, "Select Complement");
		AddressSetView programSet = program.getMemory();
		AddressSet initialSelectSet = new AddressSet();
		initialSelectSet.addRange(addr("0x10011e8"), addr("0x10011ef"));
		initialSelectSet.addRange(addr("0x1001208"), addr("0x100120b"));
		initialSelectSet.addRange(addr("0x100248f"), addr("0x10024a3"));
		initialSelectSet.addRange(addr("0x1002ed0"), addr("0x1002ef3"));
		ProgramSelection selection1 = new ProgramSelection(initialSelectSet);
		ProgramSelection selection2 = new ProgramSelection(programSet.subtract(initialSelectSet));
		setSelection(initialSelectSet);
		assertEquals(selection1, cb.getCurrentSelection());

		// Select All From None
		performAction(action, cb.getProvider(), true);
		assertEquals(selection2, cb.getCurrentSelection());
		// Select None From All
		performAction(action, cb.getProvider(), true);
		assertEquals(selection1, cb.getCurrentSelection());
	}

	@Test
	public void testSelectComplementOnSomeOfView() {
		DockingActionIf action = getAction(cb, "Select Complement");
		AddressSet viewSet = new AddressSet(addr("0x1001000"), addr("0x10012ff"));
		setView(viewSet);
		AddressSet initialSelectSet = new AddressSet();
		initialSelectSet.addRange(addr("0x10011e8"), addr("0x10011ef"));
		initialSelectSet.addRange(addr("0x1001208"), addr("0x100120b"));
		initialSelectSet.addRange(addr("0x100248f"), addr("0x10024a3"));
		initialSelectSet.addRange(addr("0x1002ed0"), addr("0x1002ef3"));
		AddressSet select1Set = new AddressSet();
		select1Set.addRange(addr("0x10011e8"), addr("0x10011ef"));
		select1Set.addRange(addr("0x1001208"), addr("0x100120b"));
		ProgramSelection selection1 = new ProgramSelection(select1Set);
		ProgramSelection selection2 = new ProgramSelection(viewSet.subtract(select1Set));
		setSelection(initialSelectSet);
		assertEquals(selection1, cb.getCurrentSelection());
		// Select All From None
		performAction(action, cb.getProvider(), true);
		assertEquals(selection2, cb.getCurrentSelection());
		// Select None From All
		performAction(action, cb.getProvider(), true);
		assertEquals(selection1, cb.getCurrentSelection());
	}

	@Test
	public void testSaveRestoreState() throws Exception {

		cb.goToField(addr("0x1007000"), "Address", 0, 0);
		ViewerPosition vp = runSwing(() -> fp.getViewerPosition());

		SaveState saveState = new SaveState();
		runSwing(() -> cb.writeDataState(saveState));
		tool = env.restartTool();
		setUpCodeBrowserTool(tool);

		env.showTool();
		runSwing(() -> {
			Dimension d = tool.getToolFrame().getSize();
			d.height += 400;
			tool.getToolFrame().setSize(d);
			tool.getToolFrame().validate();

		});

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		CodeBrowserPlugin cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		fp = cbPlugin.getFieldPanel();
		waitForSwing();
		runSwing(() -> cbPlugin.readDataState(saveState));

		cbPlugin.updateNow();
		assertEquals("01007000", runSwing(() -> cbPlugin.getCurrentFieldText()));

		assertEquals(vp, runSwing(() -> fp.getViewerPosition()));
	}

	private void assertAddressInArray(Address address) {
		assertAddressExistsInArray(address, address);
		assertAddressExistsInArray(address.add(1), address);
		assertAddressExistsInArray(address.add(2), address);
		assertAddressExistsInArray(address.add(3), address);
	}

	private void assertAddressExistsInArray(Address goToAddr, Address resultAddr) {
		cb.goToField(goToAddr, "Address", 0, 0);
		waitForSwing();
		assertEquals(resultAddr, cb.getCurrentLocation().getByteAddress());
	}

	private void setView(AddressSet addrSet) {
		runSwing(() -> cb.viewChanged(addrSet), true);
	}

	private void setSelection(final AddressSet addrSet) {
		runSwing(
			() -> tool.firePluginEvent(
				new ProgramSelectionPluginEvent("test", new ProgramSelection(addrSet), program)),
			true);
	}

	private ProgramSelection dragToMakeSelection() {
		cb.goToField(addr("0x1003a50"), "Bytes", 0, 4);
		cb.updateNow();
		Point p1 = getCursorPoint();
		cb.goToField(addr("0x1003a5f"), "Mnemonic", 0, 0, 2, false);
		cb.updateNow();
		Point p2 = getCursorPoint();
		dragMouse(fp, 1, p1.x, p1.y, p2.x, p2.y, 0);

		ProgramSelection ps = getCurrentSelection();
		assertEquals(16, ps.getNumAddresses());
		assertEquals(1, ps.getNumAddressRanges());
		assertEquals(addr("0x1003a50"), ps.getMinAddress());

		return ps;
	}

	private Point getCursorPoint() {
		return runSwing(() -> fp.getCursorPoint());
	}

	private ProgramSelection getCurrentSelection() {
		return runSwing(() -> cb.getCurrentSelection());
	}
}
