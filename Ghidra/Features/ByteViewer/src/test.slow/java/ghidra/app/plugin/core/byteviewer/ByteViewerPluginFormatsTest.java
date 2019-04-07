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
package ghidra.app.plugin.core.byteviewer;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.Date;
import java.util.Map;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.*;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Test for byte viewer formats. 
 */
public class ByteViewerPluginFormatsTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private Memory memory;
	private Listing listing;
	private ByteViewerPlugin plugin;
	private ByteViewerPanel panel;
	private ByteViewerComponentProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(ByteViewerPlugin.class.getName());

		plugin = env.getPlugin(ByteViewerPlugin.class);
		provider =
			(ByteViewerComponentProvider) TestUtils.getInstanceField("connectedProvider", plugin);
		tool.showComponentProvider(provider, true);

		program = buildNotepad();
		memory = program.getMemory();
		listing = program.getListing();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		panel = provider.getByteViewerPanel();
		waitForSwing();
	}

	private Program buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	private ProgramDB create16bitProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("16bit", ProgramBuilder._8051);
		builder.createMemory("test2", "0x1000", 0x1000);
		builder.setBytes("0x1100", "ff 20 10 50 30 00");
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testInsertionFieldHex() throws Exception {
		env.showTool();
		String insertionStr = findLabelStr(panel, "Insertion");

		// move the cursor to the right; the insertion field should not update
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			c.cursorRight();
		});
		assertEquals(insertionStr, findLabelStr(panel, "Insertion"));

		// move the cursor to the right; the insertion field should update by one
		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.cursorRight();
		});

//		SwingUpdateManager updateManager = (SwingUpdateManager) 
//			TestUtils.getInstanceField("updateManager", provider);
//		waitForSwingUpdateManager( updateManager );
		waitForSwing();
		assertEquals(getAddr(0x01001001).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the left; the insertion field should have 
		//   been decremented by one
		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.cursorLeft();
		});
		assertEquals(getAddr(0x01001000).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the left; the insertion field should not change
		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.cursorLeft();
		});
		assertEquals(insertionStr, findLabelStr(panel, "Insertion"));
	}

	@Test
	public void testInsertionFieldOctal() throws Exception {
		env.showTool();
		addViews();
		ByteViewerComponent c = findComponent(panel, "Octal");
		panel.setCurrentView(c);

		String insertionStr = findLabelStr(panel, "Insertion");

		// move the cursor to the right two times; the insertion field should not update
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			currentComponent.cursorRight();
			currentComponent.cursorRight();
		});
		assertEquals(insertionStr, findLabelStr(panel, "Insertion"));

		// move the cursor to the right; the insertion field should update by one
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.cursorRight();
		});
		assertEquals(getAddr(0x01001001).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the left; the insertion field should have 
		//   been decremented by one
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.cursorLeft();
		});
		assertEquals(getAddr(0x01001000).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the left two times; the insertion field should not change
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.cursorLeft();
			currentComponent.cursorLeft();
		});
		assertEquals(insertionStr, findLabelStr(panel, "Insertion"));
	}

	@Test
	public void testInsertionFieldAscii() throws Exception {
		env.showTool();
		addViews();
		ByteViewerComponent c = findComponent(panel, "Ascii");
		panel.setCurrentView(c);

		String insertionStr = findLabelStr(panel, "Insertion");

		// move the cursor to the right; the insertion field should update by one
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			currentComponent.cursorRight();
		});
		assertEquals(getAddr(0x01001001).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the right; the insertion field should update by one
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.cursorRight();
		});
		assertEquals(getAddr(0x01001002).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the left; the insertion field should have 
		//   been decremented by one
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.cursorLeft();
		});
		assertEquals(getAddr(0x01001001).toString(), findLabelStr(panel, "Insertion"));

		// move the cursor to the left; the insertion field should update
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.cursorLeft();
		});
		assertEquals(insertionStr, findLabelStr(panel, "Insertion"));
	}

	@Test
	public void testHexIntegerView() throws Exception {

		env.showTool();
		addViews();

		final ByteViewerComponent c = findComponent(panel, "HexInteger");
		panel.setCurrentView(c);
		assertEquals(4, c.getNumberOfFields());
		assertEquals(4, c.getDataModel().getUnitByteSize());

		final FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});
		// verify that the 4 bytes are represented as an 8 digit hex number
		assertEquals(8, c.getCurrentField().getNumCols(loc.getRow()));
	}

	@Test
	public void testOtherEditsHexInteger() throws Exception {
		// verify that the 4 byte string is rendered in red when a byte
		// is changed from another view, e.g. Ascii or Hex
		env.showTool();
		addViews();

		final ByteViewerComponent c = findComponent(panel, "Ascii");
		panel.setCurrentView(c);

		final ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		final FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new ActionContext());
			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();

		final ByteViewerComponent hexComp = findComponent(panel, "HexInteger");

		runSwing(() -> {
			ProgramByteBlockSet blockset =
				(ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(getAddr(0x01001000));
			FieldLocation l = hexComp.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
			hexComp.setCursorPosition(l.getIndex(), l.getFieldNum(), 0, 0);
		});

		assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR,
			((ByteField) hexComp.getCurrentField()).getForeground());
	}

	@Test
	public void testIntegerView() throws Exception {

		env.showTool();

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Integer", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();
		final ByteViewerComponent c = findComponent(panel, "Integer");
		panel.setCurrentView(c);

		runSwing(() -> {
			IndexedScrollPane sp =
				(IndexedScrollPane) findContainer(panel, IndexedScrollPane.class);
			JScrollBar scrollBar = sp.getHorizontalScrollBar();
			scrollBar.setValue(scrollBar.getMaximum());
		});
		waitForSwing();

		assertEquals(4, c.getNumberOfFields());
		assertEquals(4, c.getDataModel().getUnitByteSize());

		runSwing(() -> {

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			ProgramByteBlockSet blockset =
				(ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(getAddr(0x01001003));
			currentComponent.setViewerCursorLocation(bbInfo.getBlock(), bbInfo.getOffset(),
				bbInfo.getColumn());
		});
		waitForSwing();

		FieldLocation loc = getFieldLocation(getAddr(0x01001003));
		assertEquals(11, c.getCurrentField().getNumCols(loc.getRow()));

		// verify that no edits can be done in Integer format since it
		// does not support editing
		Color fg = ((ByteField) c.getCurrentField()).getForeground();
		if (fg != null) {
			assertEquals(ByteViewerComponentProvider.DEFAULT_CURRENT_CURSOR_COLOR, fg);
		}
	}

	@Test
	public void testOctalView() throws Exception {
		env.showTool();

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Octal", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();
		final ByteViewerComponent c = findComponent(panel, "Octal");
		panel.setCurrentView(c);

		runSwing(() -> {
			IndexedScrollPane sp =
				(IndexedScrollPane) findContainer(panel, IndexedScrollPane.class);
			JScrollBar scrollBar = sp.getHorizontalScrollBar();
			scrollBar.setValue(scrollBar.getMaximum());
		});
		waitForSwing();

		assertEquals(16, c.getNumberOfFields());
		assertEquals(1, c.getDataModel().getUnitByteSize());

		runSwing(() -> {

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			ProgramByteBlockSet blockset =
				(ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(getAddr(0x01001003));
			currentComponent.setViewerCursorLocation(bbInfo.getBlock(), bbInfo.getOffset(),
				bbInfo.getColumn());
		});
		waitForSwing();

		FieldLocation loc = getFieldLocation(getAddr(0x01001003));
		assertEquals(3, c.getCurrentField().getNumCols(loc.getRow()));

		// verify that no edits can be done in Integer format since it
		// does not support editing
		Color fg = ((ByteField) c.getCurrentField()).getForeground();
		if (fg != null) {
			assertEquals(ByteViewerComponentProvider.DEFAULT_CURRENT_CURSOR_COLOR, fg);
		}
	}

	@Test
	public void testOtherEditsInteger() throws Exception {
		// verify that changed bytes are rendered in red in the Integer view
		env.showTool();
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Ascii", true);
		setViewSelected(dialog, "Octal", true);
		setViewSelected(dialog, "HexInteger", true);
		setViewSelected(dialog, "Integer", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();

		final ByteViewerComponent c = findComponent(panel, "Ascii");
		panel.setCurrentView(c);

		final ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		final FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new ActionContext());

			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();

		final ByteViewerComponent intComp = findComponent(panel, "Integer");

		runSwing(() -> {
			ProgramByteBlockSet blockset =
				(ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
			ByteBlockInfo bbInfo = blockset.getByteBlockInfo(getAddr(0x01001000));
			FieldLocation l = intComp.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());
			intComp.setCursorPosition(l.getIndex(), l.getFieldNum(), 0, 0);
		});
		// color should indicate the edit
		assertEquals(ByteViewerComponentProvider.DEFAULT_EDIT_COLOR,
			((ByteField) intComp.getCurrentField()).getForeground());
	}

	@Test
	public void testEditUnsupportedInteger() throws Exception {
		env.showTool();

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Integer", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();

		final ByteViewerComponent c = findComponent(panel, "Integer");
		panel.setCurrentView(c);
		int v = program.getMemory().getInt(getAddr(0x01001000));
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			DockingActionIf action = getAction(plugin, "Enable/Disable Byteviewer Editing");

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.actionPerformed(new ActionContext());

			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();
		// verify that no changes were made
		assertEquals(v, program.getMemory().getInt(getAddr(0x01001000)));
	}

	@Test
	public void testAddressIdentification16Bit() throws Exception {
		ProgramDB pdb = null;
		try {
			final ProgramManager pm = tool.getService(ProgramManager.class);
			runSwing(() -> pm.closeProgram());
			waitForSwing();
			pdb = create16bitProgram();
			final ProgramDB p = pdb;
			runSwing(() -> pm.openProgram(p.getDomainFile()));
			memory = p.getMemory();
			env.showTool();
			waitForSwing();

			ByteViewerOptionsDialog dialog = launchByteViewerOptions();
			setViewSelected(dialog, "Address", true);
			pressButtonByText(dialog.getComponent(), "OK");
			waitForSwing();
			ByteViewerComponent c = findComponent(panel, "Address");
			panel.setCurrentView(c);

			// Address view should show "1" in a circle for all bytes that are
			// the
			// start of an address
			AddressIterator iter = memory.getAddresses(true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				FieldLocation loc = getFieldLocation(addr);
				ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
				Address a = getTestAddress(addr);
				if (a != null && memory.contains(a)) {
					assertEquals(AddressFormatModel.GOOD_ADDRESS, field.getText());
				}
				else {
					// Address view should show a '.' for all bytes whose formed address
					// does not fall within the range of memory for the program
					assertEquals(AddressFormatModel.BAD_ADDRESS, field.getText());
				}
			}
		}
		finally {
			if (pdb != null) {
				env.getGhidraProject().close(pdb);
			}
		}
	}

	@Test
	public void testAddressIdentification32Bit() throws Exception {

		env.showTool();

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Address", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();
		ByteViewerComponent c = findComponent(panel, "Address");
		panel.setCurrentView(c);

		// Address view should show "1" in a circle for all bytes that are the
		// start of an address and not part of an instruction
		AddressIterator iter = memory.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			FieldLocation loc = getFieldLocation(addr);
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Address a = getTestAddress(addr);
			if (a != null && memory.contains(a)) {
				assertEquals(AddressFormatModel.GOOD_ADDRESS, field.getText());
			}
			else {
				// Address view should show a '.' for all bytes whose formed address
				// does not fall within the range of memory for the program
				assertEquals(AddressFormatModel.BAD_ADDRESS, field.getText());
			}
		}
	}

	@Test
	public void testDisassembledRecognition() throws Exception {
		// verify that the undefined bytes are marked with a box 
		// ("\u2700" unicode for dingbat char);
		// defined data and instructions are marked with '.'
		env.showTool();

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Disassembled", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();

		ByteViewerComponent c = findComponent(panel, "Disassembled");
		panel.setCurrentView(c);

		AddressIterator iter = memory.getAddresses(true);
		int ditCount = 0;
		int blockCount = 0;
		// just test 20 of each case
		while (iter.hasNext() && ditCount < 20 && blockCount < 20) {
			Address addr = iter.next();
			FieldLocation loc = getFieldLocation(addr);
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());

			if ((listing.getInstructionContaining(addr) != null) ||
				(listing.getDefinedDataContaining(addr) != null)) {
				assertEquals(".", field.getText());
				ditCount++;
			}
			else {
				assertEquals(DisassembledFormatModel.BLOCK, field.getText());
				blockCount++;
			}
		}

	}

	@Test
	public void testDisassembledRecognition2() throws Exception {
		// verify that when data is created, the dingbat char changes to '.'

		env.showTool();

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Disassembled", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();

		ByteViewerComponent c = findComponent(panel, "Disassembled");
		panel.setCurrentView(c);

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, getAddr(01001530)));

		waitForSwing();

		int transactionID = program.startTransaction("test");
		Address addr = getAddr(0x01001530);
		for (int i = 0; i < 5; i++) {
			listing.createData(addr, new ByteDataType(), 1);
			addr = addr.add(1);
		}
		program.endTransaction(transactionID, true);

		program.flushEvents();
		waitForSwing();

		addr = getAddr(0x01001530);
		for (int i = 0; i < 5; i++) {
			FieldLocation loc = getFieldLocation(addr);
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			assertEquals(".", field.getText());
			addr = addr.add(1);
		}
	}

	@Test
	public void testDisassembledRecognition3() throws Exception {
		// verify that when data is created, the dingbat char changes to '.'

		env.showTool();

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Disassembled", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();

		ByteViewerComponent c = findComponent(panel, "Disassembled");
		panel.setCurrentView(c);

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, getAddr(01001530)));

		waitForSwing();

		int transactionID = program.startTransaction("test");
		Address addr = getAddr(0x01001530);
		StructureDataType dt = new StructureDataType("test", 0);
		for (int i = 0; i < 7; i++) {
			dt.add(new ByteDataType());
		}
		listing.createData(addr, dt, dt.getLength());
		program.endTransaction(transactionID, true);

		program.flushEvents();
		waitForSwing();

		addr = getAddr(0x01001530);
		for (int i = 0; i < dt.getLength(); i++) {
			FieldLocation loc = getFieldLocation(addr);
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			assertEquals(".", field.getText());
			addr = addr.add(1);
		}
	}

	@Test
	public void testCloseProgram() throws Exception {
		env.showTool();

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Address", true);
		setViewSelected(dialog, "Disassembled", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();
		ByteViewerComponent c = findComponent(panel, "Address");
		panel.setCurrentView(c);

		final ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram());

		waitForSwing();
		assertNull(panel.getCursorLocation());
		assertNull(c.getCurrentField());
		assertNull(c.getField(BigInteger.ZERO, 0));

		c = findComponent(panel, "Disassembled");
		panel.setCurrentView(c);
		assertNull(panel.getCursorLocation());
		assertNull(c.getCurrentField());
		assertNull(c.getField(BigInteger.ZERO, 0));

	}

	private Address getTestAddress(Address a) {

		int size = a.getAddressSpace().getSize();
		int nbytes = size / 8;
		try {
			long value = 0;
			switch (nbytes) {
				case 8:
					value = memory.getLong(a);
					break;
				case 4:
					value = memory.getInt(a);
					break;
				case 2:
					value = memory.getShort(a);
					break;
				case 1:
					value = memory.getByte(a);
					break;
				default:
					return null;
			}
			return a.getNewAddress(value);
		}
		catch (MemoryAccessException ex) {
			// Do nothing... Tried to form an address that was not readable or writable
		}
		catch (AddressOutOfBoundsException e) {
			// ignore??
		}
		catch (IllegalArgumentException e) {
			// ignore??
		}
		return null;
	}

	private Address getAddr(long offset) {
		return getAddr(program, offset);
	}

	private Address getAddr(Program p, long offset) {
		return p.getMinAddress().getNewAddress(offset);
	}

	private FieldLocation getFieldLocation(Address addr) {
		ByteViewerComponent c = panel.getCurrentComponent();
		ProgramByteBlockSet blockset = (ProgramByteBlockSet) plugin.getProvider().getByteBlockSet();
		ByteBlockInfo bbInfo = blockset.getByteBlockInfo(addr);
		return c.getFieldLocation(bbInfo.getBlock(), bbInfo.getOffset());

	}

	private String findLabelStr(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JLabel) {
				if (name.equals(((JLabel) element).getName())) {
					return ((JLabel) element).getText();
				}
			}
			if (element instanceof Container) {
				String str = findLabelStr((Container) element, name);
				if (str != null) {
					return str;
				}
			}
		}
		return null;
	}

	private ByteViewerComponent findComponent(Container container, String name) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof ByteViewerComponent) {
				if (((ByteViewerComponent) element).getDataModel().getName().equals(name)) {
					return (ByteViewerComponent) element;
				}
			}
			else if (element instanceof Container) {
				ByteViewerComponent bvc = findComponent((Container) element, name);
				if (bvc != null) {
					return bvc;
				}
			}
		}
		return null;
	}

	private Container findContainer(Container parent, Class<?> theClass) {
		Component[] c = parent.getComponents();
		for (Component element : c) {
			if (element.getClass() == theClass) {
				return (Container) element;
			}
			if (element instanceof Container) {
				Container container = findContainer((Container) element, theClass);
				if (container != null) {
					return container;
				}
			}
		}
		return null;
	}

	private void addViews() throws Exception {
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Ascii", true);
		setViewSelected(dialog, "Octal", true);
		setViewSelected(dialog, "HexInteger", true);
		pressButtonByText(dialog.getComponent(), "OK");
		waitForSwing();
	}

	private void setViewSelected(ByteViewerOptionsDialog dialog, String viewName,
			boolean selected) {
		Map<?, ?> checkboxMap = (Map<?, ?>) getInstanceField("checkboxMap", dialog);
		JCheckBox checkbox = (JCheckBox) checkboxMap.get(viewName);
		checkbox.setSelected(selected);
	}

	private ByteViewerOptionsDialog launchByteViewerOptions() {
		final DockingActionIf action = getAction(plugin, "Byte Viewer Options");
		assertTrue(action.isEnabled());

		runSwing(() -> action.actionPerformed(new ActionContext()), false);
		waitForSwing();
		ByteViewerOptionsDialog d = waitForDialogComponent(ByteViewerOptionsDialog.class);
		return d;
	}
}
