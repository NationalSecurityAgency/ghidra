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

import static java.awt.event.InputEvent.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.swing.JCheckBox;
import javax.swing.JLabel;

import org.junit.*;

import docking.DefaultActionContext;
import docking.DockingUtils;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.*;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bean.FixedBitSizeValueField;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalCallback;

/**
 * Test editing in the Byte Viewer.
 */
public class ByteViewerPlugin2Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private Memory memory;
	private Listing listing;
	private ByteViewerPlugin plugin;
	private ByteViewerPanel panel;
	private CodeBrowserPlugin cbPlugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		tool.addPlugin(ByteViewerPlugin.class.getName());

		plugin = env.getPlugin(ByteViewerPlugin.class);
		tool.showComponentProvider(plugin.getProvider(), true);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		program = buildNotepad();
		memory = program.getMemory();
		listing = program.getListing();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		panel = plugin.getProvider().getByteViewerPanel();
		waitForSwing();
	}

	private Program buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		builder.createMemory("test2", "0xf001000", 0x100);
		builder.createMemory("test2", "0xf002000", 0x100);
		builder.setBytes("0x1002000", "50");
		builder.disassemble("0x1002000", 1);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testEditModeHex() throws Exception {
		env.showTool();

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		assertEquals((byte) 0xa0, program.getMemory().getByte(getAddr(0x01001000)));
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR,
			((ByteField) c.getCurrentField()).getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testEditModeHex2() throws Exception {
		// verify that the byte being edited cannot be in an instruction

		env.showTool();

		Address addr = getAddr(0x01002000);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(addr);
		byte b = memory.getByte(addr);
		assertEquals((byte) 0x50, b);
		assertEquals(256, loc.getIndex().intValue());
		assertEquals(0, loc.getFieldNum());

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});

		program.flushEvents();
		waitForSwing();
		assertEquals(b, program.getMemory().getByte(addr));
		Color fg = ((ByteField) c.getCurrentField()).getForeground();
		if (fg != null) {
			assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR, fg);
		}
		Window w = windowForComponent(plugin.getProvider().getComponent());
		String str = findLabelStr(w, "Tool Status");
		assertEquals("Editing not allowed: Instruction exists at address 01002000", str);
	}

	@Test
	public void testEditModeHex3() throws Exception {
		env.showTool();

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, getAddr(01001530)));

		waitForSwing();

		Address addr = getAddr(0x01001530);
		txSwing(() -> {
			StructureDataType dt = new StructureDataType("test", 0);
			for (int i = 0; i < 7; i++) {
				dt.add(new ByteDataType());
			}
			listing.createData(addr, dt, dt.getLength());
		});

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		runSwing(() -> {
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		ByteViewerComponent c = panel.getCurrentComponent();

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		assertEquals((byte) 0xa0, program.getMemory().getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

	}

	@Test
	public void testEditsInOtherViews() throws Exception {
		// verify changed bytes show up in red in other views
		env.showTool();
		addViews();

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, getAddr(01001530)));
		waitForSwing();

		Address addr = getAddr(0x01001530);
		txSwing(() -> {
			StructureDataType dt = new StructureDataType("test", 0);
			for (int i = 0; i < 7; i++) {
				dt.add(new ByteDataType());
			}
			listing.createData(addr, dt, dt.getLength());
		});

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		runSwing(() -> {
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		ByteViewerComponent c = panel.getCurrentComponent();

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		assertEquals((byte) 0xa0, program.getMemory().getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

		ByteViewerComponent asciiC = findComponent(panel, "Ascii");
		runSwing(() -> panel.setCurrentView(asciiC));

		loc = getFieldLocation(addr);
		field = asciiC.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

		ByteViewerComponent hexIntC = findComponent(panel, "Hex Integer");
		runSwing(() -> panel.setCurrentView(hexIntC));

		loc = getFieldLocation(addr);
		field = asciiC.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());
	}

	@Test
	public void testUndoRedo() throws Exception {
		env.showTool();
		Address addr = getAddr(0x01001000);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		ByteViewerComponent c = panel.getCurrentComponent();
		byte value = program.getMemory().getByte(addr);
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		assertEquals((byte) 0xa0, memory.getByte(addr));

		undo(program);
		program.flushEvents();
		waitForSwing();

		assertEquals(value, memory.getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		Color fg = field.getForeground();
		assertTrue(fg == null ||
			ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());

		redo(program);
		program.flushEvents();

		// field color should show edit color
		loc = getFieldLocation(addr);
		field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

	}

	@Test
	public void testUndoRedo2() throws Exception {

		disableCodeBrowserLocationEvents();

		env.showTool();

		// make 5 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");

		runSwing(() -> {
			Address addr = getAddr(0x01001000);
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		ByteViewerComponent c = panel.getCurrentComponent();

		runSwing(() -> {
			char[] values = { 'a', '1', '2', 'b', '3' };
			int[] keyCodes =
				{ KeyEvent.VK_P, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3 };

			Address addr = getAddr(0x01001000);
			for (int i = 0; i < 5; i++) {
				FieldLocation loc = getFieldLocation(addr);
				KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, keyCodes[i], values[i]);
				c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
					c.getCurrentField());
				addr = addr.add(1);
			}

		});
		program.flushEvents();
		waitForSwing();

		FieldLocation loc1 = new FieldLocation(0, 0, 0, 0); // first byte on first line
		FieldLocation loc2 = new FieldLocation(0, 1, 0, 0); // second byte on first line

		undo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);

		undo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);

		undo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, null);

		undo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, null);

		undo(program);
		testFieldColor(loc1, null);
		testFieldColor(loc2, null);
		assertFalse(program.canUndo());

		redo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, null);

		redo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, null);

		redo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);

		redo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);

		redo(program);
		testFieldColor(loc1, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		testFieldColor(loc2, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexShort() throws Exception {
		env.showTool();
		addViews();

		Address addr = getAddr(0x01001003);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		ByteViewerComponent c = findComponent(panel, "Hex Short");
		panel.setCurrentView(c);

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol());
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		byte value = program.getMemory().getByte(addr);
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0xa0, memory.getByte(addr));

		undo(program);

		assertEquals(value, memory.getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		Color fg = field.getForeground();
		assertTrue(fg == null ||
			ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());

		redo(program);

		// field color should show edit color
		loc = getFieldLocation(addr);
		field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

	}

	@Test
	public void testUndoRedoHexInteger() throws Exception {
		env.showTool();
		addViews();

		Address addr = getAddr(0x01001003);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		ByteViewerComponent c = findComponent(panel, "Hex Integer");
		panel.setCurrentView(c);

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol());
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		byte value = program.getMemory().getByte(addr);
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0xa0, memory.getByte(addr));

		undo(program);

		assertEquals(value, memory.getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		Color fg = field.getForeground();
		assertTrue(fg == null ||
			ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());

		redo(program);

		// field color should show edit color
		loc = getFieldLocation(addr);
		field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

	}

	@Test
	public void testUndoRedoHexLong() throws Exception {
		env.showTool();
		addViews();

		Address addr = getAddr(0x01001003);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		ByteViewerComponent c = findComponent(panel, "Hex Long");
		panel.setCurrentView(c);

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol());
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		byte value = program.getMemory().getByte(addr);
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0xa0, memory.getByte(addr));

		undo(program);

		assertEquals(value, memory.getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		Color fg = field.getForeground();
		assertTrue(fg == null ||
			ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());

		redo(program);

		// field color should show edit color
		loc = getFieldLocation(addr);
		field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

	}

	@Test
	public void testUndoRedoHexLongLong() throws Exception {
		env.showTool();
		addViews();

		Address addr = getAddr(0x01001003);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		ByteViewerComponent c = findComponent(panel, "Hex Long Long");
		panel.setCurrentView(c);

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol());
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		byte value = program.getMemory().getByte(addr);
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev =
				new KeyEvent(currentComponent, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
				loc.getCol(), currentComponent.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0xa0, memory.getByte(addr));

		undo(program);

		assertEquals(value, memory.getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		Color fg = field.getForeground();
		assertTrue(fg == null ||
			ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());

		redo(program);

		// field color should show edit color
		loc = getFieldLocation(addr);
		field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

	}

	@Test
	public void testUndoRedoHexShort2() throws Exception {
		disableCodeBrowserLocationEvents();

		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Short");
		panel.setCurrentView(c);
		// make 3 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");

		runSwing(() -> {
			Address addr = getAddr(0x01001003);
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		runSwing(() -> {
			char[] values = { 'a', '1', '2' };
			int[] keyCodes =
				{ KeyEvent.VK_P, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3 };

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			for (int i = 0; i < 3; i++) {
				FieldLocation loc = currentComponent.getCursorLocation();
				KeyEvent ev = new KeyEvent(currentComponent, 0, new Date().getTime(), 0,
					keyCodes[i], values[i]);
				currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
					loc.getCol(), currentComponent.getCurrentField());
			}

		});
		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < 3; i++) {
			assertTrue(program.canUndo());

			undo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			if (i == 2) {
				assertTrue(fg == null ||
					ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());
			}
			else {
				assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
			}
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < 3; i++) {

			redo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexInteger2() throws Exception {
		disableCodeBrowserLocationEvents();

		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Integer");
		panel.setCurrentView(c);
		// make 5 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");

		runSwing(() -> {
			Address addr = getAddr(0x01001003);
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		runSwing(() -> {
			char[] values = { 'a', '1', '2', 'b', '3' };
			int[] keyCodes =
				{ KeyEvent.VK_P, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3 };

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			for (int i = 0; i < 5; i++) {
				FieldLocation loc = currentComponent.getCursorLocation();
				KeyEvent ev = new KeyEvent(currentComponent, 0, new Date().getTime(), 0,
					keyCodes[i], values[i]);
				currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
					loc.getCol(), currentComponent.getCurrentField());
			}

		});
		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < 5; i++) {
			assertTrue(program.canUndo());

			undo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			if (i == 4) {
				assertTrue(fg == null ||
					ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());
			}
			else {
				assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
			}
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < 5; i++) {

			redo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexLong2() throws Exception {
		disableCodeBrowserLocationEvents();

		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Long");
		panel.setCurrentView(c);
		// make 9 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");

		runSwing(() -> {
			Address addr = getAddr(0x01001003);
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		runSwing(() -> {
			char[] values = { 'a', '1', '2', 'b', '3', 'c', '4', 'd', '5' };
			int[] keyCodes =
				{ KeyEvent.VK_P, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3,
					KeyEvent.VK_C, KeyEvent.VK_4, KeyEvent.VK_D, KeyEvent.VK_5 };

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			for (int i = 0; i < 9; i++) {
				FieldLocation loc = currentComponent.getCursorLocation();
				KeyEvent ev = new KeyEvent(currentComponent, 0, new Date().getTime(), 0,
					keyCodes[i], values[i]);
				currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
					loc.getCol(), currentComponent.getCurrentField());
			}

		});
		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < 9; i++) {
			assertTrue(program.canUndo());

			undo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			if (i == 8) {
				assertTrue(fg == null ||
					ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());
			}
			else {
				assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
			}
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < 9; i++) {

			redo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexLongLong2() throws Exception {
		disableCodeBrowserLocationEvents();

		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Long Long");
		panel.setCurrentView(c);
		// make 9 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");

		runSwing(() -> {
			Address addr = getAddr(0x01001003);
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		runSwing(() -> {
			char[] values = { 'a', '1', '2', 'b', '3', 'c', '4', 'd', '5', 'e', '6', 'f', '7', 'a',
				'8', 'b', '9' };
			int[] keyCodes =
				{ KeyEvent.VK_P, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3,
					KeyEvent.VK_C, KeyEvent.VK_4, KeyEvent.VK_D, KeyEvent.VK_5, KeyEvent.VK_E,
					KeyEvent.VK_6,
					KeyEvent.VK_F, KeyEvent.VK_7, KeyEvent.VK_G, KeyEvent.VK_8, KeyEvent.VK_H,
					KeyEvent.VK_9 };

			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			for (int i = 0; i < 17; i++) {
				FieldLocation loc = currentComponent.getCursorLocation();
				KeyEvent ev = new KeyEvent(currentComponent, 0, new Date().getTime(), 0,
					keyCodes[i], values[i]);
				currentComponent.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(),
					loc.getCol(), currentComponent.getCurrentField());
			}

		});
		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < 17; i++) {
			assertTrue(program.canUndo());

			undo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			if (i == 16) {
				assertTrue(fg == null ||
					ByteViewerComponentProvider.CURSOR_NON_ACTIVE_COLOR == field.getForeground());
			}
			else {
				assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
			}
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < 17; i++) {

			redo(program);

			FieldLocation loc = c.getCursorLocation();
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			Color fg = field.getForeground();
			assertEquals(fg, ByteViewerComponentProvider.CHANGED_VALUE_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testEditInputHex() throws Exception {
		env.showTool();
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());
		byte value = program.getMemory().getByte(getAddr(0x01001000));
		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_P, 'p');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		assertEquals(value, program.getMemory().getByte(getAddr(0x01001000)));
	}

	@Test
	public void testEditModeAscii() throws Exception {
		env.showTool();
		addViews();
		waitForSwing();
		ByteViewerComponent c = findComponent(panel, "Ascii");
		panel.setCurrentView(c);

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		waitForSwing();
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_Z, 'z');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		Address addr = getAddr(0x01001000);
		assertEquals((byte) 0x7a, program.getMemory().getByte(addr));
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testEditModeOctal() throws Exception {
		env.showTool();
		addViews();
		waitForSwing();
		ByteViewerComponent c = findComponent(panel, "Octal");
		panel.setCurrentView(c);
		Address addr = getAddr(0x01001000);
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			FieldLocation loc = getFieldLocation(addr);
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();

		assertEquals((byte) 0x40, program.getMemory().getByte(addr));
		FieldLocation loc = getFieldLocation(addr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testEditInputOctal() throws Exception {
		env.showTool();
		addViews();
		waitForSwing();
		ByteViewerComponent c = findComponent(panel, "Octal");
		panel.setCurrentView(c);

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		byte value = program.getMemory().getByte(getAddr(0x01001000));
		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_9, '9');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		assertEquals(value, program.getMemory().getByte(getAddr(0x01001000)));
	}

	@Test
	public void testEditModeHexShort() throws Exception {
		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Short");
		panel.setCurrentView(c);

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001003));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0x10, program.getMemory().getByte(getAddr(0x01001003)));
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR,
			((ByteField) c.getCurrentField()).getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testEditModeHexInteger() throws Exception {
		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Integer");
		panel.setCurrentView(c);

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001003));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0x10, program.getMemory().getByte(getAddr(0x01001003)));
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR,
			((ByteField) c.getCurrentField()).getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testEditModeHexLong() throws Exception {
		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Long");
		panel.setCurrentView(c);

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001003));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0x10, program.getMemory().getByte(getAddr(0x01001003)));
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR,
			((ByteField) c.getCurrentField()).getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testEditModeHexLongLong() throws Exception {
		env.showTool();
		addViews();

		ByteViewerComponent c = findComponent(panel, "Hex Long Long");
		panel.setCurrentView(c);

		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		FieldLocation loc = getFieldLocation(getAddr(0x01001003));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});
		assertTrue(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, c.getFocusedCursorColor());

		runSwing(() -> {
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		assertEquals((byte) 0x10, program.getMemory().getByte(getAddr(0x01001003)));
		assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR,
			((ByteField) c.getCurrentField()).getForeground());

		runSwing(() -> {
			action.setSelected(false);
			action.actionPerformed(new DefaultActionContext());
		});
		assertFalse(action.isSelected());
		assertEquals(ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR,
			c.getFocusedCursorColor());
	}

	@Test
	public void testMemoryMapEdits() throws Exception {
		env.showTool();

		// put the byte viewer in edit mode
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		runSwing(() -> {
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		// add a memory block		
		txSwing(() -> {
			Address addr = getAddr(0x100);
			memory.createInitializedBlock(".test", addr, 10, (byte) 0, null, false);
		});

		// edit the first 3 bytes in the block
		ByteViewerComponent c = panel.getCurrentComponent();
		runSwing(() -> {
			Address testAddress = getAddr(0x100);
			FieldLocation loc = getFieldLocation(testAddress);
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());

			testAddress = testAddress.add(1);
			loc = getFieldLocation(testAddress);
			ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_2, '2');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());

			testAddress = testAddress.add(1);
			loc = getFieldLocation(testAddress);
			ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_3, '3');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		Address addr = getAddr(0x100);
		for (int i = 0; i < 3; i++) {
			// verify that the bytes are rendered in red
			FieldLocation loc = getFieldLocation(addr);
			ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
			assertEquals(ByteViewerComponentProvider.CHANGED_VALUE_COLOR, field.getForeground());
			addr = addr.add(i);
		}
	}

	@Test
	public void testMemoryMapMove() throws Exception {
		// Move a memory block; verify that the byte viewer updates

		env.showTool();

		// put the byte viewer in edit mode
		ToggleDockingAction action =
			(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
		runSwing(() -> {
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		// first add a memory block
		txSwing(() -> {
			Address addr = getAddr(0x100);
			memory.createInitializedBlock(".test", addr, 10, (byte) 0, null, false);
		});

		// edit the first 3 bytes in the block
		ByteViewerComponent c = panel.getCurrentComponent();
		runSwing(() -> {
			Address testAddress = getAddr(0x100);
			FieldLocation loc = getFieldLocation(testAddress);
			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_1, '1');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());

			testAddress = testAddress.add(1);
			loc = getFieldLocation(testAddress);
			ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_2, '2');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());

			testAddress = testAddress.add(1);
			loc = getFieldLocation(testAddress);
			ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_3, '3');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();

		// move the block
		txSwing(() -> {
			Address addr = getAddr(0x100);
			MemoryBlock block = memory.getBlock(addr);
			Address newStart = getAddr(0x500);
			memory.moveBlock(block, newStart, TaskMonitor.DUMMY);
		});

		Address addr = getAddr(0x500);
		FieldLocation loc = getFieldLocation(addr);

		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertNotNull(field);
	}

	@Test
	public void testMemoryBlockSplit() throws Exception {
		// split a memory block; verify that the byte viewer shows
		// the separator between blocks after the block is split
		env.showTool();
		Address addr = getAddr(0x01002000);

		MemoryBlock block = memory.getBlock(addr);
		Address newaddr = getAddr(0x01002009);

		txSwing(() -> {
			memory.split(block, newaddr);
		});

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = getFieldLocation(newaddr);
		for (int i = 0; i < c.getNumberOfFields(); i++) {
			ByteField field = c.getField(loc.getIndex().subtract(BigInteger.ONE), i);
			assertEquals("..", field.getText());
		}
	}

	@Test
	public void testMemoryBlockExpandUp() throws Exception {
		// expand up: create a block, then join to its successor

		disableCodeBrowserLocationEvents();

		env.showTool();
		Address addr = getAddr(0x01001000);
		MemoryBlock block = memory.getBlock(addr);
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, addr));

		Address newaddr = getAddr(0x01000500);

		txSwing(() -> {
			MemoryBlock newblock =
				memory.createInitializedBlock(".test", newaddr, 0xb00, (byte) 0, null, false);
			memory.join(newblock, block);
		});

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = getFieldLocation(newaddr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertNotNull(field);

		// cursor should remain where it was before the block expansion
		loc = c.getCursorLocation();
		assertEquals(getFieldLocation(addr), loc);

		// there should be no separator above the current location
		field = c.getField(loc.getIndex().subtract(BigInteger.ONE), 0);
		assertFalse(field.getText().equals(".."));
	}

	@Test
	public void testMemoryBlockExpandDown() throws Exception {
		disableCodeBrowserLocationEvents();

		// expand block down: create a block, then join to its predecessor
		env.showTool();
		Address addr = getAddr(0x01001000);
		MemoryBlock block = memory.getBlock(addr);
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, addr));

		Address newaddr = getAddr(0x01003000L);

		txSwing(() -> {
			MemoryBlock newblock =
				memory.createInitializedBlock(".test", newaddr, 0x100, (byte) 0, null, false);
			memory.join(block, newblock);
		});

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = getFieldLocation(newaddr);
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertNotNull(field);
		loc = c.getCursorLocation();
		// cursor should remain where it was before the block expansion
		assertEquals(getFieldLocation(addr), loc);
	}

	@Test
	public void testMemoryBlockDeletedInView() throws Exception {
		// delete a memory block that is showing in the view
		disableCodeBrowserLocationEvents();
		env.showTool();
		Address addr = getAddr(0x0f001000);
		MemoryBlock block = memory.getBlock(addr);
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, addr));
		waitForSwing();

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = c.getCursorLocation();
		assertEquals(getFieldLocation(addr), loc);

		txSwing(() -> {
			memory.removeBlock(block, TaskMonitor.DUMMY);
		});

		addr = getAddr(0x0f002000);
		loc = getFieldLocation(addr);
		// cursor should be positioned at next address after deleted block
		assertEquals(loc, c.getCursorLocation());
	}

	@Test
	public void testMemoryBlockDeletedNotInView() throws Exception {
		// delete a memory block that is not showing in the view

		disableCodeBrowserLocationEvents();

		env.showTool();
		Address addr = getAddr(0x0f001000);
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, addr));
		waitForSwing();

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = c.getCursorLocation();
		assertEquals(getFieldLocation(addr), loc);

		MemoryBlock block = memory.getBlock(getAddr(0x01001000));
		txSwing(() -> {
			memory.removeBlock(block, TaskMonitor.DUMMY);
		});

		loc = getFieldLocation(addr);
		// cursor position should not be affected
		assertEquals(loc, c.getCursorLocation());
	}

	@Test
	public void testCursorLocationNewBlock() throws Exception {
		// set bytes per line to 10
		// add block that starts at address 0x30, length of 0x12
		// add a second block that  starts at address 0x48, length of 0x100
		// position the cursor on the first byte on the line for address 0x48
		// verify that the insertion label shows 0x48

		env.showTool();

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		FixedBitSizeValueField field =
			(FixedBitSizeValueField) getInstanceField("bytesPerLineField", d);
		runSwing(() -> field.setValue(BigInteger.valueOf(10)));
		pressButtonByText(d.getComponent(), "OK");

		// add the block
		txSwing(() -> {
			Address addr = getAddr(0x30);
			memory.createInitializedBlock(".test", addr, 0x12, (byte) 0, null, false);

			// add the second block at 0x48
			Address addr2 = getAddr(0x48);
			memory.createInitializedBlock(".test2", addr2, 0x100, (byte) 0, null, false);
		});

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			Address a = getAddr(0x48);
			FieldLocation loc = getFieldLocation(a);
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});

		Address addr = getAddr(0x48);
		FieldLocation loc = getFieldLocation(addr);
		ByteViewerComponent c = panel.getCurrentComponent();
		// cursor position should not be affected
		assertEquals(loc, c.getCursorLocation());
		assertEquals("00000048", findLabelStr(plugin.getProvider().getComponent(), "Insertion"));
	}

	@Test
	public void testMemoryChange() throws Exception {

		env.showTool();
		runSwing(() -> tool.showComponentProvider(plugin.getProvider(), false));
		ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram(), false);
		waitForSwing();

		pm.openProgram(program.getDomainFile());

		// add a memory block
		txSwing(() -> {
			memory.createInitializedBlock(".test", getAddr(0), 500, (byte) 0, TaskMonitor.DUMMY,
				false);
		});

		runSwing(() -> {
			GoToService goToService = tool.getService(GoToService.class);
			goToService.goTo(new ProgramLocation(program, getAddr(0)));
		});
		runSwing(() -> tool.showComponentProvider(plugin.getProvider(), true));
		waitForSwing();

		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(getFieldLocation(getAddr(0)), c.getCursorLocation());

		runSwing(() -> tool.showComponentProvider(plugin.getProvider(), false));
		waitForSwing();

		// now remove the block
		txSwing(() -> {
			MemoryBlock block = memory.getBlock(getAddr(0));
			memory.removeBlock(block, TaskMonitor.DUMMY);
		});

		runSwing(() -> tool.showComponentProvider(plugin.getProvider(), true));
		waitForSwing();

		c = panel.getCurrentComponent();
		Address addr = cbPlugin.getCurrentAddress();
		assertEquals(getFieldLocation(addr), c.getCursorLocation());
	}

	@Test
	public void testSelectionAcrossBlocks() throws Exception {
		env.showTool();
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Ascii", true);
		setViewSelected(dialog, "Octal", true);
		pressButtonByText(dialog.getComponent(), "OK");

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		FixedBitSizeValueField field =
			(FixedBitSizeValueField) getInstanceField("bytesPerLineField", d);
		runSwing(() -> field.setValue(BigInteger.valueOf(10)));
		pressButtonByText(d.getComponent(), "OK");

		// add the block		
		txSwing(() -> {
			Address addr = getAddr(0x30);
			memory.createInitializedBlock(".test", addr, 0x12, (byte) 0, null, false);

			// add the second block at 0x48
			Address addr2 = getAddr(0x48);
			memory.createInitializedBlock(".test2", addr2, 0x100, (byte) 0, null, false);
		});

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			Address a = getAddr(0x30);
			FieldLocation loc = getFieldLocation(a);
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});
		FieldSelection fsel = new FieldSelection();
		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc1 = c.getCursorLocation();
		FieldLocation loc2 = getFieldLocation(getAddr(0x000000cb));
		fsel.addRange(new FieldLocation(loc1.getIndex(), loc1.getFieldNum(), 0, 0),
			new FieldLocation(loc2.getIndex(), loc2.getFieldNum(), 0, 0));

		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.selectionChanged(fsel, EventTrigger.GUI_ACTION);
		});
		c = panel.getCurrentComponent();
		ByteBlockSelection sel = c.getViewerSelection();
		ByteViewerComponent octalC = findComponent(panel, "Octal");
		assertTrue(byteBlockSelectionEquals(sel, octalC.getViewerSelection()));

		ByteViewerComponent asciiC = findComponent(panel, "Ascii");
		assertTrue(byteBlockSelectionEquals(sel, asciiC.getViewerSelection()));

	}

	@Test
	public void testEditLastByteInBlock() throws Exception {

		env.showTool();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		}, false);

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		FixedBitSizeValueField field =
			(FixedBitSizeValueField) getInstanceField("bytesPerLineField", d);
		runSwing(() -> field.setValue(BigInteger.valueOf(10)));
		pressButtonByText(d.getComponent(), "OK");
		runSwing(() -> {
			ToggleDockingAction action =
				(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());
		});

		// add the block
		txSwing(() -> {
			Address addr = getAddr(0x30);
			memory.createInitializedBlock(".test", addr, 0x12, (byte) 0, null, false);

			// add the second block at 0x48
			Address addr2 = getAddr(0x48);
			memory.createInitializedBlock(".test2", addr2, 0x100, (byte) 0, null, false);
		});

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			Address a = getAddr(0x41);
			FieldLocation loc = getFieldLocation(a);
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());

			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_3, '3');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		assertEquals((byte) 0x30, memory.getByte(getAddr(0x41)));
	}

	@Test
	public void testEditOptionCurrentViewColor() throws Exception {
		env.showTool();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Current View Cursor Color
		putColor(opt, ByteViewerComponentProvider.CURSOR_ACTIVE_COLOR_OPTION_NAME, Palette.GREEN);

		ByteViewerComponent c = panel.getCurrentComponent();
		assertColorsEqual(Palette.GREEN, c.getFocusedCursorColor());
	}

	@Test
	public void testEditOptionCursorColor() throws Exception {

		env.showTool();
		addViews();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Current View Cursor Color
		putColor(opt, ByteViewerComponentProvider.CURSOR_NOT_FOCUSED_COLOR_OPTION_NAME,
			Palette.GREEN);

		ByteViewerComponent c = findComponent(panel, "Octal");
		assertColorsEqual(Palette.GREEN, c.getNonFocusCursorColor());
	}

	@Test
	public void testEditOptionNonHighlightCursorColor() throws Exception {
		env.showTool();
		addViews();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Current View Cursor Color
		putColor(opt, ByteViewerComponentProvider.CURSOR_NOT_FOCUSED_COLOR_OPTION_NAME,
			Palette.CYAN);

		ByteViewerComponent c = findComponent(panel, "Octal");
		assertColorsEqual(Palette.CYAN, c.getNonFocusCursorColor());
	}

	@Test
	public void testEditOptionEditColor() throws Exception {
		// color for changed bytes
		env.showTool();
		addViews();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Edit Color
		putColor(opt, ByteViewerComponentProvider.CHANGED_VALUE_COLOR_OPTION_NAME, Palette.GREEN);

		FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		runSwing(() -> {
			ToggleDockingAction action =
				(ToggleDockingAction) getAction(plugin, "Enable/Disable Byteviewer Editing");
			action.setSelected(true);
			action.actionPerformed(new DefaultActionContext());

			ByteViewerComponent c = panel.getCurrentComponent();

			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);

			KeyEvent ev = new KeyEvent(c, 0, new Date().getTime(), 0, KeyEvent.VK_A, 'a');
			c.keyPressed(ev, loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol(),
				c.getCurrentField());
		});
		program.flushEvents();
		waitForSwing();

		ByteViewerComponent c = panel.getCurrentComponent();
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertColorsEqual(Palette.GREEN, field.getForeground());
	}

	@Test
	public void testEditOptionFont() throws Exception {
		env.showTool();
		addViews();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		Options opt = tool.getOptions("ByteViewer");
		// change the Font
		Font font = new Font("Times New Roman", Font.BOLD, 12);
		putFont(opt, ByteViewerComponentProvider.OPTION_FONT, font);

		FieldLocation loc = getFieldLocation(getAddr(0x01001000));
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		assertEquals(font, field.getFontMetrics().getFont());
	}

	@Test
	public void testEditOptionSeparatorColor() throws Exception {
		env.showTool();
		addViews();

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			FieldLocation loc = getFieldLocation(getAddr(0x01001000));
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		Options opt = tool.getOptions("ByteViewer");
		// change the color for block separator
		putColor(opt, ByteViewerComponentProvider.SEPARATOR_COLOR_OPTION_NAME, Palette.GREEN);

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = getFieldLocation(getAddr(0x0f001000));
		ByteField field = c.getField(loc.getIndex().subtract(BigInteger.ONE), 0);
		assertColorsEqual(Palette.GREEN, field.getForeground());
	}

	@Test
	public void testGoToUpdatesByteViewer() throws Exception {
		env.showTool();
		runSwing(() -> {
			GoToService goToService = tool.getService(GoToService.class);
			goToService.goTo(new ProgramLocation(program, getAddr(0x01001050)));
		});
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(getFieldLocation(getAddr(0x01001050)), c.getCursorLocation());
	}

	@Test
	public void testGoToUpdatesFromViewer() throws Exception {
		env.showTool();

		Address address = getAddr(0x01002000);
		setByteViewerLocation(plugin.getProvider(), address);

		ProgramLocation cbLocation = cbPlugin.getCurrentLocation();
		assertEquals(address, cbLocation.getAddress());
	}

	@Test
	public void testGoToFromSnapshot() throws Exception {
		env.showTool();

		DockingActionIf snapshotAction = getAction(plugin, "ByteViewer Clone");
		performAction(snapshotAction, true);

		Address address = getAddr(0x01002000);
		ProgramByteViewerComponentProvider snapshot = getSnapshotProvider();
		setByteViewerLocation(snapshot, address);

		int modifiers = 0;
		clickLocation(snapshot, modifiers);

		ProgramLocation cbLocation = cbPlugin.getCurrentLocation();
		Assert.assertNotEquals("Snapshot triggered navigation unexpectedly", address,
			cbLocation.getAddress());

		modifiers = DockingUtils.CONTROL_KEY_MODIFIER_MASK | SHIFT_DOWN_MASK;
		clickLocation(snapshot, modifiers);

		cbLocation = cbPlugin.getCurrentLocation();
		assertEquals("Snapshot did not trigger navigation with special modifiers", address,
			cbLocation.getAddress());
	}

	@Test
	public void testHighlightByte() throws Exception {
		env.showTool();
		ByteViewerComponent component = panel.getCurrentComponent();

		ByteViewerHighlighter highlightProvider =
			(ByteViewerHighlighter) getInstanceField("highlightProvider", component);
		String currentHighlightText = highlightProvider.getText();
		assertNull(currentHighlightText);

		Address address = getAddr(0x01002000);
		setByteViewerLocation(plugin.getProvider(), address);

		int modifiers = 0;
		ProgramByteViewerComponentProvider provider = plugin.getProvider();
		clickLocation(provider, modifiers);
		clickMiddleMouseLocation(provider, modifiers);

		currentHighlightText = highlightProvider.getText();
		assertEquals("50", currentHighlightText);

		clickMiddleMouseLocation(provider, modifiers);
		currentHighlightText = highlightProvider.getText();
		assertEquals(null, currentHighlightText);
	}

	@Test
	public void testSaveRestoreState() throws Exception {
		env.showTool();
		addViews();
		ByteViewerComponent c = panel.getCurrentComponent();

		FieldLocation loc = getFieldLocation(getAddr(0x0100100b));
		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.setCursorPosition(loc.getIndex(), loc.getFieldNum(), 0, 0);
		});

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		FixedBitSizeValueField field =
			(FixedBitSizeValueField) getInstanceField("groupSizeField", dialog);
		runSwing(() -> field.setValue(BigInteger.valueOf(4)));
		pressButtonByText(dialog.getComponent(), "OK");

		// change the font
		Options opt = tool.getOptions("ByteViewer");
		Font font = new Font("Times New Roman", Font.BOLD, 12);

		runSwing(() -> {

			opt.setFont(ByteViewerComponentProvider.OPTION_FONT, font);
			GoToService goToService = tool.getService(GoToService.class);
			goToService.goTo(new ProgramLocation(program, getAddr(0x01002500)));
		});
		assertEquals(4, plugin.getProvider().getGroupSize());

		ViewerPosition vp = panel.getViewerPosition();
		runSwing(() -> env.saveRestoreToolState());

		waitForSwing();
		c = panel.getCurrentComponent();
		assertEquals(4, plugin.getProvider().getGroupSize());

		assertEquals(getFieldLocation(getAddr(0x01002500)), c.getCursorLocation());
		assertEquals(font, panel.getFontMetrics().getFont());
		waitForSwing();

		assertEquals(vp, panel.getViewerPosition());
	}

	// Remove code browser plugin so the cursor position does not get changed because of location 
	// events that the code browser generates.
	private void disableCodeBrowserLocationEvents() throws Exception {
		runSwing(() -> tool.removePlugins(List.of(cbPlugin)));
	}

	private void testFieldColor(FieldLocation loc, Color color) {
		ByteViewerComponent c = panel.getCurrentComponent();
		ByteField field = c.getField(loc.getIndex(), loc.getFieldNum());
		Color fieldColor = field.getForeground();
		assertEquals(fieldColor, color);
	}

	// perform the given callback in a transaction on the Swing thread
	private <E extends Exception> void txSwing(ExceptionalCallback<E> c) {

		int txId = program.startTransaction("Test - Function in Transaction");
		boolean commit = true;
		try {
			runSwingWithException(c);
			program.flushEvents();
		}
		catch (Exception e) {
			commit = false;
			failWithException("Exception modifying program '" + program.getName() + "'", e);
		}
		finally {
			program.endTransaction(txId, commit);
		}

		waitForSwing();
	}

	private void putFont(Options options, String optionName, Font font) {
		runSwing(() -> options.setFont(optionName, font));
	}

	private void putColor(Options options, String optionName, Color color) {
		runSwing(() -> options.setColor(optionName, color));
	}

	private void clickMiddleMouseLocation(ProgramByteViewerComponentProvider testProvider,
			int mouseModifiers) {

		ByteViewerPanel byteViewerPanel = testProvider.getByteViewerPanel();
		ByteViewerComponent component = byteViewerPanel.getCurrentComponent();

		Rectangle cursorBounds = component.getCursorBounds();

		int x = cursorBounds.x + 2; // some fudge
		int y = cursorBounds.y + 2;
		clickMouse(component, MouseEvent.BUTTON2, x, y, 1, mouseModifiers);
	}

	private void clickLocation(ProgramByteViewerComponentProvider testProvider,
			int mouseModifiers) {

		ByteViewerPanel byteViewerPanel = testProvider.getByteViewerPanel();
		ByteViewerComponent component = byteViewerPanel.getCurrentComponent();

		Rectangle cursorBounds = component.getCursorBounds();

		int x = cursorBounds.x + 2; // some fudge
		int y = cursorBounds.y + 2;
		clickMouse(component, MouseEvent.BUTTON1, x, y, 1, mouseModifiers);
	}

	private void setByteViewerLocation(ProgramByteViewerComponentProvider testProvider,
			Address address) throws Exception {
		ByteViewerPanel byteViewerPanel = testProvider.getByteViewerPanel();
		ByteViewerComponent component = byteViewerPanel.getCurrentComponent();
		FieldLocation byteViewerLocation = getFieldLocation(address);

		runSwing(() -> {
			component.setCursorPosition(byteViewerLocation.getIndex(),
				byteViewerLocation.getFieldNum(), byteViewerLocation.getRow(),
				byteViewerLocation.getCol());
			component.scrollToCursor();
		});
	}

	private ProgramByteViewerComponentProvider getSnapshotProvider() {
		@SuppressWarnings("unchecked")
		java.util.List<ProgramByteViewerComponentProvider> providers =
			(List<ProgramByteViewerComponentProvider>) getInstanceField("disconnectedProviders",
				plugin);
		assertFalse("No snapshot provider created", providers.isEmpty());
		return providers.get(0);
	}

	private ByteViewerOptionsDialog launchByteViewerOptions() {
		DockingActionIf action = getAction(plugin, "Byte Viewer Options");
		assertTrue(action.isEnabled());

		performAction(action, false);
		waitForSwing();
		ByteViewerOptionsDialog d = waitForDialogComponent(ByteViewerOptionsDialog.class);
		return d;
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

	private void addViews() throws Exception {
		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		setViewSelected(dialog, "Ascii", true);
		setViewSelected(dialog, "Octal", true);
		setViewSelected(dialog, "Hex Short", true);
		setViewSelected(dialog, "Hex Integer", true);
		setViewSelected(dialog, "Hex Long", true);
		setViewSelected(dialog, "Hex Long Long", true);
		pressButtonByText(dialog.getComponent(), "OK");
	}

	private void setViewSelected(ByteViewerOptionsDialog dialog, String viewName,
			boolean selected) {
		Map<?, ?> checkboxMap = (Map<?, ?>) getInstanceField("checkboxMap", dialog);
		JCheckBox checkbox = (JCheckBox) checkboxMap.get(viewName);
		checkbox.setSelected(selected);
	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
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
				if (name.equals(element.getName())) {
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

	private boolean byteBlockSelectionEquals(ByteBlockSelection b1, ByteBlockSelection b2) {

		int nRanges = b1.getNumberOfRanges();
		if (nRanges != b2.getNumberOfRanges()) {
			return false;
		}
		for (int i = 0; i < nRanges; i++) {
			ByteBlockRange range1 = b1.getRange(i);
			ByteBlockRange range2 = b2.getRange(i);
			if (!range1.equals(range2)) {
				return false;
			}
		}
		return true;
	}

}
