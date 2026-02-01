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
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import docking.DockingUtils;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.format.ByteBlockSelection;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalCallback;

/**
 * Test editing in the Byte Viewer.
 */
public class ByteViewerPlugin2Test extends AbstractByteViewerPluginTest {

	@Override
	protected List<Class<? extends Plugin>> getDefaultPlugins() {
		return List.of(GoToAddressLabelPlugin.class, NavigationHistoryPlugin.class,
			NextPrevAddressPlugin.class, CodeBrowserPlugin.class);
	}

	@Override
	protected Program buildProgram() throws Exception {
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

	@Test
	public void testEditModeHex() throws Exception {
		Address addr = addr(0x01001000);
		setEditMode(true);

		goTo(addr);
		ByteViewerComponent c = panel.getCurrentComponent();
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		waitForSwing();

		assertByteData(addr, 0xa0);
		assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testEditModeHex2() throws Exception {
		// verify that the byte being edited cannot be in an instruction
		Address addr = addr(0x01002000);
		goTo(addr);

		setEditMode(true);

		assertByteData(addr, 0x50);
		assertFieldLocationInfo(addr, 256, 0);

		ByteViewerComponent c = panel.getCurrentComponent();
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		waitForSwing();

		assertByteData(addr, 0x50);
		assertFieldColor(getField(c), ByteViewerComponentProvider.FG_COLOR, true);

		Window w = windowForComponent(provider.getComponent());
		String str = runSwing(() -> findLabelStr(w, "Tool Status"));
		assertEquals("Editing not allowed: Instruction exists at address 01002000", str);
	}

	@Test
	public void testEditModeHex3() throws Exception {
		Address addr = addr(0x01001530);
		goTo(addr);
		txSwing(() -> {
			StructureDataType dt = new StructureDataType("test", 0);
			for (int i = 0; i < 7; i++) {
				dt.add(new ByteDataType());
			}
			listing.createData(addr, dt, dt.getLength());
		});

		setEditMode(true);
		ByteViewerComponent c = panel.getCurrentComponent();

		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		waitForSwing();

		assertByteData(addr, 0xa0);
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
	}

	@Test
	public void testEditsInOtherViews() throws Exception {
		// verify changed bytes show up in red in other views
		addViews();

		Address addr = addr(0x01001530);
		goTo(addr);
		txSwing(() -> {
			StructureDataType dt = new StructureDataType("test", 0);
			for (int i = 0; i < 7; i++) {
				dt.add(new ByteDataType());
			}
			listing.createData(addr, dt, dt.getLength());
		});

		setEditMode(true);
		ByteViewerComponent c = panel.getCurrentComponent();

		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		waitForSwing();

		assertByteData(addr, 0xa0);
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertEquals("a0", getField(c, addr).getText());

		assertFieldColor(getField("Chars", addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertEquals(".", getField("Chars", addr).getText());

		assertFieldColor(getField("Hex Integer", addr),
			ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertEquals("a0000000", getField("Hex Integer", addr).getText());
	}

	@Test
	public void testUndoRedo() throws Exception {
		Address addr = addr(0x01001000);
		goTo(addr);
		setEditMode(true);

		ByteViewerComponent c = panel.getCurrentComponent();

		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		waitForSwing();

		assertByteData(addr, 0xa0);

		undo(program);
		program.flushEvents();
		waitForSwing();

		assertByteData(addr, value);
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.FG_COLOR, true);

		redo(program);
		program.flushEvents();

		// field color should show edit color
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
	}

	@Test
	public void testUndoRedo2() throws Exception {

		disableCodeBrowserLocationEvents();

		goTo(addr(0x01001000));

		// make 5 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		setEditMode(true);

		char[] values = { 'a', '1', '2', 'b', '3' };
		int[] keyCodes =
			{ KeyEvent.VK_A, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3 };

		Address addr = addr(0x01001000);
		for (int i = 0; i < keyCodes.length; i++) {
			pressKey(0, keyCodes[i], values[i]);
			addr = addr.add(1);
		}
		program.flushEvents();
		waitForSwing();

		FieldLocation loc1 = new FieldLocation(0, 0, 0, 0); // first byte on first line
		FieldLocation loc2 = new FieldLocation(0, 1, 0, 0); // second byte on first line

		undo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		undo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		undo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, null);

		undo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, null);

		undo(program);
		assertFieldColor(loc1, null);
		assertFieldColor(loc2, null);
		assertFalse(program.canUndo());

		redo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, null);

		redo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, null);

		redo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		redo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		redo(program);
		assertFieldColor(loc1, ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		assertFieldColor(loc2, ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexShort() throws Exception {
		addViews();

		Address addr = addr(0x01001003);
		goTo(addr);

		ByteViewerComponent c = setView("Hex Short");

		setEditMode(true);

		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		assertByteData(addr, 0xa0);

		undo(program);

		assertByteData(addr, value);

		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.FG_COLOR, true);

		redo(program);

		// field color should show edit color
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
	}

	@Test
	public void testUndoRedoHexInteger() throws Exception {
		addViews();

		Address addr = addr(0x01001003);
		goTo(addr);

		ByteViewerComponent c = setView("Hex Integer");
		setEditMode(true);

		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		assertByteData(addr, 0xa0);

		undo(program);

		assertByteData(addr, value);

		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.FG_COLOR, true);

		redo(program);

		// field color should show edit color
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
	}

	@Test
	public void testUndoRedoHexLong() throws Exception {

		addViews();

		setEditMode(true);
		Address addr = addr(0x01001003);
		goTo(addr);
		
		ByteViewerComponent c = setView("Hex Long");

		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		assertByteData(addr, 0xa0);

		undo(program);

		assertByteData(addr, value);

		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.FG_COLOR, true);

		redo(program);

		// field color should show edit color
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
	}

	@Test
	public void testUndoRedoHexLongLong() throws Exception {

		addViews();

		Address addr = addr(0x01001003);
		goTo(addr);
		setEditMode(true);

		ByteViewerComponent c = setView("Hex Long Long");
		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		assertByteData(addr, 0xa0);

		undo(program);

		assertByteData(addr, value);

		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.FG_COLOR, true);

		redo(program);

		// field color should show edit color
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
	}

	@Test
	public void testUndoRedoHexShort2() throws Exception {
		disableCodeBrowserLocationEvents();

		addViews();

		// make 3 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		goTo(addr(0x01001002));
		setEditMode(true);

		ByteViewerComponent c = setView("Hex Short");
		char[] values = { 'a', '1', '2' };
		int[] keyCodes = { KeyEvent.VK_A, KeyEvent.VK_1, KeyEvent.VK_2, };

		for (int i = 0; i < keyCodes.length; i++) {
			pressKey(0, keyCodes[i], values[i]);
		}

		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < keyCodes.length; i++) {
			assertTrue(program.canUndo());

			undo(program);

			Color expectedColor = i == keyCodes.length - 1
					? ByteViewerComponentProvider.FG_COLOR
					: ByteViewerComponentProvider.EDITED_TEXT_COLOR;

			assertFieldColor(c.getCursorLocation(), expectedColor,
				expectedColor == ByteViewerComponentProvider.FG_COLOR);
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < keyCodes.length; i++) {

			redo(program);

			assertFieldColor(c.getCursorLocation(), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexInteger2() throws Exception {
		disableCodeBrowserLocationEvents();

		addViews();

		goTo(addr(0x01001000));
		setEditMode(true);

		ByteViewerComponent c = setView("Hex Integer");

		// make 5 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		char[] values = { 'a', '1', '2', 'b', '3' };
		int[] keyCodes =
			{ KeyEvent.VK_A, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3 };

		for (int i = 0; i < keyCodes.length; i++) {
			pressKey(0, keyCodes[i], values[i]);
		}
		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < keyCodes.length; i++) {
			assertTrue(program.canUndo());

			undo(program);

			Color expectedColor = i == keyCodes.length - 1
					? ByteViewerComponentProvider.FG_COLOR
					: ByteViewerComponentProvider.EDITED_TEXT_COLOR;
			assertFieldColor(getField(c), expectedColor,
				expectedColor == ByteViewerComponentProvider.FG_COLOR);
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < keyCodes.length; i++) {

			redo(program);

			assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexLong2() throws Exception {
		disableCodeBrowserLocationEvents();

		addViews();

		setEditMode(true);

		ByteViewerComponent c = setView("Hex Long");
		// make 9 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		char[] values = { 'a', '1', '2', 'b', '3', 'c', '4', 'd', '5' };
		int[] keyCodes =
			{ KeyEvent.VK_A, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B, KeyEvent.VK_3,
				KeyEvent.VK_C, KeyEvent.VK_4, KeyEvent.VK_D, KeyEvent.VK_5 };

		for (int i = 0; i < keyCodes.length; i++) {
			pressKey(0, keyCodes[i], values[i]);
		}

		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < keyCodes.length; i++) {
			assertTrue(program.canUndo());

			undo(program);

			Color expectedColor = i == keyCodes.length - 1
					? ByteViewerComponentProvider.FG_COLOR
					: ByteViewerComponentProvider.EDITED_TEXT_COLOR;
			assertFieldColor(getField(c), expectedColor,
				expectedColor == ByteViewerComponentProvider.FG_COLOR);
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < 9; i++) {

			redo(program);

			assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testUndoRedoHexLongLong2() throws Exception {
		disableCodeBrowserLocationEvents();


		addViews();

		setEditMode(true);
		ByteViewerComponent c = setView("Hex Long Long");
		// make 9 changes
		// verify that the Undo button is enabled and undo can be done 5 times
		char[] values = { 'a', '1', '2', 'b', '3', 'c', '4', 'd', '5', 'e', '6', 'f', '7', 'a',
			'8', 'b', '9' };
		int[] keyCodes = { KeyEvent.VK_A, KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_B,
			KeyEvent.VK_3, KeyEvent.VK_C, KeyEvent.VK_4, KeyEvent.VK_D, KeyEvent.VK_5,
			KeyEvent.VK_E, KeyEvent.VK_6, KeyEvent.VK_F, KeyEvent.VK_7, KeyEvent.VK_A,
			KeyEvent.VK_8, KeyEvent.VK_B, KeyEvent.VK_9 };

		for (int i = 0; i < keyCodes.length; i++) {
			pressKey(0, keyCodes[i], values[i]);
		}

		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < keyCodes.length; i++) {
			assertTrue(program.canUndo());

			undo(program);

			Color expectedColor = i == keyCodes.length - 1
					? ByteViewerComponentProvider.FG_COLOR
					: ByteViewerComponentProvider.EDITED_TEXT_COLOR;
			assertFieldColor(getField(c), expectedColor,
				expectedColor == ByteViewerComponentProvider.FG_COLOR);
		}
		assertFalse(program.canUndo());

		for (int i = 0; i < keyCodes.length; i++) {

			redo(program);

			assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		}

		assertTrue(program.canUndo());
	}

	@Test
	public void testEditInputHex() throws Exception {

		setEditMode(true);
		Address addr = addr(0x01001000);
		goTo(addr);
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT,
			c.getFocusedCursorColor());
		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_P, 'p');
		program.flushEvents();
		assertByteData(addr, value);
	}

	@Test
	public void testEditModeAscii() throws Exception {

		loadViews("Chars");

		Address addr = addr(0x01001000);
		goTo(addr);
		setEditMode(true);

		ByteViewerComponent c = setView("Chars");

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);
		assertFieldColor(getField(c), ByteViewerComponentProvider.FG_COLOR, true);

		pressKey(0, KeyEvent.VK_Z, 'z');
		program.flushEvents();
		assertByteData(addr, 0x7a);

		assertEquals("z", getField(c, addr).getText());
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		// cursor should have auto-moved, check new field color
		assertFieldColor(getField(c), ByteViewerComponentProvider.FG_COLOR, true);

		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testEditModeOctal() throws Exception {
		addViews();
		ByteViewerComponent c = setView("Octal");

		Address addr = addr(0x01001000);
		goTo(addr);
		setEditMode(true);

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_1, '1');
		program.flushEvents();

		assertByteData(addr, 0x40);
		assertFieldColor(getField(c, addr), ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testEditInputOctal() throws Exception {
		addViews();
		ByteViewerComponent c = setView("Octal");

		Address addr = addr(0x01001000);
		goTo(addr);
		setEditMode(true);

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		byte value = program.getMemory().getByte(addr);
		pressKey(0, KeyEvent.VK_9, '9'); // '9' is out of range for octal
		program.flushEvents();
		assertByteData(addr, value);
	}

	@Test
	public void testEditModeHexShort() throws Exception {
		addViews();
		ByteViewerComponent c = setView("Hex Short");

		Address addr = addr(0x01001003);
		goTo(addr);
		setEditMode(true);

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_1, '1');
		program.flushEvents();
		assertByteData(addr, 0x10);
		assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testEditModeHexInteger() throws Exception {
		addViews();
		ByteViewerComponent c = setView("Hex Integer");

		Address addr = addr(0x01001003);
		goTo(addr);
		setEditMode(true);

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_1, '1');
		program.flushEvents();
		assertByteData(addr, 0x10);

		assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testEditModeHexLong() throws Exception {
		addViews();
		ByteViewerComponent c = setView("Hex Long");

		Address addr = addr(0x01001003);
		goTo(addr);
		setEditMode(true);

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_1, '1');
		program.flushEvents();
		assertByteData(addr, 0x10);

		assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testEditModeHexLongLong() throws Exception {
		addViews();
		ByteViewerComponent c = setView("Hex Long Long");

		Address addr = addr(0x01001003);
		goTo(addr);
		setEditMode(true);

		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_EDIT);

		pressKey(0, KeyEvent.VK_1, '1');
		program.flushEvents();
		assertByteData(addr, 0x10);

		assertFieldColor(getField(c), ByteViewerComponentProvider.EDITED_TEXT_COLOR);

		setEditMode(false);
		assertCursorColor(c, ByteViewerComponentProvider.CURSOR_COLOR_FOCUSED_NON_EDIT);
	}

	@Test
	public void testMemoryMapEdits() throws Exception {
		// put the byte viewer in edit mode
		setEditMode(true);

		Address addr = addr(0x100);

		// add a memory block		
		txSwing(() -> {
			memory.createInitializedBlock(".test", addr, 10, (byte) 0, null, false);
		});

		// edit the first 3 bytes in the block
		ByteViewerComponent c = panel.getCurrentComponent();
		char[] values = { '1', '2', '3' };
		int[] keyCodes = { KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_3 };

		for (int i = 0; i < keyCodes.length; i++) {
			goTo(addr.add(i));
			pressKey(0, keyCodes[i], values[i]);
		}
		program.flushEvents();
		waitForSwing();

		for (int i = 0; i < 3; i++) {
			// verify that the bytes are rendered in red
			assertFieldColor(getField(c, addr.add(i)),
				ByteViewerComponentProvider.EDITED_TEXT_COLOR);
		}
	}

	@Test
	public void testMemoryMapMove() throws Exception {
		// Move a memory block; verify that the byte viewer updates

		setEditMode(true);

		// first add a memory block
		txSwing(() -> {
			memory.createInitializedBlock(".test", addr(0x100), 10, (byte) 0, null, false);
		});

		// edit the first 3 bytes in the block
		ByteViewerComponent c = panel.getCurrentComponent();
		char[] values = { '1', '2', '3' };
		int[] keyCodes = { KeyEvent.VK_1, KeyEvent.VK_2, KeyEvent.VK_3 };

		for (int i = 0; i < keyCodes.length; i++) {
			goTo(addr(0x100).add(i));
			pressKey(0, keyCodes[i], values[i]);
		}
		program.flushEvents();
		waitForSwing();

		// move the block
		txSwing(() -> {
			MemoryBlock block = memory.getBlock(addr(0x100));
			memory.moveBlock(block, addr(0x500), TaskMonitor.DUMMY);
		});

		assertEquals("10", getField(c, addr(0x500)).getText());
		assertEquals("20", getField(c, addr(0x501)).getText());
		assertEquals("30", getField(c, addr(0x502)).getText());
	}

	@Test
	public void testMemoryBlockSplit() throws Exception {
		// split a memory block; verify that the byte viewer shows
		// the separator between blocks after the block is split

		Address addr = addr(0x01002000);

		MemoryBlock block = memory.getBlock(addr);
		Address newaddr = addr(0x01002009);

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


		Address addr = addr(0x01001000);
		MemoryBlock block = memory.getBlock(addr);
		gotoInPanel(addr);

		Address newaddr = addr(0x01000500);

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

		Address addr = addr(0x01001000);
		MemoryBlock block = memory.getBlock(addr);
		gotoInPanel(addr);

		Address newaddr = addr(0x01003000L);

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
		env.showTool();
		disableCodeBrowserLocationEvents();

		Address addr = addr(0x0f001000);
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
		waitForSwing();

		addr = addr(0x0f002000);
		loc = getFieldLocation(addr);
		// cursor should be positioned at next address after deleted block
		assertEquals(loc, c.getCursorLocation());
	}

	@Test
	public void testMemoryBlockDeletedNotInView() throws Exception {
		// delete a memory block that is not showing in the view

		disableCodeBrowserLocationEvents();


		Address addr = addr(0x0f001000);
		gotoInPanel(addr);

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = c.getCursorLocation();
		assertEquals(getFieldLocation(addr), loc);

		MemoryBlock block = memory.getBlock(addr(0x01001000));
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



		ByteViewerOptionsDialog d = launchByteViewerOptions();
		runSwing(() -> d.setBytesPerLine(10));
		pressButtonByText(d.getComponent(), "OK");

		// add the block
		txSwing(() -> {
			Address addr = addr(0x30);
			memory.createInitializedBlock(".test", addr, 0x12, (byte) 0, null, false);

			// add the second block at 0x48
			Address addr2 = addr(0x48);
			memory.createInitializedBlock(".test2", addr2, 0x100, (byte) 0, null, false);
		});

		runSwing(() -> {
			ByteViewerComponent c = panel.getCurrentComponent();
			Address a = addr(0x48);
			FieldLocation loc = getFieldLocation(a);
			c.setCursorPosition(loc.getIndex(), loc.getFieldNum(), loc.getRow(), loc.getCol());
		});

		Address addr = addr(0x48);
		FieldLocation loc = getFieldLocation(addr);
		ByteViewerComponent c = panel.getCurrentComponent();
		// cursor position should not be affected
		assertEquals(loc, c.getCursorLocation());
		assertEquals("00000048", findLabelStr(provider.getComponent(), "Insertion"));
	}

	@Test
	public void testMemoryChange() throws Exception {


		runSwing(() -> tool.showComponentProvider(provider, false));
		ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram(), false);
		waitForSwing();

		pm.openProgram(program.getDomainFile());

		// add a memory block
		txSwing(() -> {
			memory.createInitializedBlock(".test", addr(0), 500, (byte) 0, TaskMonitor.DUMMY,
				false);
		});

		gotoInPanel(addr(0));
		runSwing(() -> tool.showComponentProvider(provider, true));
		waitForSwing();

		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(getFieldLocation(addr(0)), c.getCursorLocation());

		runSwing(() -> tool.showComponentProvider(provider, false));
		waitForSwing();

		// now remove the block
		txSwing(() -> {
			MemoryBlock block = memory.getBlock(addr(0));
			memory.removeBlock(block, TaskMonitor.DUMMY);
		});

		runSwing(() -> tool.showComponentProvider(provider, true));
		waitForSwing();

		c = panel.getCurrentComponent();
		Address addr = cbPlugin.getCurrentAddress();
		assertEquals(getFieldLocation(addr), c.getCursorLocation());
	}

	@Test
	public void testSelectionAcrossBlocks() throws Exception {

		loadViews("Chars", "Octal");

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		runSwing(() -> d.setBytesPerLine(10));
		pressButtonByText(d.getComponent(), "OK");

		// add the block		
		txSwing(() -> {
			Address addr = addr(0x30);
			memory.createInitializedBlock(".test", addr, 0x12, (byte) 0, null, false);

			// add the second block at 0x48
			Address addr2 = addr(0x48);
			memory.createInitializedBlock(".test2", addr2, 0x100, (byte) 0, null, false);
		});

		goTo(addr(0x30));

		FieldSelection fsel = new FieldSelection();
		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc1 = c.getCursorLocation();
		FieldLocation loc2 = getFieldLocation(addr(0x000000cb));
		fsel.addRange(new FieldLocation(loc1.getIndex(), loc1.getFieldNum(), 0, 0),
			new FieldLocation(loc2.getIndex(), loc2.getFieldNum(), 0, 0));

		runSwing(() -> {
			ByteViewerComponent currentComponent = panel.getCurrentComponent();
			currentComponent.selectionChanged(fsel, EventTrigger.GUI_ACTION);
		});
		c = panel.getCurrentComponent();
		ByteBlockSelection sel = c.getViewerSelection();
		ByteViewerComponent octalC = getView("Octal");
		assertTrue(byteBlockSelectionEquals(sel, octalC.getViewerSelection()));

		ByteViewerComponent asciiC = getView("Chars");
		assertTrue(byteBlockSelectionEquals(sel, asciiC.getViewerSelection()));
	}

	@Test
	public void testEditLastByteInBlock() throws Exception {

		goTo(addr(0x01001000));

		ByteViewerOptionsDialog d = launchByteViewerOptions();
		runSwing(() -> d.setBytesPerLine(10));
		pressButtonByText(d.getComponent(), "OK");

		setEditMode(true);

		// add the block
		txSwing(() -> {
			Address addr = addr(0x30);
			memory.createInitializedBlock(".test", addr, 0x12, (byte) 0, null, false);

			// add the second block at 0x48
			Address addr2 = addr(0x48);
			memory.createInitializedBlock(".test2", addr2, 0x100, (byte) 0, null, false);
		});

		goTo(addr(0x41));
		pressKey(0, KeyEvent.VK_3, '3');
		program.flushEvents();
		waitForSwing();

		assertByteData(addr(0x41), 0x30);
	}

	@Test
	public void testEditOptionCurrentViewColor() throws Exception {

		goTo(addr(0x01001000));

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Current View Cursor Color
		putColor(opt, ByteViewerComponentProvider.CURSOR_FOCUSED_COLOR_OPTION_NAME, Palette.GREEN);

		ByteViewerComponent c = panel.getCurrentComponent();
		assertColorsEqual(Palette.GREEN, c.getFocusedCursorColor());
	}

	@Test
	public void testEditOptionCursorColor() throws Exception {


		addViews();

		goTo(addr(0x01001000));

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Current View Cursor Color
		putColor(opt, ByteViewerComponentProvider.CURSOR_UNFOCUSED_COLOR_OPTION_NAME,
			Palette.GREEN);

		ByteViewerComponent c = getView("Octal");
		assertColorsEqual(Palette.GREEN, c.getNonFocusCursorColor());
	}

	@Test
	public void testEditOptionNonHighlightCursorColor() throws Exception {

		addViews();

		goTo(addr(0x01001000));

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Current View Cursor Color
		putColor(opt, ByteViewerComponentProvider.CURSOR_UNFOCUSED_COLOR_OPTION_NAME,
			Palette.CYAN);

		ByteViewerComponent c = getView("Octal");
		assertColorsEqual(Palette.CYAN, c.getNonFocusCursorColor());
	}

	@Test
	public void testEditOptionEditColor() throws Exception {
		// color for changed bytes

		addViews();

		goTo(addr(0x01001000));

		Options opt = tool.getOptions("ByteViewer");
		// change the color for Edit Color
		putColor(opt, ByteViewerComponentProvider.EDIT_TEXT_COLOR_OPTION_NAME, Palette.GREEN);

		setEditMode(true);
		pressKey(0, KeyEvent.VK_A, 'a');
		program.flushEvents();
		waitForSwing();

		ByteField field = getField(getCurrentView(), addr(0x01001000));
		assertColorsEqual(Palette.GREEN, field.getForeground());
	}

	@Test
	public void testEditOptionFont() throws Exception {

		addViews();
		goTo(addr(0x01001000));

		Options opt = tool.getOptions("ByteViewer");
		// change the Font
		Font font = new Font("Times New Roman", Font.BOLD, 12);
		putFont(opt, ByteViewerComponentProvider.OPTION_FONT, font);

		ByteField field = getField(getCurrentView(), addr(0x01001000));
		assertEquals(font, field.getFontMetrics().getFont());
	}

	@Test
	public void testEditOptionSeparatorColor() throws Exception {

		addViews();
		goTo(addr(0x01001000));

		Options opt = tool.getOptions("ByteViewer");
		// change the color for block separator
		putColor(opt, ByteViewerComponentProvider.SEPARATOR_COLOR_OPTION_NAME, Palette.GREEN);

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = getFieldLocation(addr(0x0f001000));
		ByteField field = c.getField(loc.getIndex().subtract(BigInteger.ONE), 0);
		assertColorsEqual(Palette.GREEN, field.getForeground());
	}

	@Test
	public void testGoToUpdatesByteViewer() throws Exception {

		goTo(addr(0x01001050));
		ByteViewerComponent c = panel.getCurrentComponent();
		assertEquals(getFieldLocation(addr(0x01001050)), c.getCursorLocation());
	}

	@Test
	public void testGoToUpdatesFromViewer() throws Exception {


		Address address = addr(0x01002000);
		setByteViewerLocation(provider, address);

		ProgramLocation cbLocation = cbPlugin.getCurrentLocation();
		assertEquals(address, cbLocation.getAddress());
	}

	@Test
	public void testGoToFromSnapshot() throws Exception {


		DockingActionIf snapshotAction = getAction(plugin, "ByteViewer Clone");
		performAction(snapshotAction, true);

		Address address = addr(0x01002000);
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

		ByteViewerComponent component = panel.getCurrentComponent();

		ByteViewerHighlighter highlightProvider =
			(ByteViewerHighlighter) getInstanceField("highlightProvider", component);
		String currentHighlightText = highlightProvider.getText();
		assertNull(currentHighlightText);

		Address address = addr(0x01002000);
		gotoInPanel(address);

		int modifiers = 0;
		clickMiddleMouseLocation(provider, modifiers);
		waitForSwing();

		currentHighlightText = runSwing(() -> highlightProvider.getText());
		assertEquals("50", currentHighlightText);

		clickMiddleMouseLocation(provider, modifiers);
		currentHighlightText = highlightProvider.getText();
		assertEquals(null, currentHighlightText);
	}

	@Test
	public void testSaveRestoreState() throws Exception {

		addViews();
		goTo(addr(0x0100100b));

		ByteViewerOptionsDialog dialog = launchByteViewerOptions();
		runSwing(() -> dialog.setHexGroupSize(4));
		pressButtonByText(dialog.getComponent(), "OK");

		// change the font
		Options opt = tool.getOptions("ByteViewer");
		Font font = new Font("Times New Roman", Font.BOLD, 12);

		runSwing(() -> opt.setFont(ByteViewerComponentProvider.OPTION_FONT, font));
		goTo(addr(0x01002500));

		ByteViewerConfigOptions configOptions = provider.getConfigOptions();
		assertEquals(4, configOptions.getHexGroupSize());

		ViewerPosition vp = panel.getViewerPosition();
		runSwing(() -> env.saveRestoreToolState());

		waitForSwing();

		configOptions = provider.getConfigOptions();

		assertEquals(4, configOptions.getHexGroupSize());
		assertEquals(getFieldLocation(addr(0x01002500)), getCurrentView().getCursorLocation());
		assertEquals(font, panel.getFont());
		assertEquals(font, getCurrentView().getFont());
		assertEquals(vp, panel.getViewerPosition());
	}

	// Remove code browser plugin so the cursor position does not get changed because of location 
	// events that the code browser generates.
	private void disableCodeBrowserLocationEvents() throws Exception {
		runSwing(() -> tool.removePlugins(List.of(cbPlugin)));
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

	private ProgramByteViewerComponentProvider getSnapshotProvider() {
		@SuppressWarnings("unchecked")
		java.util.List<ProgramByteViewerComponentProvider> providers =
			(List<ProgramByteViewerComponentProvider>) getInstanceField("disconnectedProviders",
				plugin);
		assertFalse("No snapshot provider created", providers.isEmpty());
		return providers.get(0);
	}

	private void addViews() throws Exception {
		loadViews("Chars", "Octal", "Hex Short", "Hex Integer", "Hex Long", "Hex Long Long");
	}
}
