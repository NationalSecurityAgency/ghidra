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
package ghidra.app.plugin.core.memory;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Container;

import javax.swing.JButton;
import javax.swing.JTable;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.AbstractErrDialog;
import docking.action.DockingActionIf;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for merging memory blocks.
 */
public class MemoryMapProvider4Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private MemoryMapPlugin plugin;
	private MemoryMapProvider provider;
	private Program program;
	private Memory memory;
	private JTable table;
	private TableModel model;

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);
		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {

		program = buildProgram("notepad");

		env = new TestEnv();
		tool = env.showTool(program);
		setErrorGUIEnabled(true);
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		tool.addPlugin(MemoryMapPlugin.class.getName());
		tool.addPlugin(GoToServicePlugin.class.getName());
		plugin = env.getPlugin(MemoryMapPlugin.class);

		memory = program.getMemory();

		showProvider();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testMergeBlocks() throws Exception {
		// create 4 blocks: 0-0f, 10-1f, 20-20f, 40-4f.
		tx(program, () -> {
			memory.createInitializedBlock("block1", getAddr(0), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("block2", getAddr(0x10), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("block3", getAddr(0x20), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("block4", getAddr(0x40), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
		});

		assertEquals("0000004f", model.getValueAt(3, MemoryMapModel.END));
		// select rows 0 through 3
		table.setRowSelectionInterval(0, 3);
		DockingActionIf action = getAction(plugin, "Merge Blocks");
		assertTrue(action.isEnabled());
		performAction(action, false);
		waitForSwing();

		assertEquals("block1", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals("00000000", model.getValueAt(0, MemoryMapModel.START));
		assertEquals("0000004f", model.getValueAt(0, MemoryMapModel.END));

		undo(program);
		assertEquals("0000004f", model.getValueAt(3, MemoryMapModel.END));
		redo(program);
		assertEquals("0000004f", model.getValueAt(0, MemoryMapModel.END));
	}

	@Test
	public void testMergeBlocksDisjoint() throws Exception {
		// create 4 blocks: 0-0f, 10-1f, 20-20f, 40-4f.
		tx(program, () -> {
			memory.createInitializedBlock("block1", getAddr(0), 0x10, (byte) 0,

				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("block2", getAddr(0x10), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("block3", getAddr(0x20), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("block4", getAddr(0x40), 0x10, (byte) 0,
				TaskMonitor.DUMMY, false);
		});

		assertEquals("block1", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals("block2", model.getValueAt(1, MemoryMapModel.NAME));
		assertEquals("block3", model.getValueAt(2, MemoryMapModel.NAME));
		assertEquals("block4", model.getValueAt(3, MemoryMapModel.NAME));

		// select rows 0 and 2
		// blocks are not contiguous
		// verify an error message is displayed
		table.setRowSelectionInterval(0, 0);
		table.addRowSelectionInterval(2, 2);
		DockingActionIf action = getAction(plugin, "Merge Blocks");
		assertTrue(action.isEnabled());
		performAction(action, false);
		AbstractErrDialog d = waitForErrorDialog();

		assertEquals("Merge Blocks Failed", d.getTitle());
		assertEquals("Can't merge blocks because they are not contiguous", d.getMessage());
		close(d);
	}

	@Test
	public void testMergeBlocksFarApart() throws Exception {

		tx(program, () -> {
			memory.createInitializedBlock("block1", getAddr(0), 0x50, (byte) 0,
				TaskMonitor.DUMMY, false);
		});

		// select rows 0 and 1
		table.setRowSelectionInterval(0, 1);

		DockingActionIf action = getAction(plugin, "Merge Blocks");
		assertTrue(action.isEnabled());
		performAction(action, false);
		waitForSwing();
		OptionDialog d = waitForDialogComponent(OptionDialog.class);

		assertEquals("Merge Memory Blocks", d.getTitle());
		String message = findMessage(d.getComponent());
		assertTrue(
			message.startsWith("Merging these blocks will create 16387K extra bytes in memory"));

		JButton b = findButton(d.getComponent(), "Merge Blocks");
		assertNotNull(b);
		runSwing(() -> b.getActionListeners()[0].actionPerformed(null));

		waitForSwing();
		assertEquals("block1", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals("00000000", model.getValueAt(0, MemoryMapModel.START));
		assertEquals("010075ff", model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x1007600", model.getValueAt(0, MemoryMapModel.LENGTH));

		undo(program);
		assertEquals("block1", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals("00000000", model.getValueAt(0, MemoryMapModel.START));
		assertEquals("0000004f", model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x50", model.getValueAt(0, MemoryMapModel.LENGTH));

		redo(program);
		assertEquals("block1", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals("00000000", model.getValueAt(0, MemoryMapModel.START));
		assertEquals("010075ff", model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x1007600", model.getValueAt(0, MemoryMapModel.LENGTH));
	}

	@Test
	public void testMergeBlocksFarApartCancel() throws Exception {

		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock("block1", getAddr(0), 0x50, (byte) 0,
			TaskMonitor.DUMMY, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		// select rows 0 and 1
		table.setRowSelectionInterval(0, 1);

		DockingActionIf action = getAction(plugin, "Merge Blocks");
		assertTrue(action.isEnabled());
		performAction(action, false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertEquals("Merge Memory Blocks", d.getTitle());
		assertTrue(findMessage(d.getComponent()).startsWith(
			"Merging these blocks will create 16387K extra bytes in memory"));

		JButton b = findButton(d.getComponent(), "Cancel");
		assertNotNull(b);
		runSwing(() -> b.getActionListeners()[0].actionPerformed(null));
		assertEquals("0000004f", model.getValueAt(0, MemoryMapModel.END));
	}

	private void showProvider() {
		DockingActionIf action = getAction(plugin, "Memory Map");
		performAction(action, true);
		waitForSwing();
		provider = plugin.getMemoryMapProvider();
		table = provider.getTable();
		model = table.getModel();
	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private JButton findButton(Container container, String text) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JButton) {
				if (text.equals(((JButton) element).getText())) {
					return (JButton) element;
				}
			}
			if (element instanceof Container) {
				JButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	private String findMessage(Container container) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof MultiLineLabel) {
				return ((MultiLineLabel) element).getLabel();
			}
			if (element instanceof Container) {
				String str = findMessage((Container) element);
				if (str != null) {
					return str;
				}
			}
		}
		return null;
	}

}
