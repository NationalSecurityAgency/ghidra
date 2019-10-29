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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.Set;

import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.cmd.memory.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the MemoryMapPlugin for domain object events.
 */
public class MemoryMapPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private MemoryMapPlugin plugin;
	private MemoryMapProvider provider;
	private Program program;
	private Memory memory;

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory("test2", Long.toHexString(0x1008000), 0x600);
		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {

		program = buildProgram("notepad");

		env = new TestEnv();
		tool = env.showTool(program);
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
	public void testActionEnabled() {
		DockingActionIf action = getAction(plugin, "Memory Map");
		assertTrue(action.isEnabled());
	}

	@Test
	public void testOpenProgram() throws Exception {
		env.close(program);
		program = buildProgram("sdk");
		env.open(program);
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (name.equals("Add Block") || name.equals("Set Image Base") ||
				name.equals("Memory Map") || name.equals("Close Window") ||
				name.contains("Table")) {
				assertActionEnabled(action, getActionContext(), true);
			}
			else {
				assertActionEnabled(action, getActionContext(), false);
			}
		}

	}

	@Test
	public void testCloseProgram() {
		env.close(program);
		JTable table = provider.getTable();
		assertEquals(0, table.getModel().getRowCount());
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (name.equals("Memory Map") || name.equals("Close Window")) {
				continue;
			}
			assertActionEnabled(action, getActionContext(), false);
		}
	}

	private void assertActionEnabled(DockingActionIf action, ActionContext context,
			boolean shouldBeEnabled) {

		String text = shouldBeEnabled ? "should be enabled" : "should be disabled";
		assertEquals("Action " + text + ", but is not: '" + action.getFullName() + "'",
			shouldBeEnabled, action.isEnabledForContext(context));
	}

	private ActionContext getActionContext() {
		ActionContext context = provider.getActionContext(null);
		if (context == null) {
			return new ActionContext();
		}
		return context;
	}

	@Test
	public void testBlockNameChanged() throws Exception {
		MemoryBlock block = memory.getBlock(program.getMinAddress());
		int transactionID = program.startTransaction("test");
		block.setName(".myText");
		program.endTransaction(transactionID, true);
		program.flushEvents();

		JTable table = provider.getTable();
		assertEquals(".myText", table.getModel().getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testOverlayBlockNameChanged() throws Exception {
		int transactionID = program.startTransaction("create overlay");
		try {
			memory.createInitializedBlock("Ovl1", program.getMinAddress(), 0x100L, (byte) 0x0, null,
				true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();

		JTable table = provider.getTable();
		editNameCell(table, "Ovl1");
	}

	private void editNameCell(final JTable table, String name) {
		final int nameColumn = MemoryMapModel.NAME;
		final int namedRow = getNamedRow(table, nameColumn, name);

		runSwing(() -> {
			table.getSelectionModel().setSelectionInterval(namedRow, namedRow);
			table.scrollRectToVisible(table.getCellRect(namedRow, nameColumn, true));
		});

		Rectangle rect = table.getCellRect(namedRow, nameColumn, true);
		Point tablePoint = table.getLocationOnScreen();
		final int x = tablePoint.x + rect.x + (rect.width / 2);
		final int y = tablePoint.y + rect.y + (rect.height / 2);
		runSwing(() -> {
			MouseEvent editMouseEvent = new MouseEvent(table, MouseEvent.MOUSE_CLICKED,
				System.currentTimeMillis(), 0, x, y, 2, false);
			table.editCellAt(namedRow, nameColumn, editMouseEvent);
		});

		assertEquals(true, table.isEditing());

		Component editorComponent = table.getEditorComponent();
		assertNotNull(editorComponent);
		assertTrue(editorComponent instanceof JTextField);
		final JTextField editorField = (JTextField) editorComponent;
		editorField.selectAll();
		runSwing(() -> editorField.requestFocus());
		waitForPostedSwingRunnables();

		triggerText(editorField, ".myText\n");

		assertEquals(".myText", table.getModel().getValueAt(namedRow, nameColumn));
	}

	private int getNamedRow(JTable table, int nameColumn, String name) {
		TableModel model = table.getModel();
		int rowCount = table.getRowCount();
		for (int rowIndex = 0; rowIndex < rowCount; rowIndex++) {
			String blockName = (String) model.getValueAt(rowIndex, nameColumn);
			if (blockName.equals(name)) {
				return rowIndex;
			}
		}
		return -1;
	}

	@Test
	public void testBlockAdded() {
		MemoryBlock[] blocks = memory.getBlocks();
		tool.execute(new AddInitializedMemoryBlockCmd(".test", "comments", "test", getAddr(0),
			0x100, true, true, true, false, (byte) 1, false), program);

		JTable table = provider.getTable();
		assertEquals(".test", table.getModel().getValueAt(0, MemoryMapModel.NAME));
		assertEquals(blocks.length + 1, table.getModel().getRowCount());
	}

	@Test
	public void testBlockRemoved() {
		MemoryBlock[] blocks = memory.getBlocks();

		tool.execute(
			new DeleteBlockCmd(new Address[] { blocks[blocks.length - 1].getStart() }, null),
			program);

		JTable table = provider.getTable();
		assertEquals(blocks.length - 1, table.getModel().getRowCount());
	}

	@Test
	public void testBlocksMerged() throws Exception {

		MemoryBlock[] blocks = memory.getBlocks();

		int transactionID = program.startTransaction("test");
		MemoryBlock blockOne =
			memory.createInitializedBlock(".test1", getAddr(0), 0x100, (byte) 0, null, false);
		MemoryBlock blockTwo =
			memory.createInitializedBlock(".test2", getAddr(0x100), 0x200, (byte) 0, null, false);
		program.getMemory().join(blockOne, blockTwo);
		program.endTransaction(transactionID, true);
		program.flushEvents();

		JTable table = provider.getTable();
		assertEquals(blocks.length + 1, table.getModel().getRowCount());
		assertEquals(".test1", table.getModel().getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testBlockReplaced() throws Exception {
		MemoryBlock[] blocks = memory.getBlocks();
		tool.execute(new AddUninitializedMemoryBlockCmd(".test", "comments", "test", getAddr(0),
			0x100, true, true, true, false, false), program);
		JTable table = provider.getTable();
		assertEquals(blocks.length + 1, table.getModel().getRowCount());
		assertEquals(".test", table.getModel().getValueAt(0, MemoryMapModel.NAME));
		assertEquals("Default", table.getModel().getValueAt(0, MemoryMapModel.BLOCK_TYPE));
		assertTrue(!((Boolean) table.getModel().getValueAt(0, MemoryMapModel.INIT)).booleanValue());
		int transactionID = program.startTransaction("test");
		memory.convertToInitialized(memory.getBlock(getAddr(0)), (byte) 0xff);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		assertTrue(((Boolean) table.getModel().getValueAt(0, MemoryMapModel.INIT)).booleanValue());

		assertEquals(blocks.length + 1, table.getModel().getRowCount());
	}

	@Test
	public void testBlockSplit() throws Exception {
		MemoryBlock[] blocks = memory.getBlocks();
		tool.execute(new AddInitializedMemoryBlockCmd(".test", "comments", "test", getAddr(0),
			0x100, true, true, true, false, (byte) 1, false), program);
		JTable table = provider.getTable();
		assertEquals(blocks.length + 1, table.getModel().getRowCount());

		MemoryBlock block = memory.getBlock(getAddr(0));
		int transactionID = program.startTransaction("test");
		memory.split(block, getAddr(0x20));
		program.endTransaction(transactionID, true);
		program.flushEvents();

		assertEquals(blocks.length + 2, table.getModel().getRowCount());
		assertEquals(getAddr(0x20).toString(),
			table.getModel().getValueAt(1, MemoryMapModel.START));
	}

	@Test
	public void testBlockMoved() throws Exception {
		MemoryBlock[] blocks = memory.getBlocks();
		JTable table = provider.getTable();
		assertEquals(blocks.length, table.getModel().getRowCount());

		MemoryBlock block = memory.getBlock(memory.getMinAddress());
		int transactionID = program.startTransaction("test");
		memory.moveBlock(block, getAddr(0x100), TaskMonitorAdapter.DUMMY_MONITOR);
		program.endTransaction(transactionID, true);
		program.flushEvents();

		assertEquals(blocks.length, table.getModel().getRowCount());

		assertEquals(getAddr(0x100).toString(),
			table.getModel().getValueAt(0, MemoryMapModel.START));

	}
	/////////////////////////////////////////////////////////////////////////

	private void showProvider() {
		DockingActionIf action = getAction(plugin, "Memory Map");
		performAction(action, true);
		provider = plugin.getMemoryMapProvider();
	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

}
