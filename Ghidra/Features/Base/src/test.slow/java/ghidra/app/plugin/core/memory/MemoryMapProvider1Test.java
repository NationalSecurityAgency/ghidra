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
import java.util.*;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellEditor;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.AddressEvaluator;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Basic tests for the memory map provider.
 */
public class MemoryMapProvider1Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private MemoryMapPlugin plugin;
	private MemoryMapProvider provider;
	private Program program;
	private Memory memory;
	private JTable table;
	private MemoryMapModel model;

	public MemoryMapProvider1Test() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		MemoryBlock[] blocks = new MemoryBlock[5];
		blocks[0] = builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		blocks[1] = builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		blocks[2] = builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		blocks[3] = builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		blocks[4] = builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);

		Program newProgram = builder.getProgram();
		int transactionID = newProgram.startTransaction("Test Transaction");
		for (MemoryBlock b : blocks) {
			b.setSourceName("test");
			b.setComment("comment (1)");
		}
		blocks[0].setExecute(true);
		blocks[3].setComment("Bound Import Table Data");
		blocks[4].setComment("Debug Data");
		newProgram.endTransaction(transactionID, true);

		return newProgram;
	}

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(true);

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
		env.release(program);
		env.dispose();
	}

	@Test
	public void testActionsEnabled() {
		// select first row
		// all actions except "merge" should be enabled
		table.addRowSelectionInterval(0, 0);
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		for (DockingActionIf action : actions) {
			if (action.getName().equals("Merge Blocks")) {
				assertFalse(action.isEnabled());
			}
			else {
				assertTrue(action.isEnabled());
			}
		}
	}

	@Test
	public void testMultiSelection() {

		table.addRowSelectionInterval(0, 1);
		assertEquals(2, table.getSelectedRowCount());
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		for (DockingActionIf action : actions) {
			String name = action.getName();
			if (name.equals("Add Block") || name.equals("Merge Blocks") ||
				name.equals("Delete Block") || name.equals("Set Image Base") ||
				name.equals("Memory Map") || name.equals("Close Window")) {
				assertTrue("Action should be enabled for  a multi-row selection - '" + name + "'",
					action.isEnabled());
			}
			else {
				assertFalse(
					"Action should not be enabled for  a multi-row selection - '" + name + "'",
					action.isEnabled());
			}
		}
	}

	@Test
	public void testGoToAddress() {
		Rectangle rect = table.getCellRect(2, MemoryMapModel.START, true);
		clickMouse(table, 1, rect.x, rect.y, 1, 0);
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		assertEquals(getAddr(0x0100a000), cb.getCurrentAddress());

		rect = table.getCellRect(3, MemoryMapModel.END, true);
		clickMouse(table, 1, rect.x, rect.y, 1, 0);
		String str = (String) model.getValueAt(3, MemoryMapModel.END);
		Address endAddr = AddressEvaluator.evaluate(program, str);

		// the cursor should be on the address that contains the last byte of the range, which
		// happens to be a member of a structure that we opened
		CodeUnit cu = program.getListing().getCodeUnitContaining(endAddr);
		assertTrue(cu.contains(cb.getCurrentAddress()));
	}

	private void setColumnSelected(final int row, final int column, final boolean value) {
		runSwing(() -> table.setValueAt(Boolean.valueOf(value), row, column));
	}

	@Test
	public void testChangeBlockAccess() throws Exception {
		setColumnSelected(0, MemoryMapModel.READ, false);

		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.READ));
		undo(program);
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.READ));
		redo(program);
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.READ));

		setColumnSelected(0, MemoryMapModel.WRITE, true);

		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));
		undo(program);
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.WRITE));
		redo(program);
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));

		setColumnSelected(0, MemoryMapModel.EXECUTE, false);

		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		undo(program);
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		redo(program);
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.EXECUTE));
	}

	@Test
	public void testChangeInitState() throws Exception {

		int transactionID = program.startTransaction("test");
		memory.createUninitializedBlock(".test", getAddr(0), 0x100, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForPostedSwingRunnables();

		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.INIT));
		waitForPostedSwingRunnables();

		Rectangle rect = table.getCellRect(0, MemoryMapModel.INIT, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);
		waitForPostedSwingRunnables();

		NumberInputDialog dialog = waitForDialogComponent(null, NumberInputDialog.class, 1000);
		assertNotNull(dialog);
		invokeInstanceMethod("okCallback", dialog);
		waitForPostedSwingRunnables();

		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.INIT));

		undo(program);
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.INIT));

		redo(program);
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.INIT));
	}

	@Test
	public void testChangeInitState2() throws Exception {

		Rectangle rect = table.getCellRect(0, MemoryMapModel.INIT, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);
		waitForPostedSwingRunnables();

		OptionDialog dialog = waitForDialogComponent(null, OptionDialog.class, 1000);
		assertNotNull(dialog);
		invokeInstanceMethod("okCallback", dialog);
		waitForPostedSwingRunnables();

		waitForBusyTool(tool);

		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.INIT));
		assertTrue(table.getModel().isCellEditable(0, MemoryMapModel.INIT));
	}

	@Test
	public void testEditName() throws Exception {

		table.addRowSelectionInterval(0, 0);
		Rectangle rect = table.getCellRect(0, MemoryMapModel.NAME, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);
		waitForPostedSwingRunnables();

		SwingUtilities.invokeAndWait(() -> {
			int row = 0;
			TableCellEditor editor = table.getCellEditor(row, MemoryMapModel.NAME);
			Component c = editor.getTableCellEditorComponent(table,
				model.getValueAt(row, MemoryMapModel.NAME), true, row, MemoryMapModel.NAME);
			JTextField tf = (JTextField) c;

			tf.setText(".test");
			editor.stopCellEditing();
		});
		waitForPostedSwingRunnables();
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
	}

// Test Eliminated - Memory API allows duplicate names which is a common occurance
// with import formats such as ELF
//
//	public void testDuplicateName() throws Exception {
//		table.addRowSelectionInterval(0, 0);
//		Rectangle rect = table.getCellRect(0, MemoryMapModel.NAME, true);
//		clickMouse(table, 1, rect.x, rect.y, 2, 0);
//		waitForPostedSwingRunnables();
//
//		SwingUtilities.invokeLater(() -> {
//			int row = 0;
//			TableCellEditor editor = table.getCellEditor(row, MemoryMapModel.NAME);
//			Component c = editor.getTableCellEditorComponent(table,
//				model.getValueAt(row, MemoryMapModel.NAME), true, row, MemoryMapModel.NAME);
//			JTextField tf = (JTextField) c;
//
//			tf.setText(".data");
//			editor.stopCellEditing();
//		});
//		waitForPostedSwingRunnables();
//		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));
//
//		final OptionDialog d =
//			waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
//
//		assertNotNull(d);
//		String msg = findMessage(d.getComponent());
//		assertNotNull(msg);
//		assertEquals("Block named .data already exists.", msg);
//		SwingUtilities.invokeAndWait(() -> d.close());
//
//	}

	@Test
	public void testEditComment() throws Exception {
		table.addRowSelectionInterval(0, 0);
		Rectangle rect = table.getCellRect(0, MemoryMapModel.COMMENT, true);
		clickMouse(table, 1, rect.x, rect.y, 2, 0);
		waitForPostedSwingRunnables();

		SwingUtilities.invokeAndWait(() -> {
			int row = 0;
			TableCellEditor editor = table.getCellEditor(row, MemoryMapModel.COMMENT);
			Component c = editor.getTableCellEditorComponent(table,
				model.getValueAt(row, MemoryMapModel.NAME), true, row, MemoryMapModel.NAME);
			JTextField tf = (JTextField) c;

			tf.setText("these are test comments");
			editor.stopCellEditing();
		});
		waitForPostedSwingRunnables();
		assertEquals("these are test comments", model.getValueAt(0, MemoryMapModel.COMMENT));
	}

	@Test
	public void testMoveColumns() {
		// move the end column and make sure navigation is still correct
		// on the end column 
		// move column 2 to 1
		JTableHeader header = table.getTableHeader();
		Rectangle rect1 = header.getHeaderRect(MemoryMapModel.END);
		Rectangle rect2 = header.getHeaderRect(MemoryMapModel.START);
		dragMouse(header, 1, rect1.x, rect1.y, rect2.x, rect2.y, 0);
		dragMouse(header, 1, rect1.x, rect1.y, rect2.x, rect2.y, 0);

		assertEquals("End", table.getColumnName(1));

		Rectangle rect = table.getCellRect(2, 1, true);
		clickMouse(table, 1, rect.x, rect.y, 1, 0);
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		assertEquals(getAddr(0x0100f3ff), cb.getCurrentAddress());
	}

	@Test
	public void testSortNames() {
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(MemoryMapModel.NAME);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		String[] names = new String[blocks.length];
		for (int i = 0; i < names.length; i++) {
			names[i] = blocks[i].getName();
		}
		// sort ascending
		Arrays.sort(names);
		for (int i = names.length - 1; i >= 0; i--) {
			assertEquals(names[i], model.getValueAt(i, MemoryMapModel.NAME));
		}
	}

	@Test
	public void testSortNamesDescending() {
		// ascending
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(MemoryMapModel.NAME);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		// descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		String[] names = new String[blocks.length];
		for (int i = 0; i < names.length; i++) {
			names[i] = blocks[i].getName();
		}
		Arrays.sort(names);
		for (int i = 0; i < names.length; i++) {
			int idx = names.length - 1 - i;
			assertEquals(names[idx], model.getValueAt(i, MemoryMapModel.NAME));
		}
	}

	@Test
	public void testSortStart() {
		// sort descending
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(MemoryMapModel.START);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		ArrayList<Address> list = new ArrayList<>();
		for (MemoryBlock element : blocks) {
			list.add(element.getStart());
		}
		for (int i = 0; i < list.size(); i++) {
			int idx = list.size() - 1 - i;
			assertEquals(list.get(idx).toString(), model.getValueAt(i, MemoryMapModel.START));
		}
	}

	@Test
	public void testSortEnd() {
		// sort ascending
		JTableHeader header = table.getTableHeader();
		Rectangle rect = header.getHeaderRect(MemoryMapModel.END);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		ArrayList<Address> list = new ArrayList<>();
		for (MemoryBlock element : blocks) {
			list.add(element.getEnd());
		}
		for (int i = 0; i < list.size(); i++) {
			assertEquals(list.get(i).toString(), model.getValueAt(i, MemoryMapModel.END));
		}
	}

	@Test
	public void testSortEndDescending() {
		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.END);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		// descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		ArrayList<Address> list = new ArrayList<>();
		for (MemoryBlock element : blocks) {
			list.add(element.getEnd());
		}
		for (int i = 0; i < list.size(); i++) {
			int idx = list.size() - 1 - i;
			assertEquals(list.get(idx).toString(), model.getValueAt(i, MemoryMapModel.END));
		}

	}

	@Test
	public void testSortLength() {
		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.LENGTH);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		MemoryBlock[] blocks = memory.getBlocks();
		long[] lengths = new long[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			lengths[i] = blocks[i].getSize();
		}
		Arrays.sort(lengths);
		for (int i = 0; i < lengths.length; i++) {
			assertEquals("0x" + Long.toHexString(lengths[i]),
				model.getValueAt(i, MemoryMapModel.LENGTH));
		}
	}

	@Test
	public void testSortLengthDescending() {
		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.LENGTH);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		MemoryBlock[] blocks = memory.getBlocks();
		long[] lengths = new long[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			lengths[i] = blocks[i].getSize();
		}
		Arrays.sort(lengths);

		// descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		for (int i = 0; i < lengths.length; i++) {
			int idx = lengths.length - 1 - i;
			assertEquals("0x" + Long.toHexString(lengths[idx]),
				model.getValueAt(i, MemoryMapModel.LENGTH));
		}
	}

	@Test
	public void testSortBlockType() throws Exception {

		// add a bit overlay block, live block, and an unitialized block
		int transactionID = program.startTransaction("test");
		memory.createBitMappedBlock(".Bit", getAddr(0), getAddr(0x01001000), 0x100, false);
		memory.createUninitializedBlock(".Uninit", getAddr(0x3000), 0x200, false);
		program.endTransaction(transactionID, true);

		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.BLOCK_TYPE);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		MemoryBlock[] blocks = memory.getBlocks();

		String[] typeNames = new String[blocks.length];
		for (int i = 0; i < typeNames.length; i++) {
			typeNames[i] = blocks[i].getType().toString();
		}
		Arrays.sort(typeNames);

		for (int i = 0; i < typeNames.length; i++) {
			assertEquals(typeNames[i], model.getValueAt(i, MemoryMapModel.BLOCK_TYPE));
		}

	}

	@Test
	public void testSortBlockTypeDescending() throws Exception {
		// add a bit overlay block, live block, and an unitialized block
		int transactionID = program.startTransaction("test");
		memory.createBitMappedBlock(".Bit", getAddr(0), getAddr(0x01001000), 0x100, false);
		memory.createUninitializedBlock(".Uninit", getAddr(0x3000), 0x200, false);
		program.endTransaction(transactionID, true);

		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.BLOCK_TYPE);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		// descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();

		String[] typeNames = new String[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			typeNames[i] = blocks[i].getType().toString();
		}
		Arrays.sort(typeNames);

		for (int i = 0; i < typeNames.length; i++) {
			int idx = typeNames.length - 1 - i;
			assertEquals(typeNames[idx], model.getValueAt(i, MemoryMapModel.BLOCK_TYPE));
		}

	}

	@Test
	public void testSortSource() throws Exception {
		//
		int transactionID = program.startTransaction("test");
		MemoryBlock block =
			memory.createBitMappedBlock(".Bit", getAddr(0), getAddr(0x01001000), 0x100, false);
		block.setSourceName("this is a test");
		block = memory.createUninitializedBlock(".Uninit", getAddr(0x3000), 0x200, false);
		block.setSourceName("other source");
		program.endTransaction(transactionID, true);

		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.SOURCE);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);
		MemoryBlock[] blocks = memory.getBlocks();
		String[] sources = new String[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			sources[i] = blocks[i].getSourceName();
		}
		Arrays.sort(sources, new StringComparator());

		for (int i = 0; i < sources.length; i++) {
			boolean doAssert = true;
			for (MemoryBlock memBlock : blocks) {
				if (memBlock.getSourceName().equals(sources[i]) &&
					memBlock.getType() == MemoryBlockType.BIT_MAPPED) {
					MemoryBlockSourceInfo info = memBlock.getSourceInfos().get(0);
					Address addr = info.getMappedRange().get().getMinAddress();

					assertEquals(addr.toString(), model.getValueAt(i, MemoryMapModel.SOURCE));
					doAssert = false;
					break;
				}
			}
			if (doAssert) {
				assertEquals(sources[i], model.getValueAt(i, MemoryMapModel.SOURCE));
			}
		}
	}

	@Test
	public void testSortSourceDescending() throws Exception {
		//
		int transactionID = program.startTransaction("test");
		MemoryBlock block =
			memory.createBitMappedBlock(".Bit", getAddr(0), getAddr(0x01001000), 0x100, false);
		block.setSourceName("this is a test");
		block = memory.createUninitializedBlock(".Uninit", getAddr(0x3000), 0x200, false);
		block.setSourceName("other source");
		program.endTransaction(transactionID, true);

		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.SOURCE);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		// descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		String[] sources = new String[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			sources[i] = blocks[i].getSourceName();
		}
		Arrays.sort(sources, new StringComparator());
		for (int i = 0; i < sources.length; i++) {
			int idx = sources.length - 1 - i;
			boolean doAssert = true;
			for (MemoryBlock memBlock : blocks) {
				if (memBlock.getSourceName().equals(sources[idx]) &&
					memBlock.getType() == MemoryBlockType.BIT_MAPPED) {
					MemoryBlockSourceInfo info = memBlock.getSourceInfos().get(0);
					Address addr = info.getMappedRange().get().getMinAddress();
					assertEquals(addr.toString(), model.getValueAt(i, MemoryMapModel.SOURCE));
					doAssert = false;
					break;
				}
			}
			if (doAssert) {
				assertEquals(sources[idx], model.getValueAt(i, MemoryMapModel.SOURCE));
			}
		}
	}

	@Test
	public void testSortComment() {

		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.COMMENT);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		String[] comments = new String[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			comments[i] = blocks[i].getComment();
			if (comments[i] == null) {
				comments[i] = "";
			}
		}
		Arrays.sort(comments, new StringComparator());

		for (int i = 0; i < comments.length; i++) {
			assertEquals(comments[i], model.getValueAt(i, MemoryMapModel.COMMENT));
		}
	}

	@Test
	public void testSortCommentDescending() {

		JTableHeader header = table.getTableHeader();
		// ascending
		Rectangle rect = header.getHeaderRect(MemoryMapModel.COMMENT);
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		// descending
		clickMouse(header, 1, rect.x, rect.y, 1, 0);

		MemoryBlock[] blocks = memory.getBlocks();
		String[] comments = new String[blocks.length];
		for (int i = 0; i < blocks.length; i++) {
			comments[i] = blocks[i].getComment();
			if (comments[i] == null) {
				comments[i] = "";
			}
		}
		Arrays.sort(comments, new StringComparator());

		for (int i = 0; i < comments.length; i++) {
			int idx = comments.length - 1 - i;
			assertEquals(comments[idx], model.getValueAt(i, MemoryMapModel.COMMENT));
		}
	}

	/////////////////////////////////////////////////////////////////////

	private void showProvider() {
		DockingActionIf action = getAction(plugin, "Memory Map");
		performAction(action, true);
		waitForPostedSwingRunnables();
		provider = plugin.getMemoryMapProvider();
		table = provider.getTable();
		model = (MemoryMapModel) table.getModel();

	}

	private Address getAddr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
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

//	private class AddrComparator implements Comparator {
//		/* (non Javadoc)
//		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
//		 */
//		public int compare(Object o1, Object o2) {
//			Address a1 = (Address)o1;
//			Address a2 = (Address)o2;
//			return a1.compareTo(a2);
//		}
//	}
	private class StringComparator implements Comparator<String> {
		/* (non Javadoc)
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@Override
		public int compare(String s1, String s2) {
			if (s1 == null) {
				s1 = "";
			}
			if (s2 == null) {
				s2 = "";
			}
			return s1.compareToIgnoreCase(s2);
		}
	}
}
