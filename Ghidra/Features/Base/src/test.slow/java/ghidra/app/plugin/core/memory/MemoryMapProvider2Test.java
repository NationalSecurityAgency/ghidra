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

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.misc.RegisterField;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.app.util.AddressInput;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for the actions on the Memory Map provider.
 */
public class MemoryMapProvider2Test extends AbstractGhidraHeadedIntegrationTest {

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
		if (tool != null) {
			closeAllWindows();
		}
		env.dispose();
	}

	@Test
	public void testAddBlockDialogSetup() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		assertNotNull(d);
		JRadioButton initRB = (JRadioButton) findComponentByName(d.getComponent(), "Initialized");
		assertNotNull(initRB);
		assertFalse(initRB.isSelected());

		JTextField nameField = (JTextField) findComponentByName(d.getComponent(), "Block Name");
		assertNotNull(nameField);

		AddressInput addrField = (AddressInput) findComponentByName(d.getComponent(), "Start Addr");
		assertNotNull(addrField);
		assertEquals(getAddr(0), addrField.getAddress());

		RegisterField lengthField = (RegisterField) findComponentByName(d.getComponent(), "Length");
		assertNotNull(lengthField);
		assertEquals("0x0", lengthField.getText());

		JTextField commentField = (JTextField) findComponentByName(d.getComponent(), "Comment");
		assertNotNull(commentField);
		assertEquals(0, commentField.getText().length());

		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		assertNotNull(readCB);
		assertTrue(readCB.isSelected());

		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		assertNotNull(writeCB);
		assertTrue(writeCB.isSelected());

		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		assertNotNull(executeCB);
		assertFalse(executeCB.isSelected());

		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");
		assertNotNull(initialValue);
		assertEquals("0x0", initialValue.getText());

		JButton okButton = findButton(d.getComponent(), "OK");
		assertNotNull(okButton);
		assertFalse(okButton.isEnabled());

		pressButtonByText(d.getComponent(), "Cancel");
	}

	@Test
	public void testAddInitializedBlock() throws Exception {

		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		GhidraComboBox<?> comboBox = findComponent(d.getComponent(), GhidraComboBox.class);
		assertNotNull(comboBox);
		assertEquals(MemoryBlockType.DEFAULT, comboBox.getSelectedItem());

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");

		JRadioButton initializedRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Initialized");

		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");
		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Source Addr");
		assertNotNull(addrField);
		assertFalse(addrField.isShowing());

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xa");
			pressButton(executeCB);
		});

		int x = 1;
		int y = 1;
		clickMouse(initializedRB, 1, x, y, 1, 0);

		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isEnabled());
		assertTrue(writeCB.isEnabled());
		assertTrue(executeCB.isEnabled());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = memory.getBlock(getAddr(0));
		assertNotNull(block);

		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals(getAddr(0).toString(), model.getValueAt(0, MemoryMapModel.START));
		assertEquals(block.getEnd().toString(), model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x100", model.getValueAt(0, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.OVERLAY));
		assertEquals("Default", model.getValueAt(0, MemoryMapModel.BLOCK_TYPE));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.INIT));
		assertEquals("", model.getValueAt(0, MemoryMapModel.SOURCE));
		assertEquals("this is a block test", model.getValueAt(0, MemoryMapModel.COMMENT));

		assertEquals(0xa, memory.getByte(getAddr(0)));

		// undo
		undo(program);
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));

		//redo
		redo(program);
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testAddInitializedBlock2() throws Exception {

		// change the start address
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);

		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Start Addr");

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		JRadioButton initializedRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Initialized");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			addrField.setValue("0x200");
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xb");
			pressButton(executeCB);
		});

		int x = 1;
		int y = 1;
		clickMouse(initializedRB, 1, x, y, 1, 0);

		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isEnabled());
		assertTrue(writeCB.isEnabled());
		assertTrue(executeCB.isEnabled());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = memory.getBlock(getAddr(0x200));
		assertNotNull(block);

		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals(getAddr(0x200).toString(), model.getValueAt(0, MemoryMapModel.START));
		assertEquals(block.getEnd().toString(), model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x100", model.getValueAt(0, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.OVERLAY));
		assertEquals("Default", model.getValueAt(0, MemoryMapModel.BLOCK_TYPE));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.INIT));
		assertEquals("", model.getValueAt(0, MemoryMapModel.SOURCE));
		assertEquals("this is a block test", model.getValueAt(0, MemoryMapModel.COMMENT));

		assertEquals(0xb, memory.getByte(getAddr(0x200)));

		undo(program);
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));

		//redo
		redo(program);
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testAddBlockOverlap() throws Exception {
		// verify an error message is displayed
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d =
			waitForDialogComponent(AddBlockDialog.class);

		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Start Addr");

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			addrField.setValue("0x01001200");
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xb");
			pressButton(executeCB);
		});
		assertFalse(okButton.isEnabled());

		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertTrue(msg.startsWith("Block address conflict"));
		assertFalse(okButton.isEnabled());
		close(d);
	}

	@Test
	public void testBadStartValue() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d =
			waitForDialogComponent(AddBlockDialog.class);

		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Start Addr");

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			addrField.setValue("xxxxx");
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xb");
			executeCB.setSelected(true);
		});
		assertFalse(okButton.isEnabled());

		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Please enter a valid Start Address", msg);
		assertFalse(okButton.isEnabled());
		close(d);
	}

	@Test
	public void testNoBlockName() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);

		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xb");
			executeCB.setSelected(true);
		});
		assertFalse(okButton.isEnabled());

		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Please enter a Block Name", msg);
		assertFalse(okButton.isEnabled());

	}

	@Test
	public void testNoLengthUninitialized() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d =
			waitForDialogComponent(AddBlockDialog.class);

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		JRadioButton uninitializedRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Uninitialized");
		assertTrue(uninitializedRB.isSelected()); // default choice

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			nameField.setText(".test");
			commentField.setText("this is a block test");
			executeCB.setSelected(true);
		});
		assertFalse(okButton.isEnabled());

		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Please enter a valid Length: 1 to 0x100000000", msg);
		assertFalse(okButton.isEnabled());
		close(d);
	}

	@Test
	public void testNoLengthInitialized() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d =
			waitForDialogComponent(AddBlockDialog.class);

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		JRadioButton initializedRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Initialized");
		assertFalse(initializedRB.isSelected());

		pressButton(initializedRB);

		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");
		assertTrue(initialValue.isEnabled());

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			nameField.setText(".test");
			commentField.setText("this is a block test");
			initialValue.setText("0xb");
			executeCB.setSelected(true);
		});
		assertFalse(okButton.isEnabled());

		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Please enter a valid Length: 1 to 0x100000000", msg);
		assertFalse(okButton.isEnabled());
		close(d);
	}

	@Test
	public void testDuplicateBlockName() throws Exception {

		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d =
			waitForDialogComponent(AddBlockDialog.class);

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		JTextField lengthField = (JTextField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			nameField.setText(".rsrc");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xb");
			executeCB.setSelected(true);
		});
		assertTrue(okButton.isEnabled());

		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Warning! Duplicate Block Name", msg);

		close(d);
	}

	@Test
	public void testAddUninitializedBlock() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		JRadioButton uninitRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Uninitialized");

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			uninitRB.setSelected(true);
			uninitRB.getActionListeners()[0].actionPerformed(null);

			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is an uninitialized block test");
		});
		waitForSwing();
		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isSelected());
		assertTrue(writeCB.isSelected());
		assertFalse(executeCB.isSelected());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = memory.getBlock(getAddr(0));
		assertNotNull(block);

		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals(getAddr(0).toString(), model.getValueAt(0, MemoryMapModel.START));
		assertEquals(block.getEnd().toString(), model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x100", model.getValueAt(0, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.OVERLAY));
		assertEquals("Default", model.getValueAt(0, MemoryMapModel.BLOCK_TYPE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.INIT));
		assertEquals("", model.getValueAt(0, MemoryMapModel.SOURCE));
		assertEquals("this is an uninitialized block test",
			model.getValueAt(0, MemoryMapModel.COMMENT));

		// undo
		undo(program);
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));

		//redo
		redo(program);
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testAddOverlayBlockInitialized() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		GhidraComboBox<?> comboBox = findComponent(d.getComponent(), GhidraComboBox.class);

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		JCheckBox overlayCB = (JCheckBox) findComponentByName(d.getComponent(), "Overlay");
		JRadioButton initializedRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Initialized");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");
		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Source Addr");
		assertNotNull(addrField);
		assertFalse(addrField.isShowing());

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			comboBox.setSelectedItem(MemoryBlockType.DEFAULT);
			overlayCB.setSelected(true);
			overlayCB.getActionListeners()[0].actionPerformed(null);
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			initialValue.setText("0xa");
		});

		runSwing(() -> {
			pressButton(executeCB);
		});

		int x = 1;
		int y = 1;
		clickMouse(initializedRB, 1, x, y, 1, 0);

		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isSelected());
		assertTrue(writeCB.isSelected());
		assertTrue(executeCB.isSelected());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = null;
		AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
		for (AddressSpace space : spaces) {
			if (space.isOverlaySpace()) {
				Address blockAddr = space.getAddress(0);
				block = memory.getBlock(blockAddr);
				break;
			}
		}

		assertNotNull(block);
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		int row = blocks.length - 1;
		assertEquals(".test", model.getValueAt(row, MemoryMapModel.NAME));
		assertEquals("00000000", model.getValueAt(row, MemoryMapModel.START));
		assertEquals(".test::00000000", block.getStart().toString());
		assertEquals("000000ff", model.getValueAt(row, MemoryMapModel.END));
		assertEquals(".test::000000ff", block.getEnd().toString());
		assertEquals("0x100", model.getValueAt(row, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.WRITE));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.OVERLAY));
		assertEquals(
			MemoryBlockType.DEFAULT.toString(),
			model.getValueAt(row, MemoryMapModel.BLOCK_TYPE));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.INIT));
		assertEquals("", model.getValueAt(row, MemoryMapModel.SOURCE));
		assertEquals("this is a block test", model.getValueAt(row, MemoryMapModel.COMMENT));

		assertEquals(0xa, memory.getByte(block.getStart()));
	}

	@Test
	public void testAddOverlayBlockUninitialized() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		GhidraComboBox<?> comboBox = findComponent(d.getComponent(), GhidraComboBox.class);

		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		JCheckBox overlayCB = (JCheckBox) findComponentByName(d.getComponent(), "Overlay");

		JRadioButton uninitRB =
			(JRadioButton) findComponentByName(d.getComponent(), "Uninitialized");
		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Source Addr");
		assertNotNull(addrField);
		assertFalse(addrField.isShowing());

		JButton okButton = findButton(d.getComponent(), "OK");

		runSwing(() -> {
			comboBox.setSelectedItem(MemoryBlockType.DEFAULT);
			overlayCB.setSelected(true);
			overlayCB.getActionListeners()[0].actionPerformed(null);
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a block test");
			pressButton(executeCB);
			uninitRB.setSelected(true);
			uninitRB.getActionListeners()[0].actionPerformed(null);
		});
		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isEnabled());
		assertTrue(writeCB.isEnabled());
		assertTrue(executeCB.isEnabled());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = null;
		AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
		for (AddressSpace space : spaces) {
			if (space.isOverlaySpace()) {
				Address blockAddr = space.getAddress(0);
				block = memory.getBlock(blockAddr);
				break;
			}
		}

		assertNotNull(block);

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		int row = blocks.length - 1;
		assertEquals(".test", model.getValueAt(row, MemoryMapModel.NAME));
		assertEquals("00000000", model.getValueAt(row, MemoryMapModel.START));
		assertEquals(".test::00000000", block.getStart().toString());
		assertEquals("000000ff", model.getValueAt(row, MemoryMapModel.END));
		assertEquals(".test::000000ff", block.getEnd().toString());
		assertEquals("0x100", model.getValueAt(row, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.WRITE));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.TRUE, model.getValueAt(row, MemoryMapModel.OVERLAY));
		assertEquals(
			MemoryBlockType.DEFAULT.toString(),
			model.getValueAt(row, MemoryMapModel.BLOCK_TYPE));
		assertEquals(Boolean.FALSE, model.getValueAt(row, MemoryMapModel.INIT));
		assertEquals("", model.getValueAt(row, MemoryMapModel.SOURCE));
		assertEquals("this is a block test", model.getValueAt(row, MemoryMapModel.COMMENT));

		try {
			memory.getByte(block.getStart());
			Assert.fail("Should have gotten MemoryAccessException!");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}

	@Test
	public void testAddBitBlock() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		GhidraComboBox<?> comboBox = findComponent(d.getComponent(), GhidraComboBox.class);
		assertNotNull(comboBox);
		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");

		JButton okButton = findButton(d.getComponent(), "OK");
		runSwing(() -> {
			comboBox.setSelectedItem(MemoryBlockType.BIT_MAPPED);
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a bit block test");
		});
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");
		assertNotNull(initialValue);
		assertFalse(initialValue.isShowing());

		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Source Addr");
		assertNotNull(addrField);
		assertTrue(addrField.isVisible());
		if (addrField.getAddress() == null) {
			assertFalse(okButton.isEnabled());
			String msg = findLabelStr(d.getComponent(), "statusLabel");
			assertEquals("Please enter a source address for the bit block", msg);
			runSwing(() -> addrField.setValue("01001000"));
		}
		else {
			assertTrue(okButton.isEnabled());
		}

		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isEnabled());
		assertTrue(writeCB.isEnabled());
		assertTrue(executeCB.isEnabled());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = memory.getBlock(getAddr(0));
		assertNotNull(block);

		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals(getAddr(0).toString(), model.getValueAt(0, MemoryMapModel.START));
		assertEquals(block.getEnd().toString(), model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x100", model.getValueAt(0, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.OVERLAY));
		assertEquals("Bit Mapped", model.getValueAt(0, MemoryMapModel.BLOCK_TYPE));
		assertNull(model.getValueAt(0, MemoryMapModel.INIT));
		assertEquals("01001000", model.getValueAt(0, MemoryMapModel.SOURCE));
		assertEquals("this is a bit block test", model.getValueAt(0, MemoryMapModel.COMMENT));

		// undo
		undo(program);
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));

		//redo
		redo(program);
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testAddByteMappedBlock() throws Exception {
		DockingActionIf action = getAction(plugin, "Add Block");
		performAction(action, false);

		// find the dialog for the add
		AddBlockDialog d = waitForDialogComponent(AddBlockDialog.class);
		GhidraComboBox<?> comboBox = findComponent(d.getComponent(), GhidraComboBox.class);
		assertNotNull(comboBox);
		JTextField nameField =
			(JTextField) findComponentByName(d.getComponent(), "Block Name");
		RegisterField lengthField =
			(RegisterField) findComponentByName(d.getComponent(), "Length");
		JTextField commentField =
			(JTextField) findComponentByName(d.getComponent(), "Comment");
		JCheckBox readCB = (JCheckBox) findComponentByName(d.getComponent(), "Read");
		JCheckBox writeCB = (JCheckBox) findComponentByName(d.getComponent(), "Write");
		JCheckBox executeCB = (JCheckBox) findComponentByName(d.getComponent(), "Execute");
		RegisterField initialValue =
			(RegisterField) findComponentByName(d.getComponent(), "Initial Value");
		assertNotNull(initialValue);
		assertFalse(initialValue.isShowing());
		AddressInput addrField =
			(AddressInput) findComponentByName(d.getComponent(), "Source Addr");
		assertNotNull(addrField);
		assertFalse(addrField.isShowing());

		JButton okButton = findButton(d.getComponent(), "OK");
		runSwing(() -> {
			comboBox.setSelectedItem(MemoryBlockType.BYTE_MAPPED);
			nameField.setText(".test");
			lengthField.setText("0x100");
			commentField.setText("this is a byte block test");
		});
		assertTrue(addrField.isShowing());
		if (addrField.getAddress() == null) {
			assertFalse(okButton.isEnabled());
			String msg = findLabelStr(d.getComponent(), "statusLabel");
			assertEquals("Please enter a source address for the bit block", msg);
			runSwing(() -> addrField.setValue("01001000"));
		}
		else {
			assertTrue(okButton.isEnabled());
		}

		assertTrue(okButton.isEnabled());
		assertTrue(readCB.isEnabled());
		assertTrue(writeCB.isEnabled());
		assertTrue(executeCB.isEnabled());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		program.flushEvents();
		waitForSwing();

		MemoryBlock block = memory.getBlock(getAddr(0));
		assertNotNull(block);

		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals(getAddr(0).toString(), model.getValueAt(0, MemoryMapModel.START));
		assertEquals(block.getEnd().toString(), model.getValueAt(0, MemoryMapModel.END));
		assertEquals("0x100", model.getValueAt(0, MemoryMapModel.LENGTH));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.READ));
		assertEquals(Boolean.TRUE, model.getValueAt(0, MemoryMapModel.WRITE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.EXECUTE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.OVERLAY));
		assertEquals("Byte Mapped", model.getValueAt(0, MemoryMapModel.BLOCK_TYPE));
		assertEquals(Boolean.FALSE, model.getValueAt(0, MemoryMapModel.INIT));
		assertEquals("01001000", model.getValueAt(0, MemoryMapModel.SOURCE));
		assertEquals("this is a byte block test", model.getValueAt(0, MemoryMapModel.COMMENT));

		// undo
		undo(program);
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));

		//redo
		redo(program);
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testDeleteBlock() throws Exception {

		Address minAddr = program.getMinAddress();
		// select a row
		table.addRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Delete Block");
		performAction(action, false);
		waitForSwing();

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Delete Memory Block?", d.getTitle());

		JButton button = findButton(d.getComponent(), "Yes");
		assertNotNull(button);

		runSwingLater(() -> button.getActionListeners()[0].actionPerformed(null));
		Thread.sleep(500);
		while (!program.canLock()) {
			Thread.sleep(100);
		}
		Thread.sleep(500);

		program.flushEvents();
		waitForSwing();

		assertEquals(".data", model.getValueAt(0, MemoryMapModel.NAME));
		assertFalse(memory.contains(minAddr));

		undo(program);
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));

		redo(program);
		assertEquals(".data", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testDeleteBlockAnswerNo() {
		// select a row
		table.addRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Delete Block");
		performAction(action, false);
		waitForSwing();

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Delete Memory Block?", d.getTitle());

		JButton button = findButton(d.getComponent(), "No");
		assertNotNull(button);

		runSwingLater(() -> button.getActionListeners()[0].actionPerformed(null));
		assertEquals(".text", model.getValueAt(0, MemoryMapModel.NAME));
	}

	@Test
	public void testMoveBlockNotAllowed() throws Exception {
		// create an overlay block
		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock(".overlay", getAddr(0), 0x100, (byte) 0xa,
			TaskMonitor.DUMMY, true);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();
		int row = table.getModel().getRowCount() - 1;
		table.setRowSelectionInterval(row, row);

		DockingActionIf action = getAction(plugin, "Move Block");
		performAction(action, false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Move Overlay Block Not Allowed", d.getTitle());
	}

	@Test
	public void testMoveBlock() throws Exception {
		// add a block at 0, length 0x100
		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock(".test", getAddr(0), 0x100, (byte) 0,
			TaskMonitor.DUMMY, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		table.setRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Move Block");
		assertTrue(action.isEnabled());
		performAction(action, false);

		waitForSwing();
		MoveBlockDialog d =
			waitForDialogComponent(MoveBlockDialog.class);

		assertNotNull(d);
		assertEquals("Move Memory Block", d.getTitle());

		// verify the labels
		JLabel nameLabel = (JLabel) findComponentByName(d.getComponent(), "blockName");
		assertNotNull(nameLabel);
		assertEquals(".test", nameLabel.getText());

		JLabel origStartLabel = (JLabel) findComponentByName(d.getComponent(), "origStart");
		assertNotNull(origStartLabel);
		assertEquals(getAddr(0).toString(), origStartLabel.getText());

		JLabel origEndLabel = (JLabel) findComponentByName(d.getComponent(), "origEnd");
		assertNotNull(origEndLabel);
		assertEquals(getAddr(0xffL).toString(), origEndLabel.getText());

		JLabel lengthLabel = (JLabel) findComponentByName(d.getComponent(), "length");
		assertNotNull(lengthLabel);
		assertEquals("256  (0x100)", lengthLabel.getText());

		AddressInput startField =
			(AddressInput) findComponentByName(d.getComponent(), "newStart");

		assertNotNull(startField);
		assertEquals(getAddr(0), startField.getAddress());

		AddressInput endField =
			(AddressInput) findComponentByName(d.getComponent(), "newEnd");
		assertNotNull(endField);
		assertEquals(getAddr(0xffL), endField.getAddress());

		JButton okButton = findButton(d.getComponent(), "OK");
		assertNotNull(okButton);
		assertFalse(okButton.isEnabled());

		// move the block to 0x300
		runSwing(() -> startField.setValue(getAddr(0x0300).toString()));
		assertEquals(getAddr(0x3ff), endField.getAddress());
		assertTrue(okButton.isEnabled());

		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));
		// wait for thread to start
		Thread.sleep(1000);

		while (!program.canLock()) {
			Thread.sleep(100);
		}

		program.flushEvents();
		waitForSwing();
		assertEquals(".test", model.getValueAt(0, MemoryMapModel.NAME));
		assertEquals(getAddr(0x300).toString(), model.getValueAt(0, MemoryMapModel.START));
		assertEquals(getAddr(0x3ff).toString(), model.getValueAt(0, MemoryMapModel.END));
	}

	@Test
	public void testMoveBlockInvalidStart() throws Exception {
		// add a block at 0, length 0x100
		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock(".test", getAddr(0), 0x100, (byte) 0,
			TaskMonitor.DUMMY, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		table.setRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Move Block");
		assertTrue(action.isEnabled());
		performAction(action, false);

		waitForSwing();
		MoveBlockDialog d =
			waitForDialogComponent(MoveBlockDialog.class);

		assertNotNull(d);
		assertEquals("Move Memory Block", d.getTitle());

		// verify the labels
		JLabel nameLabel = (JLabel) findComponentByName(d.getComponent(), "blockName");
		assertNotNull(nameLabel);
		assertEquals(".test", nameLabel.getText());

		JLabel origStartLabel = (JLabel) findComponentByName(d.getComponent(), "origStart");
		assertNotNull(origStartLabel);
		assertEquals(getAddr(0).toString(), origStartLabel.getText());

		JLabel origEndLabel = (JLabel) findComponentByName(d.getComponent(), "origEnd");
		assertNotNull(origEndLabel);
		assertEquals(getAddr(0xffL).toString(), origEndLabel.getText());

		JLabel lengthLabel = (JLabel) findComponentByName(d.getComponent(), "length");
		assertNotNull(lengthLabel);
		assertEquals("256  (0x100)", lengthLabel.getText());

		AddressInput startField =
			(AddressInput) findComponentByName(d.getComponent(), "newStart");

		assertNotNull(startField);
		assertEquals(getAddr(0), startField.getAddress());

		AddressInput endField =
			(AddressInput) findComponentByName(d.getComponent(), "newEnd");
		assertNotNull(endField);
		assertEquals(getAddr(0xffL), endField.getAddress());

		JButton okButton = findButton(d.getComponent(), "OK");
		assertNotNull(okButton);
		assertFalse(okButton.isEnabled());

		// enter an invalid address
		runSwing(
			() -> startField.setValue(getAddr(0x0300).toString() + "gggg"));
		assertFalse(okButton.isEnabled());
		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Invalid Address", msg);
		close(d);
	}

	@Test
	public void testMoveBlockInvalidEnd() throws Exception {
		// add a block at 0, length 0x100
		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock(".test", getAddr(0), 0x100, (byte) 0,
			TaskMonitor.DUMMY, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		table.setRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Move Block");
		assertTrue(action.isEnabled());
		performAction(action, false);

		waitForSwing();
		MoveBlockDialog d =
			waitForDialogComponent(MoveBlockDialog.class);

		assertNotNull(d);
		assertEquals("Move Memory Block", d.getTitle());

		// verify the labels
		JLabel nameLabel = (JLabel) findComponentByName(d.getComponent(), "blockName");
		assertNotNull(nameLabel);
		assertEquals(".test", nameLabel.getText());

		JLabel origStartLabel = (JLabel) findComponentByName(d.getComponent(), "origStart");
		assertNotNull(origStartLabel);
		assertEquals(getAddr(0).toString(), origStartLabel.getText());

		JLabel origEndLabel = (JLabel) findComponentByName(d.getComponent(), "origEnd");
		assertNotNull(origEndLabel);
		assertEquals(getAddr(0xffL).toString(), origEndLabel.getText());

		JLabel lengthLabel = (JLabel) findComponentByName(d.getComponent(), "length");
		assertNotNull(lengthLabel);
		assertEquals("256  (0x100)", lengthLabel.getText());

		AddressInput startField =
			(AddressInput) findComponentByName(d.getComponent(), "newStart");

		assertNotNull(startField);
		assertEquals(getAddr(0), startField.getAddress());

		AddressInput endField =
			(AddressInput) findComponentByName(d.getComponent(), "newEnd");
		assertNotNull(endField);
		assertEquals(getAddr(0xffL), endField.getAddress());

		JButton okButton = findButton(d.getComponent(), "OK");
		assertNotNull(okButton);
		assertFalse(okButton.isEnabled());

		// enter an invalid address
		runSwing(() -> endField.setValue(getAddr(0x0300).toString() + "gggg"));
		assertFalse(okButton.isEnabled());
		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Invalid Address", msg);
		close(d);
	}

	@Test
	public void testMoveBlockEndTooSmall() throws Exception {
		// add a block at 0, length 0x100
		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock(".test", getAddr(0), 0x100, (byte) 0,
			TaskMonitor.DUMMY, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		table.setRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Move Block");
		assertTrue(action.isEnabled());
		performAction(action, false);

		waitForSwing();
		MoveBlockDialog d =
			waitForDialogComponent(MoveBlockDialog.class);

		assertNotNull(d);
		assertEquals("Move Memory Block", d.getTitle());

		// verify the labels
		JLabel nameLabel = (JLabel) findComponentByName(d.getComponent(), "blockName");
		assertNotNull(nameLabel);
		assertEquals(".test", nameLabel.getText());

		JLabel origStartLabel = (JLabel) findComponentByName(d.getComponent(), "origStart");
		assertNotNull(origStartLabel);
		assertEquals(getAddr(0).toString(), origStartLabel.getText());

		JLabel origEndLabel = (JLabel) findComponentByName(d.getComponent(), "origEnd");
		assertNotNull(origEndLabel);
		assertEquals(getAddr(0xffL).toString(), origEndLabel.getText());

		JLabel lengthLabel = (JLabel) findComponentByName(d.getComponent(), "length");
		assertNotNull(lengthLabel);
		assertEquals("256  (0x100)", lengthLabel.getText());

		AddressInput startField =
			(AddressInput) findComponentByName(d.getComponent(), "newStart");

		assertNotNull(startField);
		assertEquals(getAddr(0), startField.getAddress());

		AddressInput endField =
			(AddressInput) findComponentByName(d.getComponent(), "newEnd");
		assertNotNull(endField);
		assertEquals(getAddr(0xffL), endField.getAddress());

		JButton okButton = findButton(d.getComponent(), "OK");
		assertNotNull(okButton);
		assertFalse(okButton.isEnabled());

		// enter an invalid address
		runSwing(() -> {
			startField.setValue(getAddr(0x1000).toString());
			endField.setValue(getAddr(0x10).toString());
		});
		assertFalse(okButton.isEnabled());
		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("End Address is too small", msg);
		close(d);
	}

	@Test
	public void testMoveBlockOverlap() throws Exception {
		// add a block at 0, length 0x100
		int transactionID = program.startTransaction("test");
		memory.createInitializedBlock(".test", getAddr(0), 0x100, (byte) 0,
			TaskMonitor.DUMMY, false);
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForSwing();

		table.setRowSelectionInterval(0, 0);

		DockingActionIf action = getAction(plugin, "Move Block");
		assertTrue(action.isEnabled());
		performAction(action, false);

		waitForSwing();
		MoveBlockDialog d =
			waitForDialogComponent(MoveBlockDialog.class);

		assertNotNull(d);
		assertEquals("Move Memory Block", d.getTitle());

		// verify the labels
		JLabel nameLabel = (JLabel) findComponentByName(d.getComponent(), "blockName");
		assertNotNull(nameLabel);
		assertEquals(".test", nameLabel.getText());

		JLabel origStartLabel = (JLabel) findComponentByName(d.getComponent(), "origStart");
		assertNotNull(origStartLabel);
		assertEquals(getAddr(0).toString(), origStartLabel.getText());

		JLabel origEndLabel = (JLabel) findComponentByName(d.getComponent(), "origEnd");
		assertNotNull(origEndLabel);
		assertEquals(getAddr(0xffL).toString(), origEndLabel.getText());

		JLabel lengthLabel = (JLabel) findComponentByName(d.getComponent(), "length");
		assertNotNull(lengthLabel);
		assertEquals("256  (0x100)", lengthLabel.getText());

		AddressInput startField =
			(AddressInput) findComponentByName(d.getComponent(), "newStart");

		assertNotNull(startField);
		assertEquals(getAddr(0), startField.getAddress());

		AddressInput endField =
			(AddressInput) findComponentByName(d.getComponent(), "newEnd");
		assertNotNull(endField);
		assertEquals(getAddr(0xffL), endField.getAddress());

		JButton okButton = findButton(d.getComponent(), "OK");
		assertNotNull(okButton);
		assertFalse(okButton.isEnabled());

		// enter an invalid address
		runSwing(() -> startField.setValue("00000000"));
		assertFalse(okButton.isEnabled());
		String msg = findLabelStr(d.getComponent(), "statusLabel");
		assertEquals("Block is already at 00000000", msg);
		close(d);
	}

	private void showProvider() {
		DockingActionIf action = getAction(plugin, "Memory Map");
		performAction(action, true);
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

	private String findLabelStr(Container container, String name) {
		JLabel label = (JLabel) findComponentByName(container, name);
		if (label != null) {
			return label.getText();
		}
		return null;
	}

}
