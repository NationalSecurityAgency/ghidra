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
package ghidra.app.plugin.core.select;

import static org.junit.Assert.*;

import java.awt.KeyboardFocusManager;
import java.awt.Window;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

/**
 * Test class to test the Select Bytes dialog.
 */
public class SelectBytesPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String SELECT_BYTES_BUTTON_NAME = "Select Bytes";

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin browser;
	private DockingActionIf showDialogAction;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		tool = env.getTool();
		configureTool(tool);

		browser = env.getPlugin(CodeBrowserPlugin.class);
		SelectBytesPlugin plugin = env.getPlugin(SelectBytesPlugin.class);

		showDialogAction = getAction(plugin, "SelectBytes");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private void openProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("program1", false);
		builder.createMemory(".text", "0x1001000", 0x1000);
		builder.createMemory(".text2", "0x1006000", 0x1000);
		program = builder.getProgram();
		env.showTool(program);
		waitForSwing();
	}

	private void open8051Program() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("program2", ProgramBuilder._8051);
		builder.createMemory("CODE", "CODE:0000", 0x6fff);
		program = builder.getProgram();

		env.showTool(program);
		waitForSwing();
	}

	private void configureTool(PluginTool toolToConfigure) throws Exception {
		toolToConfigure.addPlugin(BlockModelServicePlugin.class.getName());
		toolToConfigure.addPlugin(NextPrevAddressPlugin.class.getName());
		toolToConfigure.addPlugin(CodeBrowserPlugin.class.getName());
		toolToConfigure.addPlugin(GoToAddressLabelPlugin.class.getName());
		toolToConfigure.addPlugin(SelectBytesPlugin.class.getName());
	}

	@Test
	public void testActionEnablement() throws Exception {

		assertFalse(showDialogAction.isEnabledForContext(getContext()));
		openProgram();
		assertTrue(showDialogAction.isEnabledForContext(getContext()));

		SelectBytesDialog dialog = showDialog();

		closeProgram();
		assertTrue(!showDialogAction.isEnabledForContext(getContext()));
		close(dialog);
	}

	@Test
	public void testSelectAll() throws Exception {
		openProgram();
		SelectBytesDialog dialog = showDialog();

		pressSelectAll(dialog);
		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(program.getMemory()), new AddressSet(selection));
		close(dialog);
	}

	@Test
	public void testSelectForward() throws Exception {
		openProgram();
		goTo(addr(0x1006420));

		SelectBytesDialog dialog = showDialog();

		pressSelectAll(dialog);
		assertAddressFieldDisabled(dialog);
		assertLengthFieldDisabled(dialog);

		pressSelectForward(dialog);

		assertAddressFieldDisabled(dialog);
		assertLengthFieldEnabled(dialog);

		setLength(dialog, 0x100);

		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x1006420), addr(0x100651f)), selection);
		close(dialog);
	}

	@Test
	public void testBadInput() throws Exception {
		openProgram();
		goTo(addr(0x1006420));

		SelectBytesDialog dialog = showDialog();

		pressSelectForward(dialog);

		setAddress(dialog, "foo");

		pressSelectBytes(dialog);
		assertEquals("length must be > 0", dialog.getStatusText());
		close(dialog);
	}

	@Test
	public void testSelectBackward() throws Exception {
		openProgram();
		goTo(addr(0x1006420));

		SelectBytesDialog dialog = showDialog();

		pressSelectBackward(dialog);

		setLength(dialog, 0x100);

		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x1006321), addr(0x1006420)), selection);
		close(dialog);

	}

	@Test
	public void testSelectToAddr() throws Exception {
		openProgram();
		goTo(addr(0x1006420));

		SelectBytesDialog dialog = showDialog();

		pressSelectToAddress(dialog);

		setAddress(dialog, "0x1007000");

		pressSelectBytes(dialog);
		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x1006420), addr(0x1006fff)), selection);
		close(dialog);
	}

	@Test
	public void testSelectForward_OverlayBlock() throws Exception {

		openProgram();

		Address start = addr(0x1006420);

		MemoryBlock block = createOverlayBlock(start, 0x100);
		Address overlayStart = block.getStart();
		Address overlayEnd = block.getEnd();
		goTo(overlayStart);

		SelectBytesDialog dialog = showDialog();

		pressSelectForward(dialog);

		setLength(dialog, 0x100);

		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(overlayStart, overlayEnd), selection);
		close(dialog);
	}

	@Test
	public void testSelectForward_OverlayBlock_LengthLargerThanBlock() throws Exception {

		openProgram();

		Address start = addr(0x1006420);

		MemoryBlock block = createOverlayBlock(start, 0x100);
		Address overlayStart = block.getStart();
		Address overlayEnd = block.getEnd();
		goTo(overlayStart);

		SelectBytesDialog dialog = showDialog();

		pressSelectForward(dialog);

		setLength(dialog, 0x101);

		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(overlayStart, overlayEnd), selection);
		close(dialog);
	}

	@Test
	public void testSelectBackward_OverlayBlock() throws Exception {

		openProgram();

		Address start = addr(0x1006420);

		MemoryBlock block = createOverlayBlock(start, 0x100);
		Address overlayStart = block.getStart();
		Address overlayEnd = block.getEnd();
		goTo(overlayEnd);

		SelectBytesDialog dialog = showDialog();

		pressSelectBackward(dialog);

		setLength(dialog, 0x100);

		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(overlayStart, overlayEnd), selection);
		close(dialog);
	}

	@Test
	public void testSelectBackward_OverlayBlock_LengthLargerThanBlock() throws Exception {

		openProgram();

		Address start = addr(0x1006420);

		MemoryBlock block = createOverlayBlock(start, 0x100);
		Address overlayStart = block.getStart();
		Address overlayEnd = block.getEnd();
		goTo(overlayEnd);

		SelectBytesDialog dialog = showDialog();

		pressSelectBackward(dialog);

		setLength(dialog, 0x101);

		pressSelectBytes(dialog);

		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(overlayStart, overlayEnd), selection);
		close(dialog);
	}

	@Test
	public void testSegmentedProgram() throws Exception {

		open8051Program();
		Address startAddress = addr(0x6420);
		goTo(startAddress);

		SelectBytesDialog dialog = showDialog();

		pressSelectAll(dialog);

		assertAddressFieldDisabled(dialog);
		assertLengthFieldDisabled(dialog);

		pressSelectBytes(dialog);
		ProgramSelection selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(program.getMemory()), new AddressSet(selection));

		//---------------------------

		clearSelection();

		pressSelectToAddress(dialog);

		assertAddressFieldEnabled(dialog);
		assertLengthFieldDisabled(dialog);

		setAddress(dialog, "0x6520");

		pressSelectBytes(dialog);
		selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(startAddress, addr(0x6520)), selection);

		//---------------------------

		clearSelection();

		pressSelectForward(dialog);

		assertAddressFieldDisabled(dialog);
		assertLengthFieldEnabled(dialog);

		setLength(dialog, 100);

		pressSelectBytes(dialog);
		selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(startAddress, addr(0x6483)), selection);

		//---------------------------

		clearSelection();

		pressSelectBackward(dialog);

		assertAddressFieldDisabled(dialog);
		assertLengthFieldEnabled(dialog);

		setLength(dialog, 100);

		pressSelectBytes(dialog);
		selection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x63bd), startAddress), selection);
		close(dialog);
	}

	@Test
	public void testCloseProgram() throws Exception {
		openProgram();
		closeProgram();

		assertFalse(showDialogAction.isEnabledForContext(getContext()));
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void pressSelectToAddress(SelectBytesDialog dialog) {
		JRadioButton toButton = (JRadioButton) findComponentByName(dialog, "toButton");
		pressButton(toButton, true);
	}

	private SelectBytesDialog showDialog() {
		performAction(showDialogAction, getContext(), true);
		SelectBytesDialog dialog = waitForDialogComponent(SelectBytesDialog.class);
		return dialog;
	}

	private MemoryBlock createOverlayBlock(Address start, int length) {
		return tx(program, () -> {
			MemoryMapDB memory = program.getMemory();
			return memory.createInitializedBlock("Name", start, length, (byte) 0, TaskMonitor.DUMMY,
				true);
		});
	}

	private Address addr(long addr) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(addr);
	}

	private ActionContext getContext() {
		ActionContext context = browser.getProvider().getActionContext(null);
		if (context == null) {
			context = new DefaultActionContext();
		}
		return context;
	}

	private void closeProgram() throws Exception {
		if (program != null) {
			env.close(program);
			program = null;
		}
	}

	private void pressSelectBackward(SelectBytesDialog dialog) {
		JRadioButton backwardButton = (JRadioButton) findComponentByName(dialog, "backwardButton");
		pressButton(backwardButton, true);
	}

	private void setAddress(SelectBytesDialog dialog, String text) {
		final JTextField addressInputField =
			(JTextField) getInstanceField("toAddressField", dialog);
		runSwing(() -> addressInputField.setText(text));
	}

	private void setLength(SelectBytesDialog dialog, int length) {
		runSwing(() -> dialog.setLength(length));
	}

	private void pressSelectForward(SelectBytesDialog dialog) {
		JRadioButton forwardButton = (JRadioButton) findComponentByName(dialog, "forwardButton");
		pressButton(forwardButton, true);
	}

	private void assertLengthFieldDisabled(SelectBytesDialog dialog) {
		IntegerTextField inputField =
			(IntegerTextField) getInstanceField("lengthField", dialog);
		assertFalse(inputField.getComponent().isEnabled());
	}

	private void assertLengthFieldEnabled(SelectBytesDialog dialog) {
		IntegerTextField inputField =
			(IntegerTextField) getInstanceField("lengthField", dialog);
		assertTrue(inputField.getComponent().isEnabled());
	}

	private void assertAddressFieldDisabled(SelectBytesDialog dialog) {
		JTextField addressInputField = (JTextField) getInstanceField("toAddressField", dialog);
		assertFalse(addressInputField.isEnabled());
	}

	private void assertAddressFieldEnabled(SelectBytesDialog dialog) {
		JTextField addressInputField = (JTextField) getInstanceField("toAddressField", dialog);
		assertTrue(addressInputField.isEnabled());
	}

	private void pressSelectAll(SelectBytesDialog dialog) {
		JRadioButton allButton = (JRadioButton) findComponentByName(dialog, "allButton");
		pressButton(allButton, true);
	}

	private void goTo(Address a) {
		goTo(tool, program, a);
	}

	private void clearSelection() {
		runSwing(() -> browser.getProvider().setSelection(null));
	}

	private void pressSelectBytes(final SelectBytesDialog dialog) {
		executeOnSwingWithoutBlocking(
			() -> pressButtonByText(dialog, SELECT_BYTES_BUTTON_NAME, true));

		// make sure the warning dialog is not showing
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window window = kfm.getActiveWindow();
		if (window instanceof JDialog) {
			JButton button = findButtonByText(window, "OK");
			if (button != null) {
				pressButton(button);
			}
		}
	}
}
