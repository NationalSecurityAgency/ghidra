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
import docking.action.DockingActionIf;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

/**
 * Test class to test SelectBlock
 */

public class SelectBlockPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String SELECT_BYTES_BUTTON_NAME = "Select Bytes";

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin browser;
	private SelectBlockPlugin plugin;
	private DockingActionIf action;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		tool = env.getTool();
		configureTool(tool);

		browser = env.getPlugin(CodeBrowserPlugin.class);
		plugin = env.getPlugin(SelectBlockPlugin.class);

		action = (DockingActionIf) getInstanceField("toolBarAction", plugin);
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

	public void open8051Program() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("program2", ProgramBuilder._8051);
		builder.createMemory("CODE", "CODE:0000", 0x6fff);
		program = builder.getProgram();

		env.showTool(program);
		waitForSwing();
	}

	private void closeProgram() throws Exception {
		if (program != null) {
			env.close(program);
			program = null;
		}
	}

	private Address addr(long addr) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(addr);
	}

	private void configureTool(PluginTool toolToConfigure) throws Exception {
		toolToConfigure.addPlugin(BlockModelServicePlugin.class.getName());
		toolToConfigure.addPlugin(NextPrevAddressPlugin.class.getName());
		toolToConfigure.addPlugin(CodeBrowserPlugin.class.getName());
		toolToConfigure.addPlugin(GoToAddressLabelPlugin.class.getName());
		toolToConfigure.addPlugin(SelectBlockPlugin.class.getName());
	}

	private ActionContext getContext() {
		ActionContext context = browser.getProvider().getActionContext(null);
		if (context == null) {
			context = new ActionContext();
		}
		return context;
	}

	@Test
	public void testActionEnablement() throws Exception {
		assertTrue(!action.isEnabledForContext(getContext()));
		openProgram();
		assertTrue(action.isEnabledForContext(getContext()));
		performAction(action, getContext(), true);
		assertTrue(action.isEnabledForContext(getContext()));
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		assertNotNull(dialog);
		assertTrue(dialog.isVisible());
		closeProgram();
		assertTrue(!action.isEnabledForContext(getContext()));
		runSwing(() -> dialog.close());
	}

	@Test
	public void testSelectAll() throws Exception {
		openProgram();
		performAction(action, getContext(), true);
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		JRadioButton allButton = (JRadioButton) findComponentByName(dialog, "allButton");
		pressButton(allButton, true);
		pressSelectBytes(dialog);
		ProgramSelection currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(program.getMemory()), new AddressSet(currSelection));
		runSwing(() -> dialog.close());
	}

	@Test
	public void testSelectForward() throws Exception {
		openProgram();
		browser.goTo(new ProgramLocation(program, addr(0x1006420)));
		performAction(action, getContext(), true);
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		JRadioButton allButton = (JRadioButton) findComponentByName(dialog, "allButton");
		pressButton(allButton, true);

		JTextField addressInputField = (JTextField) getInstanceField("toAddressField", dialog);
		assertTrue(!addressInputField.isEnabled());

		final IntegerTextField inputField =
			(IntegerTextField) getInstanceField("numberInputField", dialog);
		assertTrue(!inputField.getComponent().isEnabled());

		JRadioButton forwardButton = (JRadioButton) findComponentByName(dialog, "forwardButton");
		pressButton(forwardButton, true);

		assertTrue(!addressInputField.isEnabled());
		assertTrue(inputField.getComponent().isEnabled());

		runSwing(() -> inputField.setValue(0x100));

		pressSelectBytes(dialog);
		ProgramSelection currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x1006420), addr(0x100651f)), currSelection);
		runSwing(() -> dialog.close());
	}

	@Test
	public void testBadInput() throws Exception {
		openProgram();
		browser.goTo(new ProgramLocation(program, addr(0x1006420)));
		performAction(action, getContext(), true);
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		JRadioButton forwardButton = (JRadioButton) findComponentByName(dialog, "forwardButton");
		pressButton(forwardButton, true);

		final JTextField addressInputField =
			(JTextField) getInstanceField("toAddressField", dialog);

		runSwing(() -> addressInputField.setText("foo"));
		pressSelectBytes(dialog);
		assertEquals("length must be > 0", dialog.getStatusText());
		runSwing(() -> dialog.close());
	}

	@Test
	public void testSelectBackward() throws Exception {
		openProgram();
		browser.goTo(new ProgramLocation(program, addr(0x1006420)));
		performAction(action, getContext(), true);
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		JRadioButton backwardButton = (JRadioButton) findComponentByName(dialog, "backwardButton");
		pressButton(backwardButton, true);

		final IntegerTextField inputField =
			(IntegerTextField) getInstanceField("numberInputField", dialog);
		runSwing(() -> inputField.setValue(256));

		pressButtonByText(dialog, SELECT_BYTES_BUTTON_NAME, true);
		ProgramSelection currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x1006321), addr(0x1006420)), currSelection);
		runSwing(() -> dialog.close());

	}

	@Test
	public void testSelectToAddr() throws Exception {
		openProgram();
		browser.goTo(new ProgramLocation(program, addr(0x1006420)));
		performAction(action, getContext(), true);
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		JRadioButton toButton = (JRadioButton) findComponentByName(dialog, "toButton");
		pressButton(toButton, true);

		final JTextField addressInputField =
			(JTextField) getInstanceField("toAddressField", dialog);
		runSwing(() -> addressInputField.setText("0x1007000"));
		pressSelectBytes(dialog);
		ProgramSelection currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x1006420), addr(0x1006fff)), currSelection);
		runSwing(() -> dialog.close());

	}

	@Test
	public void testSegmentedProgram() throws Exception {
		// select all
		open8051Program();
		Address startAddress = addr(0x6420);
		browser.goTo(new ProgramLocation(program, startAddress));
		performAction(action, getContext(), true);
		SelectBlockDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), SelectBlockDialog.class, 1000);
		JRadioButton allButton = (JRadioButton) findComponentByName(dialog, "allButton");
		pressButton(allButton, true);

		// all input fields disabled
		final JTextField addressInputField =
			(JTextField) getInstanceField("toAddressField", dialog);
		assertTrue(!addressInputField.isEnabled());

		IntegerTextField inputField =
			(IntegerTextField) getInstanceField("numberInputField", dialog);
		assertTrue(!inputField.getComponent().isEnabled());

		pressSelectBytes(dialog);
		ProgramSelection currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(program.getMemory()), new AddressSet(currSelection));

		clearSelection();

		// to address
		JRadioButton toButton = (JRadioButton) findComponentByName(dialog, "toButton");
		pressButton(toButton, true);

		// only address input field is enabled
		assertTrue(addressInputField.isEnabled());
		assertTrue(!inputField.getComponent().isEnabled());

		runSwing(() -> addressInputField.setText("0x6520"));
		pressSelectBytes(dialog);
		currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(startAddress, addr(0x6520)), currSelection);

		clearSelection();

		// select forward
		JRadioButton forwardButton = (JRadioButton) findComponentByName(dialog, "forwardButton");
		pressButton(forwardButton, true);

		// only address input field is enabled
		assertTrue(!addressInputField.isEnabled());
		assertTrue(inputField.getComponent().isEnabled());

		inputField.setValue(100);
		pressSelectBytes(dialog);
		currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(startAddress, addr(0x6483)), currSelection);

		clearSelection();

		// select backward
		JRadioButton backwardButton = (JRadioButton) findComponentByName(dialog, "backwardButton");
		pressButton(backwardButton, true);

		// only address input field is enabled
		assertTrue(!addressInputField.isEnabled());
		assertTrue(inputField.getComponent().isEnabled());

		inputField.setValue(100);
		pressSelectBytes(dialog);
		currSelection = browser.getCurrentSelection();
		assertEquals(new AddressSet(addr(0x63bd), startAddress), currSelection);
		runSwing(() -> dialog.close());
	}

	@Test
	public void testCloseProgram() throws Exception {
		openProgram();
		closeProgram();

		assertTrue(!action.isEnabledForContext(getContext()));
	}

	private void clearSelection() {
		runSwing(() -> browser.getProvider().setSelection(null));
	}

	private void pressSelectBytes(final SelectBlockDialog dialog) {
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
