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
package ghidra.app.plugin.core.function;

import static org.junit.Assert.*;

import java.awt.Component;

import javax.swing.JButton;
import javax.swing.JTextField;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.plugin.core.analysis.AutoAnalysisPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.plugin.core.highlight.SetHighlightPlugin;
import ghidra.app.plugin.core.navigation.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class Function2Test extends AbstractGhidraHeadedIntegrationTest {

	public Function2Test() {
		super();
	}

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private FunctionPlugin fp;
	private DockingActionIf setStackDepthChangeAction;
	private DockingActionIf removeStackDepthChangeAction;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);

		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(NextPrevSelectedRangePlugin.class.getName());
		tool.addPlugin(NextPrevHighlightRangePlugin.class.getName());
		tool.addPlugin(SetHighlightPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
		tool.addPlugin(AutoAnalysisPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());

		fp = getPlugin(tool, FunctionPlugin.class);
		setStackDepthChangeAction = getAction(fp, "Set Stack Depth Change");
		removeStackDepthChangeAction = getAction(fp, "Remove Stack Depth Change");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {

		if ("notepad".equals(programName)) {
			ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
			program = builder.getProgram();

			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
			builder.dispose();
			waitForSwing();
			addrFactory = program.getAddressFactory();
		}
		else {
			Assert.fail("don't have program: " + programName);
		}
	}

	@Test
	public void testSetStackDepthChangeAction() throws Exception {
		env.showTool();
		loadProgram("notepad");
		int id = -1;
		try {
			id = program.startTransaction("Adding stack depth changes.");
			CallDepthChangeInfo.setStackDepthChange(program, addr("01002493"), 16);
			CallDepthChangeInfo.setStackDepthChange(program, addr("0100249b"), -10);
		}
		finally {
			if (id >= 0) {
				program.endTransaction(id, true);
			}
		}
		cb.goToField(addr("0x1002493"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth + 16", cb.getCurrentFieldText());
		cb.goToField(addr("0100249b"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth - 10", cb.getCurrentFieldText());

		cb.goToField(addr("010024a3"), "Address", 0, 0);
		assertEquals(true,
			setStackDepthChangeAction.isEnabledForContext(cb.getProvider().getActionContext(null)));
		setStackDepthChange("0x1a");
		assertEquals(26, (int) CallDepthChangeInfo.getStackDepthChange(program, addr("010024a3")));
		cb.goToField(addr("0x10024a3"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth + 26", cb.getCurrentFieldText());

		cb.goToField(addr("01002493"), "Address", 0, 0);
		assertEquals(true,
			setStackDepthChangeAction.isEnabledForContext(cb.getProvider().getActionContext(null)));
		setStackDepthChange("-33");
		assertEquals(-33, (int) CallDepthChangeInfo.getStackDepthChange(program, addr("01002493")));
		cb.goToField(addr("0x1002493"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth - 33", cb.getCurrentFieldText());
	}

	@Test
	public void testSetStackDepthChangeActionAtCall() throws Exception {
		env.showTool();
		loadProgram("notepad");

		cb.goToField(addr("010022e6"), "Address", 0, 0); // 10022e6 is Call to 1002cf5
		assertEquals(true,
			setStackDepthChangeAction.isEnabledForContext(cb.getProvider().getActionContext(null)));
		checkFunctionPurge("01002cf5", -20);

		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		NumberInputDialog dialog = waitForStackDepthChange();
		JTextField textField = getTextField(dialog);
		triggerText(textField, "-0x8");
		pressButtonByText(dialog, "OK", false);

		DialogComponentProvider provider =
			waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		assertNotNull("Could not find Option Dialog", provider);
		pressButtonByText(provider.getComponent(), "Local", true);
		waitForBusyTool(tool);
		waitForSwing();

		checkFunctionPurge("01002cf5", -20);

		assertEquals(-8, (int) CallDepthChangeInfo.getStackDepthChange(program, addr("010022e6")));
		cb.goToField(addr("0x10022e6"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth - 8", cb.getCurrentFieldText());

		// Now Set the Function Purge instead.

		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		NumberInputDialog dialog2 = waitForStackDepthChange();
		textField = getTextField(dialog2);
		triggerText(textField, "-0xc");
		pressButtonByText(dialog2, "OK", false);

		DialogComponentProvider provider2 =
			waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		pressButtonByText(provider2.getComponent(), "Global", true);
		waitForBusyTool(tool);
		waitForSwing();
		assertNull("Shouldn't have found a stack depth @ 010022e6.",
			CallDepthChangeInfo.getStackDepthChange(program, addr("010022e6")));

		assertEquals(false, cb.goToField(addr("0x10022e6"), "Register Transition", 0, 0));

		checkFunctionPurge("01002cf5", -12);
	}

	@Test
	public void testSetStackDepthChangeDefaultInDialog() throws Exception {
		env.showTool();
		loadProgram("notepad");

		cb.goToField(addr("010022e6"), "Address", 0, 0); // 10022e6 is Call to 1002cf5
		assertEquals(true,
			setStackDepthChangeAction.isEnabledForContext(cb.getProvider().getActionContext(null)));

		checkFunctionPurge("01002cf5", -20);

		// Should default to function purge since no stack depth and is a call.
		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		NumberInputDialog dialog = waitForStackDepthChange();
		IntegerTextField field = (IntegerTextField) getInstanceField("numberInputField", dialog);
		assertEquals(20, field.getIntValue());

		// Set the stack depth change.

		JTextField textField = getTextField(dialog);
		triggerText(textField, "-0x8");
		pressButtonByText(dialog, "OK", false);

		DialogComponentProvider provider =
			waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		pressButtonByText(provider.getComponent(), "Local", true);
		waitForBusyTool(tool);
		waitForSwing();

		checkFunctionPurge("01002cf5", -20);

		assertEquals(-8, (int) CallDepthChangeInfo.getStackDepthChange(program, addr("010022e6")));
		cb.goToField(addr("0x10022e6"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth - 8", cb.getCurrentFieldText());

		// Now the stack depth is set.
		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		dialog = waitForStackDepthChange();
		field = (IntegerTextField) getInstanceField("numberInputField", dialog);
		assertEquals(-8, field.getIntValue());

		textField = getTextField(dialog);
		triggerText(textField, "-0xc");
		pressButtonByText(dialog, "OK", false);

		// Set the Function Purge instead.
		DialogComponentProvider provider2 =
			waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		pressButtonByText(provider2.getComponent(), "Global", true);
		waitForBusyTool(tool);
		waitForSwing();

		assertNull("Shouldn't have found a stack depth @ 010022e6.",
			CallDepthChangeInfo.getStackDepthChange(program, addr("010022e6")));

		assertEquals(false, cb.goToField(addr("0x10022e6"), "Register Transition", 0, 0));

		checkFunctionPurge("01002cf5", -12);

		//Default should still be stack depth change value.
		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		dialog = waitForStackDepthChange();
		field = (IntegerTextField) getInstanceField("numberInputField", dialog);
		assertEquals(12, field.getIntValue());
		pressButtonByText(dialog, "Cancel", false);
	}

	@Test
	public void testRemoveStackDepthChangeAction() throws Exception {
		env.showTool();
		loadProgram("notepad");
		int id = -1;
		try {
			id = program.startTransaction("Adding stack depth changes.");
			CallDepthChangeInfo.setStackDepthChange(program, addr("01002493"), 16);
			CallDepthChangeInfo.setStackDepthChange(program, addr("0100249b"), -10);
		}
		finally {
			if (id >= 0) {
				program.endTransaction(id, true);
			}
		}
		cb.goToField(addr("0x1002493"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth + 16", cb.getCurrentFieldText());
		cb.goToField(addr("0100249b"), "Register Transition", 0, 0);
		assertEquals("StackDepth = StackDepth - 10", cb.getCurrentFieldText());

		cb.goToField(addr("010024a3"), "Address", 0, 0);
		assertEquals(false, removeStackDepthChangeAction.isEnabledForContext(
			cb.getProvider().getActionContext(null)));

		cb.goToField(addr("01002493"), "Register Transition", 0, 0);
		assertEquals(true, removeStackDepthChangeAction.isEnabledForContext(
			cb.getProvider().getActionContext(null)));
		performAction(removeStackDepthChangeAction, cb.getProvider(), true);
		assertNull("Shouldn't have found a stack depth @ 01002493.",
			CallDepthChangeInfo.getStackDepthChange(program, addr("01002493")));

		assertEquals(false, cb.goToField(addr("0x1002493"), "Register Transition", 0, 0));
	}

	@Test
	public void testCancelStackDepthChangeActionFromSetDialog() throws Exception {
		env.showTool();
		loadProgram("notepad");

		assertEquals(false, cb.goToField(addr("0x10024a3"), "Register Transition", 0, 0));
		cb.goToField(addr("010024a3"), "Address", 0, 0);
		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		NumberInputDialog dialog = waitForStackDepthChange();
		JButton cancelButton = findButtonByText(dialog, "Cancel");
		assertEquals(true, cancelButton.isEnabled());
		pressButtonByText(dialog, "Cancel", true);
		waitForBusyTool();
		waitForSwing();
		assertEquals(false, cb.goToField(addr("0x10024a3"), "Register Transition", 0, 0));
	}

	private void setStackDepthChange(String stackDepthChangeValue) throws Exception {
		performAction(setStackDepthChangeAction, cb.getProvider(), false);
		NumberInputDialog dialog = waitForStackDepthChange();
		JTextField textField = getTextField(dialog);
		triggerText(textField, stackDepthChangeValue);
		pressButtonByText(dialog, "OK", true);
		waitForBusyTool();
	}

	private JTextField getTextField(NumberInputDialog dialog) {
		IntegerTextField field = (IntegerTextField) getInstanceField("numberInputField", dialog);
		JTextField textField = (JTextField) getInstanceField("textField", field);
		return textField;
	}

	private NumberInputDialog waitForStackDepthChange() {
		NumberInputDialog dialog =
			waitForDialogComponent(tool.getToolFrame(), NumberInputDialog.class, 2000);
		assertNotNull(dialog);
		Component inputField = findComponent(dialog, JTextField.class);
		assertNotNull(inputField);
		return dialog;
	}

	private void checkFunctionPurge(String addressString, int functionPurgeValue) {
		Address addr = addr(addressString);
		Function f = program.getFunctionManager().getFunctionAt(addr);
		assertNotNull("Didn't find expected function at " + addressString, f);
		assertEquals("Unexpected function purge at " + addressString, functionPurgeValue,
			f.getStackPurgeSize());
	}

	private void waitForBusyTool() {
		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();
		cb.updateNow();
	}
}
