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
package help.screenshot;

import java.math.BigInteger;

import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.plugin.core.register.*;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;

public class RegisterPluginScreenShots extends GhidraScreenShotGenerator {

	private RegisterPlugin plugin;

	public RegisterPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		plugin = getPlugin(tool, RegisterPlugin.class);
	}

	@Test
	public void testRegisterManager() {

		set("EAX", addr(0x401000), addr(0x401013), 0x23);
		set("EAX", addr(0x401c37), addr(0x401c5a), 0x56);

		showProvider(RegisterManagerProvider.class);
		selectProviderRegister("EAX");

		captureIsolatedProvider(RegisterManagerProvider.class, 700, 500);
	}

	@Test
	public void testEditRegisterValueRange() {
		String reg = "EDI";
		set(reg, addr(0x401c5b), addr(0x401c6a), 0x343);

		showProvider(RegisterManagerProvider.class);
		selectProviderRegister(reg);

		editRow(0);

		captureDialog();
	}

	@Test
	public void testSetRegisterValues() {
		goToListing(0x401cbd, OperandFieldFactory.FIELD_NAME, true);

		AddressSet addrs = new AddressSet();
		addrs.addRange(addr(0x401c9c), addr(0x401c9e));
		addrs.addRange(addr(0x401ca8), addr(0x401cab));
		addrs.addRange(addr(0x401cbd), addr(0x401cc1));
		makeSelection(addrs);

		DockingActionIf setAction = getAction(plugin, "Set Register Values");
		performAction(setAction, false);

		captureDialog(700, 300);
	}

	@Test
	public void testClearRegisterValues() {
		go(0x401c5b);

		DockingActionIf setAction = getAction(plugin, "Clear Register Values");
		performAction(setAction, false);

		captureDialog(700, 300);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void editRow(final int row) {
		RegisterManagerProvider provider = getProvider(RegisterManagerProvider.class);

		final Object registerValuesPanel = getInstanceField("values", provider);
		runSwing(() -> {
			//@formatter:off
			invokeInstanceMethod(
				"editRow",
				registerValuesPanel,
				new Class[] {int.class},
				new Object[] {row});
			//@formatter:on
		}, false);
	}

	private void set(String registerName, Address start, Address end, int value) {
		Register register = program.getRegister(registerName);
		SetRegisterCmd regCmd = new SetRegisterCmd(register, start, end, BigInteger.valueOf(value));
		tool.execute(regCmd, program);
		waitForBusyTool(tool);
	}

	private void selectProviderRegister(String registerName) {
		RegisterManagerProvider provider = getProvider(RegisterManagerProvider.class);
		RegisterTree tree = (RegisterTree) getInstanceField("tree", provider);
		Register register = program.getRegister(registerName);
		tree.selectRegister(register);
		waitForTree(tree);
	}

}
