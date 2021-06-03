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

import static org.junit.Assert.*;

import java.awt.Window;

import org.junit.Test;

import docking.ComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import generic.test.TestUtils;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.navigation.GoToAddressLabelDialog;
import ghidra.program.model.address.Address;
import ghidra.util.table.GhidraProgramTableModel;

public class NavigationScreenShots extends GhidraScreenShotGenerator {

	public NavigationScreenShots() {
		super();
	}

	@Test
	public void testGoToDialog() {

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);

		captureDialog();
	}

	@Test
	public void testGoto_Ambiguous() {

		//add fake memory blocks to mimic a multiple address space program
		tool.execute(new AddInitializedMemoryBlockCmd("CODE", "comments", "test1", addr(0), 0x100,
			true, true, true, false, (byte) 0x69, true), program);
		tool.execute(new AddUninitializedMemoryBlockCmd("INTMEM", "comments", "test2", addr(0),
			0x100, true, true, true, false, false), program);
		tool.execute(new AddInitializedMemoryBlockCmd("DUMMY", "comments", "test3", addr(20), 0x100,
			true, true, true, false, (byte) 1, true), program);

		// go to an address outside the blocks that will be displayed
		goToAddress(program.getMemory().getBlock("DUMMY").getStart());

		// goto address 5
		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		GoToAddressLabelDialog dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "5");
		pressOkOnDialog();
		waitForSwing();

		ComponentProvider provider = getProvider("Goto");
		captureIsolatedProvider(provider.getClass(), 475, 275);
	}

	@Test
	public void testGoto_Wildcard() throws Exception {

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		GoToAddressLabelDialog dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "FUN_004081?d");
		pressOkOnDialog();
		waitForSwing();
		waitForModel();

		ComponentProvider provider = getProvider("Goto");
		captureIsolatedProvider(provider.getClass(), 500, 275);
	}

	@Test
	public void testGoto_PreviousList() throws Exception {

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		GoToAddressLabelDialog dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "FUN_004081?d");
		pressOkOnDialog();
		waitForSwing();
		waitForModel();

		waitForSwing();

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "5");
		pressOkOnDialog();
		waitForSwing();
		waitForModel();

		waitForSwing();

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "FUN*");
		pressOkOnDialog();
		waitForSwing();
		waitForModel();

		waitForSwing();

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "40344d");
		pressOkOnDialog();
		waitForSwing();
		waitForModel();

		waitForSwing();

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "entry");
		pressOkOnDialog();
		waitForSwing();
		waitForModel();

		waitForSwing();

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		dialog = (GoToAddressLabelDialog) getDialog();
		setGotoText(dialog, "LAB*");
		pressOkOnDialog();
		Window window =
			waitForWindowByTitleContaining("Search Limit Exceeded!");
		assertNotNull(window);
		pressButtonByText(window, "OK");
		waitForSwing();
		waitForModel();

		waitForSwing();

		performAction("Go To Address/Label", "GoToAddressLabelPlugin", false);
		dialog = (GoToAddressLabelDialog) getDialog();
		GhidraComboBox comboBox = (GhidraComboBox) getInstanceField("comboBox", dialog);
		setPullDownItem(comboBox, 2);

		captureDialog();
	}

	private void setPullDownItem(final GhidraComboBox comboBox, final int index) {

		runSwing(() -> {
			comboBox.setEnabled(true);
			comboBox.setSelectedIndex(1);
			comboBox.showPopup();
		});
	}

	private void setGotoText(final GoToAddressLabelDialog dialog, final String text) {

		runSwing(() -> dialog.setText(text));
	}

	private void goToAddress(final Address address) {
		GoToServicePlugin goToPlugin = env.getPlugin(GoToServicePlugin.class);
		final GoToService goToService;
		goToService = (GoToService) invokeInstanceMethod("getGotoService", goToPlugin);
		runSwing(() -> goToService.goTo(address));
	}

	private GhidraProgramTableModel<?> waitForModel() throws Exception {
		int i = 0;
		while (i++ < 50) {
			TableComponentProvider<?>[] providers = getProviders();
			if (providers.length > 0) {
				GThreadedTablePanel<?> panel =
					(GThreadedTablePanel<?>) TestUtils.getInstanceField("threadedPanel",
						providers[0]);
				GTable table = panel.getTable();
				while (panel.isBusy()) {
					Thread.sleep(50);
				}
				return (GhidraProgramTableModel<?>) table.getModel();
			}
			Thread.sleep(50);
		}
		throw new Exception("Unable to get threaded table model");
	}

	private TableComponentProvider<?>[] getProviders() {
		TableServicePlugin tableServicePlugin = getPlugin(tool, TableServicePlugin.class);
		return tableServicePlugin.getManagedComponents();
	}
}
