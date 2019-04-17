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

import java.util.*;

import javax.swing.*;

import org.junit.Test;

import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.plugin.core.label.*;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.EditFieldNameDialog;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.LabelHistory;

public class LabelMgrPluginScreenShots extends GhidraScreenShotGenerator {

	public LabelMgrPluginScreenShots() {
		super();
	}

	@Test
	public void testAddLabel() {
		final AddEditDialog dialog = new AddEditDialog("Edit Label at 100122591", tool);
		runSwing(new Runnable() {
			@Override
			public void run() {
				JComboBox combo = (JComboBox) getInstanceField("labelNameChoices", dialog);
				combo.setSelectedItem("reset");
				combo = (JComboBox) getInstanceField("namespaceChoices", dialog);
				combo.addItem("MyFunction");
				combo.setSelectedItem("MyFunction");
				JCheckBox checkbox = (JCheckBox) getInstanceField("primaryCheckBox", dialog);
				checkbox.setSelected(true);
				checkbox.setEnabled(false);
			}
		});
		showDialogWithoutBlocking(tool, dialog);
		captureDialog();
	}

	@Test
	public void testEditFieldNameDialog() {
		EditFieldNameDialog dialog =
			new EditFieldNameDialog("Edit Field Name: struct.field2", tool);
		final JTextField textField = (JTextField) getInstanceField("fieldName", dialog);
		runSwing(new Runnable() {
			@Override
			public void run() {
				textField.setText("field2");
			}
		});
		showDialogWithoutBlocking(tool, dialog);
		captureDialog();
	}

	@Test
	public void testLabelHistoryInputDialog() {
		LabelHistoryInputDialog dialog = new LabelHistoryInputDialog(tool, null);
		showDialogWithoutBlocking(tool, dialog);
		captureDialog();
	}

	@Test
	public void testSetLabel() {
		LabelMgrPlugin plugin = getPlugin(tool, LabelMgrPlugin.class);
		final OperandLabelDialog dialog = new OperandLabelDialog(plugin);
		final GhidraComboBox combo = (GhidraComboBox) getInstanceField("myChoice", dialog);
		runSwing(new Runnable() {
			@Override
			public void run() {
				dialog.setTitle("Set Label at 004a671");
				combo.setSelectedItem("LAB_0040a671");
			}
		});
		showDialogWithoutBlocking(tool, dialog);
		captureDialog(350, 116);
	}

	@Test
	public void testShowLabelHistory() {
		AddressSpace space = new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 0);
		Address addr = space.getAddress(0x0040a671);
		List<LabelHistory> list = new ArrayList<LabelHistory>();
		list.add(new LabelHistory(addr, "User1", (byte) 0, "MyLabel", new Date()));
		list.add(new LabelHistory(addr, "User2", (byte) 2, "Bob to John", new Date()));
		list.add(new LabelHistory(addr, "User1", (byte) 1, "Phil", new Date()));
		LabelHistoryDialog dialog = new LabelHistoryDialog(tool, null, addr, list);

		showDialogWithoutBlocking(tool, dialog);
		captureDialog(600, 200);
	}
}
