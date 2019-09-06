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

import java.awt.Cursor;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.cmd.memory.MoveBlockListener;
import ghidra.app.cmd.memory.MoveBlockTask;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskBuilder;

/**
 * Dialog that uses a model to validate the fields for moving a block of memory.
 * 
 * 
 */
public class MoveBlockDialog extends DialogComponentProvider implements MoveBlockListener {
	private JLabel origStartLabel;
	private JLabel origEndLabel;
	private JLabel lengthLabel;
	private JLabel blockNameLabel;
	private AddressInput newStartField;
	private AddressInput newEndField;
	private boolean changing;
	private MoveBlockModel model;
	private PluginTool tool;

	MoveBlockDialog(MoveBlockModel model, PluginTool tool) {
		super("Move Memory Block");
		this.model = model;
		this.tool = tool;
		setHelpLocation(new HelpLocation(HelpTopics.MEMORY_MAP, "Move Block"));
		model.setMoveBlockListener(this);
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	@Override
	public void moveBlockCompleted(MoveBlockTask task) {

		setCursor(Cursor.getDefaultCursor());
		boolean success = task.wasSuccessful();
		setOkEnabled(success);
		setStatusText(task.getStatusMessage());

		Swing.runLater(() -> {
			if (success) {
				close();
				model.dispose();
			}
		});
	}

	@Override
	public void stateChanged() {
		setOkEnabled(false);
		changing = true;
		if (!isVisible()) {
			AddressFactory factory = model.getAddressFactory();
			newStartField.setAddressFactory(factory, true, false);
			newEndField.setAddressFactory(factory, true, false);
		}
		Address newStart = model.getNewStartAddress();
		if (newStart != null) {
			if (!newStart.equals(newStartField.getAddress())) {
				newStartField.setAddress(newStart);
			}
		}
		Address newEnd = model.getNewEndAddress();
		if (newEnd != null) {
			if (!newEnd.equals(newEndField.getAddress())) {
				newEndField.setAddress(newEnd);
			}
		}
		changing = false;
		String message = model.getMessage();
		setStatusText(message);

		if (!isVisible()) {
			blockNameLabel.setText(model.getName());
			origStartLabel.setText(model.getStartAddress().toString());
			origEndLabel.setText(model.getEndAddress().toString());
			lengthLabel.setText(model.getLengthString());
			tool.showDialog(this, tool.getComponentProvider(PluginConstants.MEMORY_MAP));
		}
		else if (message.length() == 0) {
			setOkEnabled(true);
		}
	}

	@Override
	protected void okCallback() {
		setOkEnabled(false);
		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

		MoveBlockTask task = model.makeTask();

		//@formatter:off		
		TaskBuilder.withTask(task)
			.setParent(this.getComponent())
			.launchModal()
			;
		//@formatter:on
	}

	@Override
	protected void cancelCallback() {
		close();
		model.dispose();
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 20, 150));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		blockNameLabel = new GDLabel(".text");
		blockNameLabel.setName("blockName"); // name components for junits

		origStartLabel = new GDLabel("1001000");
		origStartLabel.setName("origStart");

		origEndLabel = new GDLabel("1002000");
		origEndLabel.setName("origEnd");

		lengthLabel = new GDLabel("4096 (0x1000)");
		lengthLabel.setName("length");

		newStartField = new AddressInput();
		newStartField.setName("newStart");

		newEndField = new AddressInput();
		newEndField.setName("newEnd");

		newStartField.addChangeListener(e -> startChanged());
		newEndField.addChangeListener(e -> endChanged());

		panel.add(new GLabel("Name:", SwingConstants.RIGHT));
		panel.add(blockNameLabel);
		panel.add(new GLabel("Start Address:", SwingConstants.RIGHT));
		panel.add(origStartLabel);
		panel.add(new GLabel("End Address:", SwingConstants.RIGHT));
		panel.add(origEndLabel);
		panel.add(new GLabel("Length:", SwingConstants.RIGHT));
		panel.add(lengthLabel);
		panel.add(new GLabel("New Start Address:", SwingConstants.RIGHT));
		panel.add(newStartField);
		panel.add(new GLabel("New End Address:", SwingConstants.RIGHT));
		panel.add(newEndField);
		return panel;
	}

	private void startChanged() {
		if (changing) {
			return;
		}
		Address newStart = newStartField.getAddress();
		if (newStart != null) {
			model.setNewStartAddress(newStart);
		}
		else {
			setStatusText("Invalid Address");
			setOkEnabled(false);
		}
	}

	private void endChanged() {
		if (changing) {
			return;
		}
		Address newEnd = newEndField.getAddress();
		if (newEnd != null) {
			model.setNewEndAddress(newEnd);
		}
		else {
			setStatusText("Invalid Address");
			setOkEnabled(false);
		}
	}
}
