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
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import ghidra.app.cmd.memory.MoveBlockListener;
import ghidra.app.cmd.memory.MoveBlockTask;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitorAdapter;

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

	/**
	 * Constructor for MoveBlockDialog.
	 * 
	 * @param dialog
	 * @param title
	 * @param modal
	 * @param includeStatus
	 * @param includeButtons
	 */
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

	/**
	 * @see ghidra.app.plugin.contrib.memory.MoveBlockListener#moveBlockCompleted(boolean,
	 *      java.lang.String)
	 */
	@Override
	public void moveBlockCompleted(final MoveBlockTask cmd) {
		Runnable r = new Runnable() {
			@Override
			public void run() {
				if (cmd.getStatus()) {
					close();
					model.dispose();
				}
				else {
					setCursor(Cursor.getDefaultCursor());
					setOkEnabled(false);
					if (cmd.isCancelled()) {
						tool.setStatusInfo(getStatusText());
						close();
						model.dispose();
					}
				}
			}
		};
		SwingUtilities.invokeLater(r);
	}

	/**
	 * @see ghidra.app.plugin.contrib.memory.MoveBlockListener#stateChanged()
	 */
	@Override
	public void stateChanged() {
		setOkEnabled(false);
		changing = true;
		if (!isVisible()) {
			AddressFactory factory = model.getAddressFactory();
			newStartField.setAddressFactory(factory, true);
			newEndField.setAddressFactory(factory, true);
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
		new TaskLauncher(model.makeTask(), new TaskMonitorAdapter() {
			@Override
			public void setMessage(String message) {
				setStatusText(message);
			}
		});
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 20, 150));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		blockNameLabel = new JLabel(".text");
		blockNameLabel.setName("blockName"); // name components for junits

		origStartLabel = new JLabel("1001000");
		origStartLabel.setName("origStart");

		origEndLabel = new JLabel("1002000");
		origEndLabel.setName("origEnd");

		lengthLabel = new JLabel("4096 (0x1000)");
		lengthLabel.setName("length");

		newStartField = new AddressInput();
		newStartField.setName("newStart");

		newEndField = new AddressInput();
		newEndField.setName("newEnd");

		newStartField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				startChanged();
			}
		});
		newEndField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				endChanged();
			}
		});

		panel.add(new JLabel("Name:", SwingConstants.RIGHT));
		panel.add(blockNameLabel);
		panel.add(new JLabel("Start Address:", SwingConstants.RIGHT));
		panel.add(origStartLabel);
		panel.add(new JLabel("End Address:", SwingConstants.RIGHT));
		panel.add(origEndLabel);
		panel.add(new JLabel("Length:", SwingConstants.RIGHT));
		panel.add(lengthLabel);
		panel.add(new JLabel("New Start Address:", SwingConstants.RIGHT));
		panel.add(newStartField);
		panel.add(new JLabel("New End Address:", SwingConstants.RIGHT));
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
