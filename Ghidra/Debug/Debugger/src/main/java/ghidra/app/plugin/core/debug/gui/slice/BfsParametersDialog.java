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
package ghidra.app.plugin.core.debug.gui.slice;

import java.awt.GridLayout;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.MessageType;

/**
 * Dialog for configuring parameters for the backward slice BFS search.
 */
public class BfsParametersDialog extends DialogComponentProvider {

	private final JTextField regexField;
	private final JTextField maxHopsField;
	private final JTextField minSnapshotField;

	private boolean valid = false;
	private String regex = "SYSCALL"; // Default example
	private int maxHops = 100;
	private long minSnapshot = 0;

	public BfsParametersDialog() {
		super("Configure Search Parameters", true, true, true, false);

		regexField = new JTextField(20);
		maxHopsField = new JTextField(5);
		minSnapshotField = new JTextField(10);

		initializeComponents();
		addOKButton();
		addCancelButton();
	}

	private void initializeComponents() {
		JPanel panel = new JPanel(new GridLayout(0, 2, 5, 5));

		panel.add(new JLabel("Instruction/Data Mnemonic Regex:"));
		panel.add(regexField);

		panel.add(new JLabel("Maximum Hops/Edges to Search:"));
		panel.add(maxHopsField);

		panel.add(new JLabel("Minimum Snapshot Number (inclusive):"));
		panel.add(minSnapshotField);

		setDefaultValues();
		addWorkPanel(panel);
	}

	private void setDefaultValues() {
		regexField.setText(regex);
		maxHopsField.setText(Integer.toString(maxHops));
		minSnapshotField.setText(Long.toString(minSnapshot));
	}

	@Override
	protected void okCallback() {
		if (validateInput()) {
			saveValues();
			close();
		}
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	private boolean validateInput() {
		String regexText = regexField.getText().trim();
		String maxHopsText = maxHopsField.getText().trim();
		String minSnapshotText = minSnapshotField.getText().trim();

		if (regexText.isEmpty()) {
			setStatusText("Regex cannot be empty", MessageType.ERROR);
			return false;
		}

		try {
			Pattern.compile(regexText);
		}
		catch (PatternSyntaxException e) {
			setStatusText("Invalid regex: " + e.getMessage(), MessageType.ERROR);
			return false;
		}

		try {
			int hops = Integer.parseInt(maxHopsText);
			if (hops <= 0) {
				setStatusText("Maximum hops must be positive", MessageType.ERROR);
				return false;
			}
		}
		catch (NumberFormatException e) {
			setStatusText("Maximum hops must be a valid integer", MessageType.ERROR);
			return false;
		}

		try {
			long snapshot = Long.parseLong(minSnapshotText);
			if (snapshot < 0) {
				setStatusText("Minimum snapshot must be non-negative", MessageType.ERROR);
				return false;
			}
		}
		catch (NumberFormatException e) {
			setStatusText("Minimum snapshot must be a valid number", MessageType.ERROR);
			return false;
		}

		return true;
	}

	private void saveValues() {
		regex = regexField.getText().trim();
		maxHops = Integer.parseInt(maxHopsField.getText().trim());
		minSnapshot = Long.parseLong(minSnapshotField.getText().trim());
		valid = true;
	}

	public boolean isValid() {
		return valid;
	}

	public String getRegex() {
		return regex;
	}

	public int getMaxHops() {
		return maxHops;
	}

	public long getMinSnapshot() {
		return minSnapshot;
	}

	public void show(PluginTool tool) {
		setDefaultValues();
		tool.showDialog(this);
	}
}
