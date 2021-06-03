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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.*;

import docking.widgets.button.GRadioButton;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.util.Msg;

/**
 * Allows the user to specify whether the input mode is BINARY or HEX for the {@link InsertBytesWidget}.
 */
public class SelectionModeWidget extends ControlPanelWidget {

	// Radio buttons that the user can set to specify the input type. 
	public JRadioButton hexRB, binaryRB;

	public static enum InputMode {
		BINARY, HEX
	}

	private InputMode inputMode = InputMode.HEX;

	InsertBytesWidget parent;

	/**
	 * Constructor.
	 * 
	 * @param plugin
	 * @param title
	 * @param parent
	 */
	public SelectionModeWidget(String title, InsertBytesWidget parent) {
		super(title);
		this.parent = parent;
	}

	/**
	 * 
	 * @return
	 */
	@Override
	protected JPanel createContent() {
		JPanel rbPanel = new JPanel();
		hexRB = new GRadioButton("hex");
		binaryRB = new GRadioButton("binary");
		ButtonGroup inputGroup = new ButtonGroup();
		inputGroup.add(hexRB);
		inputGroup.add(binaryRB);
		rbPanel.add(hexRB);
		rbPanel.add(binaryRB);
		hexRB.setSelected(true);

		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());
		mainPanel.add(rbPanel, BorderLayout.CENTER);

		hexRB.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				// If we're already in hex, do nothing.
				if (inputMode == InputMode.HEX) {
					return;
				}
				inputMode = InputMode.HEX;

				// CONVERSION
				// 1. Get the whitespace map so we can restore it after conversion.
				// 2. Get the group map so we can group bytes just as in the hex display.
				// 3. Convert and display.
				List<String> whitespaces =
					InstructionSearchUtils.getWhitespace(parent.getInputString().trim());

				List<Integer> groups;
				try {
					groups = InstructionSearchUtils.getGroupSizes(parent.getInputString().trim(),
						InputMode.BINARY);

					// Now convert whatever is in the input box to hex.				
					String hexStr =
						InstructionSearchUtils.toHex(parent.getInputString().trim(), true);

					// Restore grouping.
					hexStr =
						restoreGroupingAndWhitespace(hexStr, groups, whitespaces, InputMode.HEX);

					// Now convert whatever is in the input box to hex and display.
					parent.setInputString(hexStr);
					parent.validateInput();
				}
				catch (NumberFormatException e2) {
					parent.setInputInvalid();
				}
				catch (Exception e1) {
					Msg.error(this, e1.getMessage());
				}
			}

		});

		binaryRB.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				// If we're already in binary, do nothing.
				if (inputMode == InputMode.BINARY) {
					return;
				}

				inputMode = InputMode.BINARY;

				// CONVERSION
				// 1. Get the whitespace map so we can restore it after conversion.
				// 2. Get the group map so we can group bytes just as in the hex display.
				// 3. Convert and display.
				List<String> whitespaces =
					InstructionSearchUtils.getWhitespace(parent.getInputString().trim());

				List<Integer> groups;
				try {
					groups = InstructionSearchUtils.getGroupSizes(parent.getInputString().trim(),
						InputMode.HEX);

					// Now convert whatever is in the input box to binary.				
					String binaryStr =
						InstructionSearchUtils.toBinary(parent.getInputString().trim());

					// Restore grouping.
					binaryStr = restoreGroupingAndWhitespace(binaryStr, groups, whitespaces,
						InputMode.BINARY);

					parent.setInputString(binaryStr);
					parent.validateInput();
				}
				catch (NumberFormatException e2) {
					parent.setInputInvalid();
				}
				catch (Exception e1) {
					Msg.error(this, e1.getMessage());
				}

			}

		});

		return mainPanel;
	}

	/**
	 * 
	 * @return
	 */
	public InputMode getInputMode() {
		if (hexRB.isSelected()) {
			inputMode = InputMode.HEX;
		}
		else if (binaryRB.isSelected()) {
			inputMode = InputMode.BINARY;
		}

		return inputMode;
	}

	/**
	 * 
	 * @param mode
	 */
	public void setInputMode(InputMode mode) {
		inputMode = mode;

		if (mode == InputMode.BINARY) {
			binaryRB.setSelected(true);
		}
		else if (mode == InputMode.HEX) {
			hexRB.setSelected(true);
		}
	}

	/****************************************************************************************
	 * PRIVATE METHODS
	 ****************************************************************************************/

	/**
	 * Takes the given string and puts spaces on the boundaries defined by the groups passed
	 * in. 
	 * 
	 * eg: if the source is "AA BBBB CC DDDDDD" and the groups are {2, 1, 4}, and the
	 * whitespace list is {5, 1} the returned string will be "AABB     BB CCDDDDDD".
	 * 
	 * Note that the mode passed in determines how we interpret group sizes. If the mode is HEX
	 * then a group size of '2' will mean 4 characters (2 bytes), but if the mode is BINARY then
	 * we'll grab 16 characters for that group of 2.
	 *     
	 * @param source the input string
	 * @param groups the list of group sizes
	 * @param whitespace the list of whitespace strings
	 * @param mode binary or hex
	 */
	private String restoreGroupingAndWhitespace(String source, List<Integer> groups,
			List<String> whitespace, InputMode mode) {

		// First remove all whitespace.
		source = source.replaceAll("\\s", "");

		// Now set up the mode modifier.
		int modeModifier = (mode == InputMode.BINARY) ? 8 : 2;

		// Now set up a counter to track our position in the whitespace list.
		int whitespaceIndex = 0;

		// Now loop over all the groups, breaking up our source string and adding whitespaces.
		StringBuilder sb = new StringBuilder();
		for (Integer group : groups) {
			sb.append(source.substring(0, group * modeModifier));

			if (whitespaceIndex < whitespace.size()) {
				sb.append(whitespace.get(whitespaceIndex));
				whitespaceIndex++;
			}

			// And chop off the part of the string we just processed for the next iteration.
			source = source.substring(group * modeModifier);
		}

		return sb.toString();
	}
}
