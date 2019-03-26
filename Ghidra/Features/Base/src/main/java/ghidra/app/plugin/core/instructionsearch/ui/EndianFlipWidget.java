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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

import javax.swing.JButton;
import javax.swing.JPanel;

import ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;

/**
 * Flips the endianness of the user input, whether in binary or hex mode.
 * 
 * Note that this class does not care whether the input is big or little endian; it just flips
 * the bytes and leaves the interpretation up to the user.
 */
public class EndianFlipWidget extends ControlPanelWidget {

	private InsertBytesWidget parent;

	/**
	 * Constructor.
	 * 
	 * @param plugin
	 * @param title
	 * @param parent
	 */
	public EndianFlipWidget( String title,
			InsertBytesWidget parent) {
		super(title);
		this.parent = parent;
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	/**
	 * The only thing in this widget is a button that does the flipping.
	 * 
	 * @return
	 */
	@Override
	protected JPanel createContent() {

		JPanel mainPanel = new JPanel();
		JButton flipEndiannessBtn = new JButton("flip");
		mainPanel.add(flipEndiannessBtn);

		flipEndiannessBtn.addActionListener(new EndianFlipper());

		return mainPanel;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Returns the given string as a list of byte strings. 
	 * 
	 * @param token the string the parse
	 * @param tokenLength the length of a byte (2 for hex, 8 for binary)
	 * @return
	 */
	private List<String> getByteStrings(String token, int byteLength) {

		int n = token.length() / byteLength;
		List<String> list = new ArrayList<String>(n);

		for (int i = 0; i < n; i++) {
			list.add(token.substring(i * byteLength, i * byteLength + byteLength));
		}
		return list;
	}

	/**
	 * Event handler for the flip button.
	 */
	private class EndianFlipper implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {

			// Get the input text and separate into groups (spaces are the delimiter), removing
			// any leading or trailing spaces.
			String[] groups = parent.getInputString().trim().split("\\s+");

			// Now get all of the whitespace in the input string. We do this so we can
			// restore the spacing from the original string when reconstructing.  We don't want
			// to have the input be "01 AF    10 01" and return "01 AF 10 01"; we want to return
			// "01 AF    10 01".
			List<String> whitespaces = InstructionSearchUtils.getWhitespace(parent.getInputString().trim());

			// Now validate each group to make sure they:
			// 1. have the proper input format (hex or binary)
			// 2. are the proper length for the input type (full bytes only)
			for (String str : groups) {
				if (!parent.validateInput(str)) {
					parent.showError();
					return;
				}
			}

			// Now determine if we're looking at hex or binary data, and set the byte length
			// as appropriate. This is used later on when getting the byte strings.
			int byteLength = 0;
			if (parent.getSelectionModeWidget().getInputMode() == InputMode.HEX) {
				byteLength = 2;
			}
			else if (parent.getSelectionModeWidget().getInputMode() == InputMode.BINARY) {
				byteLength = 8;
			}

			// Do a quick sanity check on the number of groups and the number of whitespaces
			// we have.  We should always have one more group than whitespaces (even if we had
			// spaces at the beginning or end of the input, we trimmed those out already).
			if (groups.length != whitespaces.size() + 1) {
				return;
			}

			// Finally, loop over all the groups, flipping each one in turn and reconstructing
			// the string at the end.
			StringBuilder mainString = new StringBuilder();
			int whitespaceIndex = 0;
			for (String str : groups) {

				// Break up the input string into a list of bytes that we can reverse, and 
				// reverse them.
				List<String> input = getByteStrings(str, byteLength);
				Collections.reverse(input);

				// Convert the list back into a string and append to the main string.
				for (String s : input) {
					mainString.append(s);
				}

				// Finally add the proper number of whitespace after this group.
				if (whitespaceIndex < whitespaces.size()) {
					mainString.append(whitespaces.get(whitespaceIndex));
					whitespaceIndex++;
				}
			}

			// Show the new string in the text area.
			parent.setInputString(mainString.toString());

		}

	}
}
