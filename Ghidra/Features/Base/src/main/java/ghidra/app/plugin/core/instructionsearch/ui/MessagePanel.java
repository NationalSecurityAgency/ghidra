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

import java.awt.Color;
import java.awt.FlowLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.widgets.label.GDLabel;

/**
 * Simple panel containing a JLabel for displaying error messages.
 * 
 */
public class MessagePanel extends JPanel {

	private JLabel msgLabel;
	private final String NO_STATUS = " ";

	/**
	 * Constructor.
	 */
	public MessagePanel() {
		setLayout(new FlowLayout(FlowLayout.CENTER));
		msgLabel = new GDLabel(NO_STATUS);
		add(msgLabel);
	}

	/**
	 * Sets the text to be displayed.
	 * 
	 * @param text the new non-html text
	 * @param foregroundColor the text color
	 */
	public void setMessageText(String text, Color foregroundColor) {
		msgLabel.setForeground(foregroundColor);
		msgLabel.setText(text);
	}

	/**
	 * Removes message text from the display.
	 */
	public void clear() {
		msgLabel.setText(NO_STATUS);
	}

	public String getMessageText() {
		return msgLabel.getText();
	}
}
