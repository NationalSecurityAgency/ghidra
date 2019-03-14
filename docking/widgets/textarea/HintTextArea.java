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
package docking.widgets.textarea;

import java.awt.*;

import javax.swing.JTextArea;

/**
 * Simple text area that shows a text hint when the field is empty. 
 * 
 * Hint text will be shown in light grey, italicized, and in angle brackets.  Normal text will
 * be plain black.
 */
public class HintTextArea extends JTextArea {

	private String hint;

	/**
	 * Constructs the class with the hint text to be shown.
	 * 
	 * @param hint
	 */
	public HintTextArea(final String hint) {
		this.hint = hint;
	}

	/**
	 * Need to override the setText method so we can set font attributes.
	 * 
	 * @param text
	 */
	@Override
	public void setText(String text) {
		super.setText(text);
		setAttributes();
	}

	@Override
	public void paintComponent(Graphics g) {
		super.paintComponent(g);

		if (getText().isEmpty()) {
			if (g instanceof Graphics2D) {
				Graphics2D g2 = (Graphics2D) g;
				g2.setColor(Color.gray);
				g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);

				if (hint != null) {
					g2.drawString(hint, 5, 12);
				}
			}
		}
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Sets the text attributes to be used when NOT viewing the hint.
	 */
	protected void setAttributes() {
		this.setFont(getFont().deriveFont(Font.PLAIN));
		setForeground(Color.BLACK);
	}

}
