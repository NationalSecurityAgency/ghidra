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
package ghidra.app.plugin.core.disassembler;

import java.awt.Color;
import java.awt.Font;

import javax.swing.JTextField;

/**
 * Allows users to provide a text hint in a text field, shown only when the text is empty.
 *
 * Hint text will be shown in light grey, italicised, and in angle brackets.  Normal text will
 * be plain black.
 */
public class HintTextField extends JTextField {
	private String hint;
	private Color cForeground;
	private Color cHint;

	public HintTextField(int cols) {
		super(cols);
	}

	public void setHintText(String s) {
		this.hint = s;
	}

	public void showHint() {
		this.setText("");
	}

	@Override
	public void setText(String text) {

		if (text != null && text.isEmpty()) {
			setHintAttributes();
			super.setText("<" + hint + ">");
		}
		else {
			setPlainAttributes();
			super.setText(text);
		}
	}

	/**
	 * Sets the text attributes to be used when NOT viewing the hint.
	 */
	private void setPlainAttributes() {
		this.setFont(getFont().deriveFont(Font.PLAIN));
		setForeground(Color.BLACK);
	}

	/**
	 * Sets the text attributes to be used when viewing the hint.
	 */
	private void setHintAttributes() {
		cForeground = getForeground();

		if (cHint == null) {
			cHint = new Color(cForeground.getRed(), cForeground.getGreen(), cForeground.getBlue(),
				cForeground.getAlpha() / 2);
		}
		setForeground(cHint);

		this.setFont(getFont().deriveFont(Font.ITALIC));
	}
}
