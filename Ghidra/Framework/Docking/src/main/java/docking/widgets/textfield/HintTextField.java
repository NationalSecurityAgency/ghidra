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
package docking.widgets.textfield;

import java.awt.*;

import javax.swing.InputVerifier;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Simple text field that shows a text hint when the field is empty.
 *
 * <P> Hint text will be shown in light grey. Normal text will be plain black.
 */
public class HintTextField extends JTextField {

	// Verifier for the input field. This may be supplied by the user or left null.
	private InputVerifier verifier;

	// If true, the field will be rendered with a background to indicate as much.
	private boolean required;

	// Text that will show in the field when it is empty; intended to provide the user
	// some indication of what the field should contain.
	private String hint;

	private Color INVALID_COLOR = new Color(255, 225, 225);
	private Color VALID_COLOR = Color.WHITE;
	private Color defaultBackgroundColor;

	/**
	 * Constructor
	 *
	 * @param hint the hint text
	 */
	public HintTextField(String hint) {
		this(hint, false, null);
	}

	/**
	 * Constructor
	 *
	 * @param hint the hint text
	 * @param required true if the field should be marked as required
	 */
	public HintTextField(String hint, boolean required) {
		this(hint, required, null);
	}

	/**
	 * Constructor
	 * 
	 * @param hint the hint text
	 * @param required true, if the field should be marked as required
	 * @param verifier input verifier, or null if none needed
	 */
	public HintTextField(String hint, boolean required, InputVerifier verifier) {
		this.hint = hint;
		this.required = required;
		this.verifier = verifier;
		addListeners();
		setAttributes();
		validateField();
	}

	/**
	 * Key listener allows us to check field validity on every key typed
	 */
	public void addListeners() {

		getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				validateField();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				validateField();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				// do nothing
			}
		});
	}

	/**
	 *Overridden to check the field validity when text changes
	 *
	 * @param text the text to fill
	 */
	@Override
	public void setText(String text) {
		super.setText(text);
		validateField();
	}

	/**
	 * Overridden to paint the hint text over the field when it's empty
	 */
	@Override
	public void paintComponent(Graphics g) {
		super.paintComponent(g);

		if (!getText().isEmpty() || hint == null) {
			return;
		}

		Graphics2D g2 = (Graphics2D) g;
		g2.setColor(Color.LIGHT_GRAY);
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
			RenderingHints.VALUE_ANTIALIAS_ON);

		Dimension size = getSize();
		Insets insets = getInsets();
		int x = 10; // offset
		int y = size.height - insets.bottom - 1;
		g2.drawString(hint, x, y);
	}

	/**
	 * Sets whether the field is required or not. If so, it will be rendered
	 * differently to indicate that to the user.
	 * 
	 * @param required true if required, false otherwise
	 */
	public void setRequired(boolean required) {
		this.required = required;
	}

	/**
	 * Allows users to override the background color used by this field when the contents are
	 * valid.  The invalid color is currently set by this class.
	 * @param color the color
	 */
	public void setDefaultBackgroundColor(Color color) {
		this.defaultBackgroundColor = color;
	}

	/**
	 * Returns true if the field contains valid input.
	 * 
	 * @return true if valid, false otherwise
	 */
	public boolean isFieldValid() {
		if (required && getText().isEmpty()) {
			return false;
		}

		if (verifier != null) {
			if (!verifier.verify(this)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Sets font/color attributes for the field.
	 */
	private void setAttributes() {
		setFont(getFont().deriveFont(Font.PLAIN));
		setForeground(Color.BLACK);
	}

	/**
	 * Checks the validity of the field and sets the appropriate 
	 * field attributes.
	 */
	private void validateField() {
		if (isFieldValid()) {
			setBackground(defaultBackgroundColor == null ? VALID_COLOR : defaultBackgroundColor);
		}
		else {
			setBackground(INVALID_COLOR);
		}
	}
}
