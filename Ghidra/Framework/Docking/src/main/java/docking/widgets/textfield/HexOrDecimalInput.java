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
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

import javax.swing.JTextField;
import javax.swing.text.*;

import docking.util.GraphicsUtils;

public class HexOrDecimalInput extends JTextField {
	private boolean isHexMode = false;
	private boolean allowsNegative = true;
	private Long currentValue;

	public HexOrDecimalInput() {
		this(null);
	}

	public HexOrDecimalInput(int columns) {
		super(columns);
		init(null);
	}

	public HexOrDecimalInput(Long initialValue) {
		init(initialValue);
	}

	private void init(Long initialValue) {
		currentValue = initialValue;
		setDocument(new MyDocument());
		updateText();
		setToolTipText("Press 'M' to toggle Hex or Decimal Mode");
		addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_M) {
					toggleMode();
					repaint();
				}
			}

		});
	}

	public Long getValue() {
		return currentValue;
	}

	public int getIntValue() {
		if (currentValue == null) {
			return 0;
		}
		return currentValue.intValue();
	}

	public void setValue(int newValue) {
		setValue((long) newValue);
	}

	public void setValue(Long newValue) {
		if (!allowsNegative && newValue != null && newValue.longValue() < 0) {
			currentValue = null;
		}
		currentValue = newValue;
		updateText();
	}

	private void toggleMode() {
		if (isHexMode) {
			setDecimalMode();
		}
		else {
			setHexMode();
		}
	}

	public void setHexMode() {
		isHexMode = true;
		updateText();
	}

	private void updateText() {
		setText(computeTextForCurrentValue());
	}

	private String computeTextForCurrentValue() {
		if (currentValue == null) {
			return "";
		}
		String stringValue;
		long value = currentValue;
		long absValue = value < 0 ? -value : value;
		if (isHexMode) {
			stringValue = Long.toHexString(absValue);
		}
		else {
			stringValue = Long.toString(absValue);
		}
		if (value < 0) {
			stringValue = "-" + stringValue;
		}
		return stringValue;
	}

	public void setDecimalMode() {
		isHexMode = false;
		updateText();
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		Font font = new Font("Monospaced", Font.PLAIN, 10);
		Font savedFont = g.getFont();
		g.setFont(font);
		g.setColor(Color.LIGHT_GRAY);
		FontMetrics fontMetrics = getFontMetrics(font);
		String mode = isHexMode ? "Hex" : "Dec";
		int stringWidth = fontMetrics.stringWidth(mode);
		Dimension size = getSize();
		Insets insets = getInsets();
		int x = size.width - insets.right - stringWidth;
		int y = size.height - insets.bottom;
		GraphicsUtils.drawString(this, g, mode, x, y);
		g.setFont(savedFont);
	}

	public void setAllowNegative(boolean b) {
		allowsNegative = b;
		if (!allowsNegative) {
			if (currentValue != null && currentValue.longValue() < 0) {
				currentValue = null;
			}
		}
		updateText();
	}

	private Long computeValueFromString(String text) {
		if (text.length() == 0) {
			return null;
		}

		boolean isNegative = false;
		long value = 0;
		if (text.startsWith("-")) {
			isNegative = true;
			text = text.substring(1);
		}
		if (isHexMode) {
			value = Long.parseUnsignedLong(text, 16);
		}
		else {
			value = Long.parseLong(text);
		}
		if (isNegative) {
			value = -value;
		}
		return value;
	}

	private class MyDocument extends PlainDocument {

		private MyDocument() {
			super();
		}

		/**
		 * @see javax.swing.text.Document#insertString(int, java.lang.String, javax.swing.text.AttributeSet)
		 */
		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
			if (str == null) {
				return;
			}
			if (!checkChars(str)) {
				return;
			}
			StringBuilder builder = new StringBuilder(HexOrDecimalInput.this.getText());
			builder.insert(offs, str);
			String newText = builder.toString();

			int lastIndexOf = newText.lastIndexOf('-');
			if (lastIndexOf > 0) {
				return;  // not allowed anywhere except at the start
			}

			if (!newText.equals("-")) {
				try {
					currentValue = computeValueFromString(newText);
				}
				catch (NumberFormatException e) {
					return;
				}
			}
			super.insertString(offs, str, a);
		}

		@Override
		public void remove(int offs, int len) throws BadLocationException {
			super.remove(offs, len);
			String newText = HexOrDecimalInput.this.getText();
			if (newText.length() == 0 || newText.equals("-")) {
				currentValue = null;
			}
			else {
				currentValue = computeValueFromString(newText);
			}
		}

		private boolean checkChars(String text) {
			for (int i = 0; i < text.length(); i++) {
				char c = text.charAt(i);
				if (!checkChar(c)) {
					return false;
				}
			}
			return true;
		}

		private boolean checkChar(char c) {
			if (allowsNegative && c == '-') {
				return true;
			}
			if (c >= '0' && c <= '9') {
				return true;
			}
			if (isHexMode && c >= 'a' && c <= 'f') {
				return true;
			}
			if (isHexMode && c >= 'A' && c <= 'F') {
				return true;
			}
			return false;
		}
	}

//	public static void main(String[] args) throws Exception {
//		JFrame frame = new JFrame("Test");
//		Container contentPane = frame.getContentPane();
//		contentPane.setLayout(new BorderLayout());
//		HexOrDecimalInput field = new HexOrDecimalInput();
//		field.setValue(20L);
//		field.setHexMode();
//		contentPane.add(field, BorderLayout.SOUTH);
//		frame.pack();
//		frame.setVisible(true);
//	}

}
