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
package ghidra.app.util.bean;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.ArrayList;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.*;

import docking.widgets.SmallBorderButton;
import resources.ResourceManager;


/**
 *
 */
public class FixedBitSizeValueField extends JPanel {
	private static final ImageIcon DROP_DOWN_MENU_ICON = ResourceManager.loadImage("images/menu16.gif");
	protected JTextField valueField;
	protected JButton menuButton;
	private PlainDocument doc;
	private DocumentFilter docFilter;
	protected int radix = 16;
	protected boolean signed = false;
	private BigInteger maxUnsignedValue;
	private BigInteger maxSignedValue;
	private BigInteger minSignedValue;

	private BigInteger maxValue;
	private BigInteger minValue;
	protected JPopupMenu popupMenu;
	protected java.util.List<JCheckBoxMenuItem> menuItems = new ArrayList<>();
	protected java.util.List<ChangeListener> listeners = new ArrayList<>();

	public FixedBitSizeValueField(int bitSize, boolean includeFormatButton, boolean leftJustify) {
		setLayout(new BorderLayout());
		valueField = new JTextField();
		if (includeFormatButton) {
			JPanel buttonPanel = new JPanel(new BorderLayout());
			menuButton = new SmallBorderButton(" hex",DROP_DOWN_MENU_ICON);
			menuButton.setHorizontalTextPosition(SwingConstants.LEADING);
			buttonPanel.setBorder(BorderFactory.createEmptyBorder(0,2,0,3));
			buttonPanel.add(menuButton, BorderLayout.EAST);
			add(buttonPanel, BorderLayout.EAST);
			menuButton.setFocusable(false);
			menuButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					showPopup();
				}
			});

		}
		add(valueField, BorderLayout.CENTER);
		Font f2 = new Font("monospaced", Font.PLAIN, 14);
		valueField.setFont(f2);
		valueField.setMargin(new Insets(0,2,0,2));

		createPopup();

		doc = new PlainDocument();
		docFilter = new MyDocFilter();
		doc.setDocumentFilter(docFilter);
		valueField.setDocument(doc);
		if (!leftJustify) {
			valueField.setHorizontalAlignment(SwingConstants.TRAILING);
		}

		setBitSize(bitSize);
		setFormat(16, false);
	}

	public void setBitSize(int bitSize) {
		BigInteger b = BigInteger.valueOf(2);
		maxSignedValue = b.pow(bitSize-1).subtract(BigInteger.ONE);
		minSignedValue = b.pow(bitSize-1).negate();
		maxUnsignedValue = b.pow(bitSize).subtract(BigInteger.ONE);

		maxValue = signed ? maxSignedValue : maxUnsignedValue;
		minValue = signed ? minSignedValue : BigInteger.ZERO;
		setValue(getValue());
	}

	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	public boolean processText() {
		String text = valueField.getText().trim();
		if (text.length() == 0) {
			return true;
		}
		if (signed && text.equals("-")) {
			return true;
		}
		BigInteger value = getValue(text);
		if (value == null) {
			return false;
		}
		if (value.compareTo(maxValue) > 0) {
			return false;
		}
		if (value.compareTo(minValue) < 0) {
			return false;
		}
		return true;
	}
	public void setMinMax(BigInteger min, BigInteger max) {
		minValue = min;
		maxValue = max;
	}

	protected void createPopup() {
		ActionListener actionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JCheckBoxMenuItem item = (JCheckBoxMenuItem)e.getSource();
				menuActivated(item);
			}
		};

		popupMenu = new JPopupMenu();
		menuItems.add(new JCheckBoxMenuItem("Hex, Unsigned"));
		menuItems.add(new JCheckBoxMenuItem("Hex, Signed"));
		menuItems.add(new JCheckBoxMenuItem("Decimal, Unsigned"));
		menuItems.add(new JCheckBoxMenuItem("Decimal, Signed"));
		menuItems.add(new JCheckBoxMenuItem("Octal, Unsigned"));
		menuItems.add(new JCheckBoxMenuItem("Binary, Unsigned"));
		for (JCheckBoxMenuItem menuItem : menuItems) {
			popupMenu.add(menuItem);
			menuItem.addActionListener(actionListener);
		}
	}
	private void showPopup() {
		Dimension d = getSize();
		popupMenu.show(this, d.width, d.height );
	}
	protected void updatePopup() {
		for (JCheckBoxMenuItem menuItem	 : menuItems) {
			menuItem.setSelected(false);
		}
		int selectedMenuItem = -1;
		switch(radix) {
			case 2:
				selectedMenuItem = signed ? -1 : 5;
				break;
			case 8:
				selectedMenuItem = signed ? -1 : 4;
				break;
			case 10:
				selectedMenuItem = signed ? 3 : 2;
				break;
			case 16:
				selectedMenuItem = signed ? 1 : 0;
				break;
		}
		if (selectedMenuItem != -1) {
			menuItems.get(selectedMenuItem).setSelected(true);
		}
	}
	protected void menuActivated(JCheckBoxMenuItem item) {

		int index = menuItems.indexOf(item);
		switch(index) {
			case 0:
				setFormat(16, false);
				break;
			case 1:
				setFormat(16, true);
				break;
			case 2:
				setFormat(10, false);
				break;
			case 3:
				setFormat(10, true);
				break;
			case 4:
				setFormat(8, false);
				break;
			case 5:
				setFormat(2, false);
				break;
		}
	}
	public void setFormat(int radix, boolean signed) {
		BigInteger curValue = getValue(valueField.getText());

		this.radix = radix;
		this.signed = signed;
		updatePopup();
		updateMenuButton();

		maxValue = signed ? maxSignedValue : maxUnsignedValue;
		minValue = signed ? minSignedValue : BigInteger.ZERO;

		if (curValue != null) {
			BigInteger newValue = curValue;
			if (signed) {
				if (curValue.compareTo(maxValue) > 0) {
					newValue = curValue.subtract(maxUnsignedValue.add(BigInteger.ONE));
				}
			}
			else {
				if (curValue.compareTo(minValue) < 0) {
					newValue = curValue.add(maxUnsignedValue.add(BigInteger.ONE));
				}
			}
			setValue(newValue);

		}
		else {
			if (valueField.getText().trim().equals("-")) {
				setValue(null);
			}
		}
	}

	protected void updateMenuButton() {
		if (menuButton == null) {
			return;
		}
		String buttonText = "";
		switch(radix) {
			case 16:
				buttonText = " hex";
				break;
			case 10:
				buttonText = " dec";
				break;
			case 8:
				buttonText = " oct";
				break;
			case 2:
				buttonText = " bin";
				break;
		}
		menuButton.setText(buttonText);

	}

	public boolean setValue(BigInteger value) {
		return setValue(value, false);
	}
	public boolean setValue(BigInteger value, boolean pad) {
		setText("");
		if (value == null) {
			return true;
		}
		if (value.compareTo(maxValue) > 0) {
			return false;
		}
		if (value.compareTo(minValue) < 0) {
			return false;
		}
		String valueString = value.toString(radix);
		if (pad) {
			valueString = pad(valueString);
		}
		setText(valueString);
		return true;
	}
	private String pad(String valueString) {
		if (signed) {
			return valueString;
		}
		String maxValueString = maxUnsignedValue.toString(radix);
		if (maxValueString.length() > valueString.length()) {
			StringBuffer buf = new StringBuffer();
			int n = maxValueString.length() - valueString.length();
			for(int i=0;i<n;i++) {
				buf.append("0");
			}
			buf.append(valueString);
			valueString = buf.toString();
		}
		return valueString;
	}
	private void setText(String text) {
		doc.setDocumentFilter(null);
		valueField.setText(text);
		doc.setDocumentFilter(docFilter);
	}
	BigInteger getValue(String text) {
		try {
			return new BigInteger(text, radix);
		} catch (NumberFormatException e) {
		}
		return null;
	}
	public BigInteger getValue() {
		return getValue(valueField.getText().trim());
	}
	public static void main(String[] args) {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Exception e) {
		}
		JFrame f = new JFrame("Test");
		JPanel panel = new JPanel(new BorderLayout());
		FixedBitSizeValueField rf = new FixedBitSizeValueField(8, true, false);
		panel.add(rf, BorderLayout.NORTH);
		f.getContentPane().add(panel);
		f.pack();
		f.setVisible(true);
	}

	String normalizeText(String s) {
		s = s.strip();
		if (radix == 16 && (s.startsWith("0x") || s.startsWith("0X"))) {
			return s.substring(2);
		}
		if (radix == 2 && (s.startsWith("0b") || s.startsWith("0B"))) {
			return s.substring(2);
		}

		return s;
	}


	class MyDocFilter extends DocumentFilter {
		/**
		 * @see javax.swing.text.DocumentFilter#insertString(FilterBypass, int, String, AttributeSet)
		 */
		@Override
		public void insertString(FilterBypass fb, int offset, String string,
				AttributeSet attr) throws BadLocationException {

			String oldText = doc.getText(0, doc.getLength());
			string = normalizeText(string);
			fb.insertString(offset, string, attr);
			if (!processText()) {
				fb.replace(0, doc.getLength(), oldText, attr);
				valueField.setCaretPosition(offset);
			}
			valueChanged();
		}

		/**
		 * @see javax.swing.text.DocumentFilter#remove(FilterBypass, int, int)
		 */
		@Override
		public void remove(FilterBypass fb, int offset, int length)
				throws BadLocationException {

			String oldText = doc.getText(0, doc.getLength());
			fb.remove(offset, length);
			if (!processText()) {
				fb.replace(0, doc.getLength(), oldText, null);
				valueField.setCaretPosition(offset);
			}
			valueChanged();
		}

		/**
		 * @see javax.swing.text.DocumentFilter#replace(FilterBypass, int, int, String, AttributeSet)
		 */
		@Override
		public void replace(FilterBypass fb, int offset, int length,
				String text, AttributeSet attrs) throws BadLocationException {
			String oldText = doc.getText(0, doc.getLength());
			text = normalizeText(text);
			fb.replace(offset, length, text, attrs);
			if (!processText()) {
				fb.replace(0, doc.getLength(), oldText, attrs);
				valueField.setCaretPosition(offset);
			}
			valueChanged();
		}
	}


	public Component getTextComponent() {
		return valueField;
	}

	public void valueChanged() {
		if (listeners.size() == 0) {
			return;
		}
		ChangeEvent ev = new ChangeEvent(this);
		for (ChangeListener listener : listeners) {
			listener.stateChanged(ev);
		}
	}




}


