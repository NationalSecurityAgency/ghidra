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
package ghidra.app.script;

import java.awt.*;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import generic.util.WindowUtilities;
import ghidra.framework.preferences.Preferences;
import ghidra.util.NumericUtilities;

public class AskDialog<T> extends DialogComponentProvider {
	public final static int STRING = 0;
	public final static int INT = 1;
	public final static int LONG = 2;
	public final static int DOUBLE = 3;
	public final static int BYTES = 4;

	private int type;
	private boolean isCanceled;
	private JLabel label;
	private JTextField textField;
	private JComboBox<?> comboField;
	private KeyListener keyListener;

	protected AskDialog(String dialogTitle, String message, int type) {
		this(null, dialogTitle, message, type, null, null);
	}

	public AskDialog(String dialogTitle, String message, int type, Object defaultValue) {
		this(null, dialogTitle, message, type, null, defaultValue);
	}

	public AskDialog(Component parent, String title, String message, int type) {
		this(parent, title, message, type, null, null);
	}

	public AskDialog(final Component parent, String title, String message, int type,
			List<T> choices, Object defaultValue) {
		super(title, true, true, true, false);

		this.type = type;

		// create the key listener all the text fields will use
		keyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();
				if (keyCode == KeyEvent.VK_ENTER) {
					okCallback();
				}
			}
		};

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		label = new GDLabel(message);
		panel.add(label, BorderLayout.WEST);

		if (choices == null) {
			textField = new JTextField(20);
			textField.setName("JTextField");//for JUnits...
			textField.addKeyListener(keyListener);
			textField.setText(defaultValue == null ? "" : defaultValue.toString());
			textField.selectAll();
			panel.add(textField, BorderLayout.CENTER);
		}
		else {
			comboField = new GComboBox<>(choices.toArray(new Object[choices.size()]));
			comboField.setEditable(false);
			comboField.setName("JComboBox");
			if (defaultValue != null) {
				comboField.setSelectedItem(defaultValue);
			}
			panel.add(comboField, BorderLayout.CENTER);
		}

		setTransient(true);
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		setRememberSize(false);
		DockingWindowManager.showDialog(parent, AskDialog.this);
	}

	private void saveCurrentDimensions() {
		Rectangle bounds = getBounds();
		Window window = WindowUtilities.windowForComponent(getComponent());

		if (window != null) {
			Point location = window.getLocation();
			bounds.x = location.x;
			bounds.y = location.y;
		}

		StringBuffer buffer = new StringBuffer();
		buffer.append(bounds.x).append(":");
		buffer.append(bounds.y).append(":");
		buffer.append(bounds.width).append(":");
		buffer.append(bounds.height).append(":");
		Preferences.setProperty("Ask Dialog Bounds", buffer.toString());
	}

	@SuppressWarnings("unchecked")  // the type must be correct, as the values were passed in
	public T getChoiceValue() {
		if (comboField == null) {
			throw new IllegalStateException(
				"Cannot call getChoiceValue() when using a " + "dialog without choices");
		}

		return (T) comboField.getSelectedItem();
	}

	public String getTextFieldValue() {
		if (textField == null) {
			throw new IllegalStateException(
				"Cannot call getTextFieldValue() when using a " + "dialog with multiple choices");
		}
		return textField.getText();
	}

	@Override
	protected void okCallback() {
		isCanceled = false;
		if (comboField != null) {
			if (comboField.getSelectedIndex() < 0) {
				setStatusText("Please make a selection from the pulldown choices.");
				return;
			}
		}
		else {
			switch (type) {
				case STRING: {
					if (textField.getText().length() == 0) {
						setStatusText("Please enter a valid STRING.");
						return;
					}
					break;
				}
				case INT: {
					try {
						getValueAsInt();
					}
					catch (Exception e) {
						setStatusText("Please enter a valid INTEGER.");
						return;
					}
					break;
				}
				case LONG: {
					try {
						getValueAsLong();
					}
					catch (Exception e) {
						setStatusText("Please enter a valid LONG.");
						return;
					}
					break;
				}
				case DOUBLE: {
					try {
						getValueAsDouble();
					}
					catch (Exception e) {
						setStatusText("Please enter a valid DOUBLE.");
						return;
					}
					break;
				}
				case BYTES: {

					if (!isValidBytePattern()) {
						setStatusText("Please enter a valid BYTE PATTERN separated by spaces.");
						return;
					}
					break;
				}
			}
		}
		saveCurrentDimensions();
		close();
	}

	private boolean isValidBytePattern() {
		String text = getValueAsString();
		if (text == null) {
			return false;
		}

		try {
			NumericUtilities.convertStringToBytes(text);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		saveCurrentDimensions();
		close();
	}

	public boolean isCanceled() {
		return isCanceled;
	}

	private Object getValue() {
		if (comboField != null) {
			return comboField.getSelectedItem();
		}
		return textField.getText();
	}

	public String getValueAsString() {
		Object val = getValue();
		if ("".equals(val)) {
			return null;
		}
		return val != null ? val.toString() : null;
	}

	protected Integer getValueAsInt() {
		String text = getValueAsString();
		if (text == null) {
			return null;
		}
		if (text.startsWith("0x")) {
			return (int) NumericUtilities.parseHexLong(text);
		}
		return (int) NumericUtilities.parseLong(text);
	}

	protected Long getValueAsLong() {
		String text = getValueAsString();
		if (text == null) {
			return null;
		}
		return NumericUtilities.parseLong(text);
	}

	protected Double getValueAsDouble() {
		String text = getValueAsString();
		if (text == null) {
			return null;
		}
		if (text.equalsIgnoreCase("pi")) {
			return Math.PI;
		}
		if (text.equalsIgnoreCase("e")) {
			return Math.E;
		}
		return new Double(text);
	}

}
