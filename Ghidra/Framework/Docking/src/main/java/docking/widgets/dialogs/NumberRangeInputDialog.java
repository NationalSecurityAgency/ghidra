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
package docking.widgets.dialogs;

import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.HintTextField;
import ghidra.util.NumericUtilities;
import ghidra.util.datastruct.SortedRangeList;
import ghidra.util.layout.PairLayout;

/**
 * An input dialog that accepts number input as discrete values or a range of values using 
 * ':' as the range separator.
 */
public class NumberRangeInputDialog extends DialogComponentProvider {

	private static final String RANGE_DELIMITER = ":";
	private static final String DEFAULT_VALUE = "";
	private static final String HINT_TEXT = "e.g. 2,5 or 1,4:8";
	private static final int MAX_SIZE = 256;

	private boolean wasCancelled;
	private String inputLabel;
	private String initialValue = DEFAULT_VALUE;
	private SortedRangeList rangeList = new SortedRangeList();
	private HintTextField textField;
	private KeyListener keyListener;

	public NumberRangeInputDialog(String title, String label) {
		super(title, true, true/* status */, true /* buttons */,
			false /* no tasks */);

		keyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();
				if (keyCode == KeyEvent.VK_ENTER) {
					okCallback();
				}
			}
		};

		this.inputLabel = label;
		setTransient(true);
		addOKButton();
		addCancelButton();
		buildMainPanel();

		DocumentListener docListener = new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				clearStatusText();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				clearStatusText();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				clearStatusText();
			}
		};
		textField.getDocument().addDocumentListener(docListener);
		setFocusComponent(textField);
	}

	private void buildMainPanel() {

		JPanel panel = new JPanel(new PairLayout(5, 5, 120));
		textField = new MyHintTextField(HINT_TEXT);
		textField.setText(initialValue);
		textField.addKeyListener(keyListener);
		textField.setName("number.range.input.dialog.text.field");
		panel.add(new GLabel(inputLabel, SwingConstants.RIGHT));
		panel.add(textField);

		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		this.addWorkPanel(panel);
	}

	/**
		 * <code>show</code> displays the dialog, gets the user input
		 *
		 * @return false if the user cancelled the operation
		 */
	public boolean show() {
		DockingWindowManager.showDialog(this);
		return !wasCancelled;
	}

	@Override
	protected void okCallback() {
		wasCancelled = false;

		if (!parseRanges()) {
			return;
		}

		close();
	}

	JTextField getTextField() {
		return textField;
	}

	private boolean parseRanges() {

		// format: 1
		//         1,4
		//         1-4
		//         1-4,8
		//         -8, 0xc, 0x10:0x20
		//         -0x20:-0x10

		String value = textField.getText();
		String[] parts = value.split(",");
		for (String rangeText : parts) {
			if (!addRange(rangeText)) {
				return false;
			}
		}
		return true;
	}

	private boolean addRange(String rangeText) {

		String trimmed = rangeText.trim();
		if (!trimmed.contains(RANGE_DELIMITER)) {
			try {
				long parsedLong = NumericUtilities.parseLong(trimmed);
				int intValue = (int) parsedLong;
				rangeList.addRange(intValue, intValue);
			}
			catch (NumberFormatException e) {
				setStatusText("Unable to parse as a number: '" + trimmed + "'");
				return false;
			}
			return true;
		}

		// this must be a range
		String[] startAndEnd = trimmed.split(RANGE_DELIMITER);
		try {
			long parsedLong = NumericUtilities.parseLong(startAndEnd[0]);
			int startInt = (int) parsedLong;

			parsedLong = NumericUtilities.parseLong(startAndEnd[1]);
			int endInt = (int) parsedLong;

			rangeList.addRange(startInt, endInt);
		}
		catch (NumberFormatException e) {
			setStatusText("Unable to parse as a number: '" + trimmed + "'");
			return false;
		}
		return true;
	}

	@Override
	protected void cancelCallback() {
		wasCancelled = true;
		rangeList.clear();
		close();
	}

	/**
	 * Returns if this dialog is cancelled
	 * @return true if cancelled
	 */
	public boolean wasCancelled() {
		return wasCancelled;
	}

	/**
	 * Return the value of the first (and maybe only) text field
	 * @return the text field value
	 */
	public SortedRangeList getValue() {
		return rangeList;
	}

	/**
	 * Sets the text of the primary text field
	 * @param text the text
	 */
	public void setValue(String text) {
		textField.setText(text);
	}

	private class MyHintTextField extends HintTextField {

		MyHintTextField(String hintText) {
			super(hintText);
			setColumns(20);
		}

		@Override
		protected Document createDefaultModel() {
			return new MyDocument(this);
		}

		private class MyDocument extends PlainDocument {
			private JTextField documentTf;

			private MyDocument(JTextField textField) {
				super();
				this.documentTf = textField;
			}

			@Override
			public void insertString(int offs, String str, AttributeSet a)
					throws BadLocationException {
				if (str == null) {
					return;
				}

				String text = documentTf.getText();
				if (text.length() + str.length() > MAX_SIZE) {
					int nTooMany = text.length() + str.length() - MAX_SIZE;
					int len = str.length() - nTooMany;
					str = str.substring(0, len);
				}
				super.insertString(offs, str, a);
			}
		}
	}

}
