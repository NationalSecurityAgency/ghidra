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
import docking.widgets.label.GLabel;
import ghidra.util.layout.PairLayout;

/**
 * A dialog that has text fields to get user input.
 *
 */
public class InputDialog extends DialogComponentProvider {
	private final static String DEFAULT_VALUE = "";
	private final static int MAX_SIZE = 256;

	private boolean isCanceled;
	private String[] inputLabels;
	private String[] inputValues;
	private String[] initialValues;
	private JTextField[] textFields;
	private KeyListener keyListener;
	private InputDialogListener listener;

	/**
	 * Creates a provider for a generic input dialog with the specified title, a text field,
	 * labeled by the specified label. The user should check the value of
	 * "isCanceled()" to know whether or not the user canceled the operation.
	 * Otherwise, use the "getValue()" or "getValues()" to get the value(s)
	 * entered by the user. Use the tool's "showDialog()" to display the dialog.
	 * <P>
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param label value to use for the label of the text field
	 */
	public InputDialog(String dialogTitle, String label) {
		this(dialogTitle, new String[] { label }, new String[] { DEFAULT_VALUE }, null);
	}

	/**
	 * Creates a generic input dialog with the specified title, a text field,
	 * labeled by the specified label. The user should check the value of
	 * "isCanceled()" to know whether or not the user canceled the operation.
	 * Otherwise, use the "getValue()" or "getValues()" to get the value(s)
	 * entered by the user. Use the tool's "showDialog()" to display the dialog.
	 * <P>
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param label value to use for the label of the text field
	 * @param initialValue initial value to use for the text field
	 */
	public InputDialog(String dialogTitle, String label, String initialValue) {
		this(dialogTitle, new String[] { label }, new String[] { initialValue }, null);
	}

	/**
	 * Creates a generic input dialog with the specified title, a text field,
	 * labeled by the specified label. The user should check the value of
	 * "isCanceled()" to know whether or not the user canceled the operation.
	 * Otherwise, use the "getValue()" or "getValues()" to get the value(s)
	 * entered by the user. Use the tool's "showDialog()" to display the dialog.
	 * <P>
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param label value to use for the label of the text field
	 * @param initialValue initial value to use for the text field
	 * @param listener the dialog listener (may be null)
	 */
	public InputDialog(String dialogTitle, String label, String initialValue,
			InputDialogListener listener) {
		this(dialogTitle, new String[] { label }, new String[] { initialValue }, listener);
	}

	/**
	 * Creates a generic input dialog with the specified title, a text field,
	 * labeled by the specified label. The user should check the value of
	 * "isCanceled()" to know whether or not the user canceled the operation.
	 * Otherwise, use the "getValue()" or "getValues()" to get the value(s)
	 * entered by the user. Use the tool's "showDialog()" to display the dialog.
	 * <P>
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param label value to use for the label of the text field
	 * @param initialValue initial value to use for the text field
	 * @param isModal whether or not the dialog is to be modal
	 */
	public InputDialog(String dialogTitle, String label, String initialValue, boolean isModal) {
		this(dialogTitle, new String[] { label }, new String[] { initialValue }, null);
	}

	/**
	 * Creates a generic input dialog with the specified title, a text field,
	 * labeled by the specified label. The user should check the value of
	 * "isCanceled()" to know whether or not the user canceled the operation.
	 * Otherwise, use the "getValue()" or "getValues()" to get the value(s)
	 * entered by the user. Use the tool's "showDialog()" to display the dialog.
	 * <P>
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param labels values to use for the labels of the text fields
	 * @param initialValues initial values to use for the text fields
	 */
	public InputDialog(String dialogTitle, String[] labels, String[] initialValues) {
		this(dialogTitle, labels, initialValues, null);
	}

	/**
	 * Creates a generic input dialog with the specified title, a text field,
	 * labeled by the specified label. The user should check the value of
	 * "isCanceled()" to know whether or not the user canceled the operation.
	 * Otherwise, use the "getValue()" or "getValues()" to get the value(s)
	 * entered by the user. Use the tool's "showDialog()" to display the dialog.
	 * <P>
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param labels values to use for the labels of the text fields
	 * @param initialValues initial values to use for the text fields
	 * @param listener listener that is called when the OK button is hit
	 */
	public InputDialog(String dialogTitle, String[] labels, String[] initialValues,
			InputDialogListener listener) {
		super(dialogTitle, true, (listener != null) /* status */, true /* buttons */,
			false /* no tasks */);
		this.listener = listener;

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

		// put the rest of the dialog together
		inputLabels = labels;
		this.initialValues = initialValues;
		setTransient(true);
		addOKButton();
		addCancelButton();
		buildMainPanel();

		if (initialValues != null && initialValues[0] != null && initialValues[0].length() > 0) {
			// highlight the field if it contains a value
			textFields[0].selectAll();
		}
		if (listener != null) {
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
			for (JTextField textField : textFields) {
				textField.getDocument().addDocumentListener(docListener);
			}
		}
		setFocusComponent(textFields[0]);
	}

	/**
	 * completes the construction of the gui for this dialog
	 */
	private void buildMainPanel() {

		JPanel panel = new JPanel(new PairLayout(5, 5, 120));
		inputValues = new String[inputLabels.length];
		textFields = new MyTextField[inputLabels.length];
		for (int i = 0; i < inputValues.length; i++) {
			textFields[i] = new MyTextField(initialValues[i]);
			textFields[i].addKeyListener(keyListener);
			textFields[i].setName("input.dialog.text.field." + i);
			panel.add(new GLabel(inputLabels[i], SwingConstants.RIGHT));
			panel.add(textFields[i]);
		}
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		this.addWorkPanel(panel);
	}

	@Override
	protected void okCallback() {
		isCanceled = false;
		for (int v = 0; v < inputValues.length; v++) {
			inputValues[v] = textFields[v].getText();
		}

		if (listener != null) {
			if (!listener.inputIsValid(this)) {
				return;
			}
		}
		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	/**
	 * Returns if this dialog is cancelled
	 * @return true if cancelled
	 */
	public boolean isCanceled() {
		return isCanceled;
	}

	/**
	 * Return the value of the first (and maybe only) text field
	 * @return the text field value
	 */
	public String getValue() {
		return inputValues[0];
	}

	/**
	 * Sets the text of the primary text field
	 * @param text the text
	 */
	public void setValue(String text) {
		setValue(text, 0);
	}

	/**
	 * Sets the text of the text field at the given index
	 * @param text the text
	 * @param index the index of the text field
	 */
	public void setValue(String text, int index) {
		textFields[index].setText(text);
	}

	/**
	 * Return the values for all the text field(s)
	 * @return the text field values
	 */
	public String[] getValues() {
		return inputValues;
	}

	private class MyTextField extends JTextField {

		MyTextField(String str) {
			super(str, 20);
		}

		@Override
		protected Document createDefaultModel() {
			return new MyDocument(this);
		}

		private class MyDocument extends PlainDocument {
			private JTextField textField;

			private MyDocument(JTextField textField) {
				super();
				this.textField = textField;
			}

			/**
			 * @see javax.swing.text.Document#insertString(int, java.lang.String, javax.swing.text.AttributeSet)
			 */
			@Override
			public void insertString(int offs, String str, AttributeSet a)
					throws BadLocationException {
				if (str == null) {
					return;
				}

				String text = textField.getText();
				if (text.length() + str.length() > MAX_SIZE) {
					int nTooMany = text.length() + str.length() - MAX_SIZE;
					int len = str.length() - nTooMany;
					str = str.substring(0, len);
				}
				super.insertString(offs, str, a);
			}
		}
	}

//    public static void main(String[] args) {
//        Frame myFrame = new Frame("testing");
//        InputDialog inputDialog = new InputDialog(myFrame, "Testing Dialog 1", "Enter project name:");
//        System.out.println("Value input: "+inputDialog.getValue());
//
//    }

}
