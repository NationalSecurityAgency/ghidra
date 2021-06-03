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
package docking.widgets.combobox;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.ComboBoxUI;
import javax.swing.text.*;

import docking.widgets.GComponent;

/**
 * GhidraComboBox adds the following features:
 * 
 * 1) ActionListeners are only invoked when the &lt;Enter&gt; key
 * is pressed within the text-field of the combo-box. 
 * In normal JComboBox case, the ActionListeners are notified
 * when an item is selected from the list.
 * 
 * 2) Adds the auto-completion feature. As a user
 * types in the field, the combo box suggest the nearest matching
 * entry in the combo box model.
 * 
 * It also fixes the following bug:
 * 
 * A normal JComboBox has a problem (feature?) 
 * that if you have a dialog with a button
 * and JComboBox and you edit the comboText field and 
 * then hit the button, the button sometimes does not work.
 * 
 * When the combobox loses focus,
 * and its text has changed, it generates an actionPerformed event as
 * though the user pressed &lt;Enter&gt; in the combo text field.  This
 * has a bizarre effect if you have added an actionPerformed listener
 * to the combobox and in your callback you adjust the enablement state
 * of the button that you pressed (which caused the text field to lose
 * focus) in that you end up changing the button's internal state(by calling
 * setEnabled(true or false)) in the middle of the button press.
 */
public class GhidraComboBox<E> extends JComboBox<E> implements GComponent {
	private ArrayList<ActionListener> listeners = new ArrayList<>();
	private ArrayList<DocumentListener> docListeners = new ArrayList<>();
	private boolean setSelectedFlag = false;

	private boolean forwardEnter;
	private Action defaultSystemEnterForwardingAction;

	/**
	 * Default constructor.
	 */
	public GhidraComboBox() {
		super();
		init();
	}

	/**
	 * Construct a new GhidraComboBox using the given model.
	 * @see javax.swing.JComboBox#JComboBox(ComboBoxModel)
	 */
	public GhidraComboBox(ComboBoxModel<E> aModel) {
		super(aModel);
		init();
	}

	/**
	 * Construct a new GhidraComboBox and populate a default model
	 * with the given items.
	 * @see javax.swing.JComboBox#JComboBox(Object[])
	 */
	public GhidraComboBox(E[] items) {
		super(items);
		init();
	}

	/**
	 * Construct a new GhidraComboBox and populate a default model with
	 * the given Vector of items.
	 * @see javax.swing.JComboBox#JComboBox(Vector)
	 */
	public GhidraComboBox(Vector<E> items) {
		super(items);
		init();
	}

	private void init() {
		setHTMLRenderingEnabled(false);
		if (getRenderer() instanceof JComponent) {
			GComponent.setHTMLRenderingFlag((JComponent) getRenderer(), false);
		}
	}

	@Override
	public void setUI(ComboBoxUI ui) {
		super.setUI(ui);
		Object object = getEditor().getEditorComponent();
		if (object instanceof JTextField) {
			JTextField textField = (JTextField) object;
			textField.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					notifyActionListeners(e);
				}
			});
			textField.setDocument(new InterceptedInputDocument());
			textField.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void removeUpdate(DocumentEvent e) {
					notifyRemove(e);
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					notifyInsert(e);
				}

				@Override
				public void changedUpdate(DocumentEvent e) {
					notifyChanged(e);
				}
			});
		}

		// HACK ALERT:  see setEnterKeyForwarding(boolean)
		ActionMap am = getActionMap();
		if (am != null) {
			defaultSystemEnterForwardingAction = am.get("enterPressed");
			am.put("enterPressed", new AbstractAction() {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (forwardEnter) {
						defaultSystemEnterForwardingAction.actionPerformed(e);
					}
				}
			});
		}
	}

	/**
	 * HACK ALERT:  By default, the JComboBoxUI forwards the &lt;Enter&gt; key actions to the root pane
	 * of the JComboBox's container (which is used primarily by any installed 'default button').
	 * The problem is that the forwarding does not happen always.  In the case that the &lt;Enter&gt;
	 * key will trigger a selection in the combo box, the action is NOT forwarded.
	 * <p>
	 * By default Ghidra disables the forwarding altogether, since most users of 
	 * {@link GhidraComboBox} will add an action listener to handle &lt;Enter&gt; actions.
	 * <p>
	 * To re-enable the default behavior, set the <code>forwardEnter</code> value to true.
	 *  
	 * @param forwardEnter true to enable default &lt;Enter&gt; key handling.
	 */
	public void setEnterKeyForwarding(boolean forwardEnter) {
		this.forwardEnter = forwardEnter;
	}

	public String getText() {
		Component comp = getEditor().getEditorComponent();
		if (comp instanceof JTextField) {
			JTextField textField = (JTextField) comp;
			return textField.getText();
		}
		return null;
	}

	@Override
	public void setSelectedItem(Object obj) {
		setSelectedFlag = true;
		super.setSelectedItem(obj);
		Component comp = getEditor().getEditorComponent();
		if (comp instanceof JTextField) {
			JTextField textField = (JTextField) comp;
			updateTextFieldTextForClearedSelection(textField, obj);
			textField.selectAll();
		}
		setSelectedFlag = false;
	}

	/**
	 * Sets the size of the text field editor used by this combo box, <b>if that is the type of
	 * editor used</b>.  By default the editor for combo boxes is a text field.  This method is
	 * a convenience for the user to set the number of columns on that text field, which updates
	 * the preferred size of the combo box.
	 * 
	 * @param columnCount The number of columns for the text field editor
	 * @see JTextField#setColumns(int)
	 */
	public void setColumnCount(int columnCount) {
		Component comp = getEditor().getEditorComponent();
		if (comp instanceof JTextField) {
			((JTextField) comp).setColumns(columnCount);
		}
	}

	/**
	 * A fix for the following series of events:
	 * -The user selects an item
	 * -The user deletes the text
	 * -setSelectedItem(Object) method is called with the same item
	 * 
	 * In that above series of steps, the text will still be empty, as the user deleted it *and*
	 * the call to setSelectedItem(Object) had no effect because the base class assumed that the
	 * item is already selected. 
	 * 
	 * This method exists to make sure, in that case, that the text of the field matches the
	 * selected item.
	 */
	private void updateTextFieldTextForClearedSelection(JTextField comboBoxTextField,
			Object selectedItem) {
		if (selectedItem == null) {
			return; // nothing to add to the text field
		}

		String text = comboBoxTextField.getText();
		String newText = selectedItem.toString();
		if (!text.equals(newText)) {
			comboBoxTextField.setText(newText);
		}
	}

	public void selectAll() {
		Component comp = getEditor().getEditorComponent();
		if (comp instanceof JTextField) {
			JTextField textField = (JTextField) comp;
			textField.selectAll();
		}
	}

	/**
	 * Remove all entries in the drop down list
	 */
	public void clearModel() {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		model.removeAllElements();
	}

	public void addToModel(E obj) {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		model.addElement(obj);
	}

	public boolean containsItem(E obj) {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		return model.getIndexOf(obj) != -1;
	}

	@Override
	public void addActionListener(ActionListener l) {
		listeners.add(l);
	}

	@Override
	public void removeActionListener(ActionListener l) {
		listeners.remove(l);
	}

	public void addDocumentListener(DocumentListener l) {
		docListeners.add(l);
	}

	public void removeDocumentListener(DocumentListener l) {
		docListeners.remove(l);
	}

	private void notifyActionListeners(ActionEvent e) {
		Iterator<ActionListener> iter = listeners.iterator();
		while (iter.hasNext()) {
			iter.next().actionPerformed(e);
		}
	}

	private void notifyInsert(DocumentEvent e) {
		Iterator<DocumentListener> iter = docListeners.iterator();
		while (iter.hasNext()) {
			iter.next().insertUpdate(e);
		}
	}

	private void notifyChanged(DocumentEvent e) {
		Iterator<DocumentListener> iter = docListeners.iterator();
		while (iter.hasNext()) {
			iter.next().changedUpdate(e);
		}
	}

	private void notifyRemove(DocumentEvent e) {
		Iterator<DocumentListener> iter = docListeners.iterator();
		while (iter.hasNext()) {
			iter.next().removeUpdate(e);
		}
	}

	private String matchHistory(String input) {
		if (setSelectedFlag) {
			return null;
		}
		if (input == null) {
			return null;
		}
		int count = getItemCount();
		for (int i = 0; i < count; i++) {
			String cur = getItemAt(i).toString();
			if (cur.startsWith(input)) {
				return cur;
			}
		}
		return null;
	}

	/**
	 * Custom Document the valid user input on the fly.
	 */
	public class InterceptedInputDocument extends DefaultStyledDocument {

		private boolean automated = false;

		/**
		 * Called before new user input is inserted into the entry text field.  The super
		 * method is called if the input is accepted.
		 */
		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {

			super.insertString(offs, str, a);

			if (automated) {
				automated = false;
			}
			else {
				JTextField textField = (JTextField) getEditor().getEditorComponent();

				String input = textField.getText();
				String match = matchHistory(input);
				if (match != null && match.length() > input.length()) {
					automated = true;
					textField.setText(match);
					textField.setSelectionStart(input.length());
					textField.setSelectionEnd(match.length());
				}
			}
		}
	}
}
