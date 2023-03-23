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

import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.ComboBoxUI;
import javax.swing.text.Document;

import docking.widgets.GComponent;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;

/**
 * GhidraComboBox adds the following features:
 *
 * <p>
 * 1) ActionListeners are only invoked when the &lt;Enter&gt; key is pressed within the text-field
 * of the combo-box. In normal JComboBox case, the ActionListeners are notified when an item is
 * selected from the list.
 *
 * <p>
 * 2) Adds the auto-completion feature. As a user types in the field, the combo box suggest the
 * nearest matching entry in the combo box model.
 *
 * <p>
 * It also fixes the following bug:
 *
 * <p>
 * A normal JComboBox has a problem (feature?) that if you have a dialog with a button and
 * JComboBox and you edit the comboText field and then hit the button, the button sometimes does
 * not work.
 *
 * <p>
 * When the combobox loses focus, and its text has changed, it generates an actionPerformed event
 * as though the user pressed &lt;Enter&gt; in the combo text field.  This has a bizarre effect if
 * you have added an actionPerformed listener to the combobox and in your callback you adjust the
 * enablement state of the button that you pressed (which caused the text field to lose focus) in
 * that you end up changing the button's internal state(by calling setEnabled(true or false)) in
 * the middle of the button press.
 *
 * @param <E> the item type
 */
public class GhidraComboBox<E> extends JComboBox<E> implements GComponent {
	private List<ActionListener> actionListeners = new ArrayList<>();
	private List<DocumentListener> docListeners = new ArrayList<>();
	private List<KeyListener> keyListeners = new ArrayList<>();
	private boolean setSelectedFlag = false;

	private boolean forwardEnter;
	private Action defaultSystemEnterForwardingAction;
	private Document document;
	private PassThroughActionListener passThroughActionListener;
	private PassThroughKeyListener passThroughKeyListener;
	private PassThroughDocumentListener passThroughDocumentListener;

	/**
	 * Default constructor.
	 */
	public GhidraComboBox() {
		init();
	}

	/**
	 * Construct a new GhidraComboBox using the given model.
	 * @param model the model
	 */
	public GhidraComboBox(ComboBoxModel<E> model) {
		super(model);
		init();
	}

	/**
	 * Construct a new GhidraComboBox and populate a default model with the given items.
	 * @param items the items
	 */
	public GhidraComboBox(E[] items) {
		super(items);
		init();
	}

	/**
	 * Construct a new GhidraComboBox and populate a default model with the given items.
	 * @param items the items
	 */
	public GhidraComboBox(Collection<E> items) {
		super(new Vector<>(items));
		init();
	}

	@Override
	public void setUI(ComboBoxUI ui) {
		super.setUI(ui);
		// this gets called during construction and during theming changes.  It always
		// creates a new editor and any listeners or documents set on the current editor are 
		// lost.  So to combat this, we install the pass through listeners here instead of 
		// in the init() method. We also reset the document if the client ever called the
		// setDocument() method

		installPassThroughListeners();

		if (document != null) {
			setDocument(document);
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
	 * HACK ALERT:  By default, the JComboBoxUI forwards the &lt;Enter&gt; key actions to the root
	 * pane of the JComboBox's container (which is used primarily by any installed 'default
	 * button'). The problem is that the forwarding does not happen always.  In the case that the
	 * &lt;Enter&gt; key will trigger a selection in the combo box, the action is NOT forwarded.
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

	/**
	 * Returns the text in combobox's editor text component
	 * @return  the text in combobox's editor text component
	 */
	public String getText() {
		JTextField textField = getTextField();
		return textField.getText();
	}

	/**
	 * Sets the text on the combobox's editor text component
	 * @param text the text to set
	 */
	public void setText(String text) {
		if (!isEditable) {
			return;
		}
		JTextField textField = getTextField();
		textField.setText(text);
	}

	@Override
	public void setSelectedItem(Object obj) {
		setSelectedFlag = true;
		super.setSelectedItem(obj);
		JTextField textField = getTextField();
		updateTextFieldTextForClearedSelection(textField, obj);
		textField.selectAll();
		setSelectedFlag = false;
	}

	/**
	 * Sets the size of the text field editor used by this combo box.
	 *
	 * @param columnCount The number of columns for the text field editor
	 * @see JTextField#setColumns(int)
	 */
	public void setColumnCount(int columnCount) {
		JTextField textField = getTextField();
		textField.setColumns(columnCount);
	}

	/**
	 * Selects the text in the text field editor usd by this combo box.
	 *
	 * @see JTextField#selectAll()
	 */
	public void selectAll() {
		JTextField textField = getTextField();
		textField.selectAll();
	}

	/**
	 * Removes all the items from the combobox data model.
	 */
	public void clearModel() {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		model.removeAllElements();
	}

	/**
	 * Adds the given item to the combobox's data model.
	 * @param item the item to add
	 */
	public void addToModel(E item) {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		model.addElement(item);
	}

	/**
	 * Adds all the  given item to the combobox's data model.
	 * @param items the item to add
	 */
	public void addToModel(Collection<E> items) {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		for (E e : items) {
			model.addElement(e);
		}
	}

	/**
	 * Returns true if the combobox contains the given item.
	 * @param item the item to check
	 * @return true if the combobox contains the given item.
	 */
	public boolean containsItem(E item) {
		DefaultComboBoxModel<E> model = (DefaultComboBoxModel<E>) getModel();
		return model.getIndexOf(item) != -1;
	}

	@Override
	public void addActionListener(ActionListener l) {
		actionListeners.add(l);
	}

	@Override
	public void removeActionListener(ActionListener l) {
		actionListeners.remove(l);
	}

	/**
	 * Adds a KeyListener to the combobox's editor component.
	 * @param l the listener to add
	 */
	public void addEditorKeyListener(KeyListener l) {
		keyListeners.add(l);
	}

	/**
	 * Removes a KeyListener from the combobox's editor component.
	 * @param l the listener to remove
	 */
	public void removeEditorKeyListener(KeyListener l) {
		keyListeners.remove(l);
	}

	/**
	 * Sets document to be used by the combobox's editor component.
	 * @param document the document to be set
	 */
	public void setDocument(Document document) {
		this.document = document;
		JTextField textField = getTextField();
		textField.setDocument(document);
		document.removeDocumentListener(passThroughDocumentListener);
		document.addDocumentListener(passThroughDocumentListener);
	}

	/**
	 * Adds a document listener to the editor component's document.
	 * @param l the listener to add
	 */
	public void addDocumentListener(DocumentListener l) {
		docListeners.add(l);
	}

	/**
	 * Removes a document listener from the editor component's document
	 * @param l the listener to remove
	 */
	public void removeDocumentListener(DocumentListener l) {
		docListeners.remove(l);
	}

	/**
	 * Sets the number of column's in the editor's component (JTextField).
	 * @param columns the number of columns to show
	 * @see JTextField#setColumns(int)
	 */
	public void setColumns(int columns) {
		JTextField textField = getTextField();
		textField.setColumns(columns);
	}

	/**
	 * Convenience method for associating a label with the editor component.
	 * @param label the label to associate
	 */
	public void associateLabel(JLabel label) {
		JTextField textField = getTextField();
		label.setLabelFor(textField);
	}

	/**
	 * Sets the selection start in the editor's text field.
	 * @param selectionStart the start of the selection
	 * @see JTextField#setSelectionStart(int)
	 */
	public void setSelectionStart(int selectionStart) {
		JTextField textField = getTextField();
		textField.setSelectionStart(selectionStart);
	}

	/**
	 * Sets the selection end in the editor's text field.
	 * @param selectionEnd the end of the selection
	 * @see JTextField#setSelectionEnd(int)
	 */
	public void setSelectionEnd(int selectionEnd) {
		JTextField textField = getTextField();
		textField.setSelectionEnd(selectionEnd);
	}

	@Override
	public void requestFocus() {
		JTextField textField = getTextField();
		textField.requestFocus();
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
	 * A fix for the following series of events:
	 * <ol>
	 * 	<li>The user selects an item</li>
	 *  <li>The user deletes the text</li>
	 *  <li>setSelectedItem(Object) method is called with the same item</li>
	 * </ol>
	 *
	 * In that above series of steps, the text will still be empty, as the user deleted it *and*
	 * the call to setSelectedItem(Object) had no effect because the base class assumed that the
	 * item is already selected.
	 *
	 * <p>
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

	private void init() {
		setHTMLRenderingEnabled(false);
		if (getRenderer() instanceof JComponent) {
			GComponent.setHTMLRenderingFlag((JComponent) getRenderer(), false);
		}
		// add our internal listener to with all the others that the pass through listener will call
		addDocumentListener(new MatchingItemsDocumentListener());

	}

	private void installPassThroughListeners() {
		JTextField textField = getTextField();

		// this gets called during construction before our fields are initialized, so need to 
		// create them here
		if (passThroughActionListener == null) {
			passThroughActionListener = new PassThroughActionListener();
			passThroughKeyListener = new PassThroughKeyListener();
			passThroughDocumentListener = new PassThroughDocumentListener();
		}
		// make sure they are never in there more than once
		textField.removeActionListener(passThroughActionListener);
		textField.removeKeyListener(passThroughKeyListener);
		textField.getDocument().removeDocumentListener(passThroughDocumentListener);

		textField.addActionListener(passThroughActionListener);
		textField.addKeyListener(passThroughKeyListener);
		textField.getDocument().addDocumentListener(passThroughDocumentListener);
	}

	private JTextField getTextField() {
		Object object = getEditor().getEditorComponent();
		if (object instanceof JTextField textField) {
			return textField;
		}
		throw new AssertException("Expected GhidraComboBox editor component to be a JTextField!");
	}

	/**
	 * Listener on the editor's JTextField that then calls any registered action 
	 * listener on this combobox
	 */
	private class PassThroughActionListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			for (ActionListener listener : actionListeners) {
				listener.actionPerformed(e);
			}
		}
	}

	/**
	 * Listener on the editor's JTextField that then calls any registered editor key 
	 * listener on this combobox
	 */
	private class PassThroughKeyListener implements KeyListener {

		@Override
		public void keyTyped(KeyEvent e) {
			for (KeyListener listener : keyListeners) {
				listener.keyTyped(e);
			}
		}

		@Override
		public void keyPressed(KeyEvent e) {
			for (KeyListener listener : keyListeners) {
				listener.keyPressed(e);
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			for (KeyListener listener : keyListeners) {
				listener.keyReleased(e);
			}
		}
	}

	/**
	 * Listener on the editor's JTextField's document that then calls any registered document 
	 * listener on this combobox
	 */
	private class PassThroughDocumentListener implements DocumentListener {
		@Override
		public void insertUpdate(DocumentEvent e) {
			for (DocumentListener listener : docListeners) {
				listener.insertUpdate(e);
			}
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			for (DocumentListener listener : docListeners) {
				listener.removeUpdate(e);
			}
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			for (DocumentListener listener : docListeners) {
				listener.changedUpdate(e);
			}
		}
	}

	/**
	 * Listener to perform matching of items as the user types
	 */
	private class MatchingItemsDocumentListener implements DocumentListener {

		@Override
		public void insertUpdate(DocumentEvent e) {
			JTextField textField = getTextField();
			String input = textField.getText();
			String match = matchHistory(input);
			if (match != null && match.length() > input.length()) {
				// Not allowed to modify textField while in the document listener call.
				Swing.runLater(() -> {
					textField.setText(match);
					textField.setSelectionStart(input.length());
					textField.setSelectionEnd(match.length());
				});
			}
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			// do nothing
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			// do nothing
		}
	}

}
