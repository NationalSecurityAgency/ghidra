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

import java.awt.Component;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Caret;

import org.apache.commons.lang3.StringUtils;

/**
 * A class that links text fields into a "formatted text field", separated by expressions.
 * 
 * This fulfills a similar purpose to formatted text fields, except the individual parts may be
 * placed independent of the other components. Granted, they ought to appear in an intuitive order.
 * The input string is split among a collection of {@link JTextField}s each according to a given
 * pattern -- excluding the final field. Cursor navigation, insertion, deletion, etc. are all
 * applied as if the linked text fields were part of a single composite text field.
 * 
 * The individual text fields must be constructed and added by the user, as in the example:
 * 
 * <pre>
 * {@code
 * Box hbox = Box.createHorizontalBox();
 * TextFieldLinker linker = new TextFieldLinker();
 * 
 * JTextField first = new JTextField();
 * hbox.add(first);
 * hbox.add(Box.createHorizontalStrut(10));
 * linker.linkField(first, "\\s+", " ");
 * 
 * JTextField second = new JTextField();
 * hbox.add(second);
 * hbox.add(new GLabel("-"));
 * linker.linkField(second, "-", "-");
 * 
 * JTextField third = new JTextField();
 * hbox.add(third);
 * linker.linkLastField(third);
 * 
 * linker.setVisible(true);
 * }
 * </pre>
 */
public class TextFieldLinker {
	protected final List<LinkedField> linkedFields = new ArrayList<>();
	protected JTextField lastField;

	protected LinkerState state;
	private boolean haveFocus;

	protected AtomicInteger mute = new AtomicInteger(0);

	// Listeners installed onto me
	protected final List<FocusListener> focusListeners = new ArrayList<>();

	/**
	 * A field that has been added with its corresponding separator expression and replacement
	 */
	protected class LinkedField {
		protected final JTextField field;
		protected final Pattern pat;
		protected final String sep;
		protected final int index;
		protected DualFieldListener listener;

		protected LinkedField(JTextField field, Pattern pat, String sep, int index) {
			this.field = field;
			this.pat = pat;
			this.sep = sep;
			this.index = index;
		}

		protected void registerListener() {
			listener = new DualFieldListener(this);
			field.addCaretListener(listener);
			field.getDocument().addDocumentListener(listener);
			field.addKeyListener(listener);
			field.addFocusListener(listener);
		}

		public void unregisterListener() {
			field.removeCaretListener(listener);
			field.getDocument().removeDocumentListener(listener);
			field.removeKeyListener(listener);
			field.removeFocusListener(listener);
			listener = null;
		}
	}

	/**
	 * The current state of a linked field, stored separately from the actual component
	 */
	protected class FieldState {
		protected String text;
		protected int caret;

		@Override
		public java.lang.String toString() {
			return "'" + text + "'c=" + caret;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof FieldState)) {
				return false;
			}
			FieldState that = (FieldState) obj;
			if (!this.text.equals(that.text)) {
				return false;
			}
			if (this.caret != that.caret) {
				return false;
			}
			return true;
		}

		protected FieldState copy() {
			FieldState cp = new FieldState();
			cp.text = text;
			cp.caret = caret;
			return cp;
		}

		public int clampedCaret() {
			return clamp(0, caret, text.length());
		}
	}

	private int clamp(int min, int val, int max) {
		return Math.max(min, Math.min(val, max));
	}

	/**
	 * A class to track the internal state gathered from the text fields
	 */
	protected class LinkerState {
		int whichFocus;
		final List<FieldState> fieldStates = new ArrayList<>();
		FieldState lastState;

		{
			for (@SuppressWarnings("unused")
			LinkedField lf : linkedFields) {
				fieldStates.add(new FieldState());
			}
			lastState = fieldStates.get(fieldStates.size() - 1);
			reset();
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof LinkerState)) {
				return false;
			}
			LinkerState that = (LinkerState) o;
			if (this.whichFocus != that.whichFocus) {
				return false;
			}
			if (!this.fieldStates.equals(that.fieldStates)) {
				return false;
			}
			return true;
		}

		/**
		 * Copy the state
		 * @return the copy
		 */
		public LinkerState copy() {
			LinkerState cp = new LinkerState();
			cp.whichFocus = this.whichFocus;
			for (FieldState fs : fieldStates) {
				cp.fieldStates.add(fs.copy());
			}
			return cp;
		}

		/**
		 * Erase the state
		 * 
		 * Blank all the fields, and put the caret at the front of the first field.
		 */
		public void reset() {
			whichFocus = 0;
			for (FieldState fs : fieldStates) {
				fs.text = "";
				fs.caret = 0;
			}
		}

		@Override
		public String toString() {
			String textspart = StringUtils.join(fieldStates, ",");
			return "LinkerState(" + textspart + ",focus=" + whichFocus + ",global='" + getText() +
				"',globalC=" + getGlobalCaret() + ")";
		}

		/**
		 * Get the whole composite string
		 * 
		 * @return the text
		 */
		public String getText() {
			return getText(-1);
		}

		/**
		 * Get the composite string, omitting the given separator.
		 * 
		 * This is used as a helper to delete the separator when backspace/delete is pressed at a
		 * boundary.
		 * @param omitSep the separator to omit, or -1 to omit nothing
		 * @return the text
		 */
		public String getText(int omitSep) {
			int lastPopulated;
			for (lastPopulated = linkedFields.size() - 1; lastPopulated >= 0; lastPopulated--) {
				if (fieldStates.get(lastPopulated).text.length() != 0) {
					break;
				}
			}
			StringBuilder result = new StringBuilder();
			for (int i = 0; i <= lastPopulated; i++) {
				if (i > 0 && omitSep != i - 1) {
					result.append(linkedFields.get(i - 1).sep);
				}
				result.append(fieldStates.get(i).text);
			}
			return result.toString();
		}

		/**
		 * Get the composite caret location
		 * @return the location (including separators)
		 */
		public int getGlobalCaret() {
			return getGlobalCaret(-1);
		}

		/**
		 * Get the composite caret location, omitting the given separator.
		 * @param omitSep the separator to omit, or -1 to omit nothing
		 * @return the location
		 */
		public int getGlobalCaret(int omitSep) {
			int caret = 0;
			for (int i = 0; i < whichFocus; i++) {
				if (i > 0 && omitSep != i - 1) {
					caret += linkedFields.get(i - 1).sep.length();
				}
				caret += fieldStates.get(i).text.length();
			}
			if (whichFocus > 0 && omitSep != whichFocus - 1) {
				caret += linkedFields.get(whichFocus - 1).sep.length();
			}
			FieldState fs = fieldStates.get(whichFocus);
			caret += fs.clampedCaret();
			return caret;
		}

		/**
		 * Get the composite text preceding the caret in the given field
		 * @param field the field whose caret to use
		 * @return the text
		 */
		public String getTextBeforeCursor(int field) {
			if (field == -1) {
				throw new IllegalArgumentException("" + field);
			}
			StringBuilder result = new StringBuilder();
			for (int i = 0; i < field; i++) {
				if (i > 0) {
					result.append(linkedFields.get(i - 1).sep);
				}
				result.append(fieldStates.get(i).text);
			}

			if (field > 0) {
				result.append(linkedFields.get(field - 1).sep);
			}
			FieldState fs = fieldStates.get(field);
			result.append(fs.text.substring(0, Math.min(fs.caret, fs.text.length())));
			return result.toString();
		}

		/**
		 * Figure out whether the caret in the given field immediately proceeds a separator.
		 * 
		 * In other words, the caret must be to the far left (position 0), and the given field must
		 * not be the first field. If true, the caret immediately follows separator index
		 * {@code field - 1}.
		 * @param field the field index to check
		 * @return true if the caret immediately follows a separator.
		 */
		public boolean isAfterSep(int field) {
			return field > 0 && fieldStates.get(field).caret == 0;
		}

		/**
		 * Figure out whether the caret in the given field immediately precedes a separator.
		 * 
		 * In other words, the caret must be to the far right, and the given field must not be the
		 * last field. If true, the caret immediately precedes separator index {@code field}.
		 * @param field the field index to check
		 * @return true if the caret immediately precedes a separator.
		 */
		public boolean isBeforeSep(int field) {
			if (field >= fieldStates.size() - 1) {
				return false;
			}
			FieldState fs = fieldStates.get(field);
			return fs.caret == fs.text.length();
		}

		/**
		 * Change focus to the given field as if navigating left.
		 * 
		 * The caret will be moved to the rightmost position, because we're moving left from the
		 * leftmost position of the field to the right.
		 * @param field the field index to be given focus.
		 */
		public void navigateFieldLeft(int field) {
			whichFocus = field;
			FieldState fs = fieldStates.get(field);
			fs.caret = fs.text.length();
		}

		/**
		 * Change focus to the given field as if navigating right.
		 * 
		 * The caret will be moved to the leftmost position, because we're moving right from the
		 * rightmost position of the field to the left.
		 * @param field the field index to be given focus.
		 */
		public void navigateFieldRight(int field) {
			whichFocus = field;
			fieldStates.get(field).caret = 0;
		}

		/**
		 * Remove the given separator from the composite text.
		 * @param sep the separator to remove, by index
		 */
		protected void removeSep(int sep) {
			int caretWOSep = getGlobalCaret(sep);
			String textWOSep = getText(sep);
			setText(textWOSep);
			if (whichFocus > sep) {
				try {
					setGlobalCaret(caretWOSep);
				}
				catch (BadLocationException e) {
					throw new RuntimeException(e);
				}
			}
		}

		/**
		 * Set the composite text
		 * @param text the new text
		 */
		public int setText(String text) {
			int adj = 0;
			for (int i = 0; i < linkedFields.size() - 1; i++) {
				LinkedField lf = linkedFields.get(i);
				FieldState fs = fieldStates.get(i);

				if (text.length() == 0) {
					fs.text = "";
					continue;
				}

				Matcher mat = lf.pat.matcher(text);
				if (mat.find(0)) {
					fs.text = text.substring(0, mat.start());
					text = text.substring(mat.end());
					if (i < whichFocus) {
						adj += lf.sep.length() - mat.group().length();
					}
				}
				else {
					fs.text = text;
					text = "";
				}
			}
			lastState.text = text;
			return adj;
		}

		/**
		 * Set the composite caret location
		 * @param caret the new caret location
		 * @throws BadLocationException if the location exceeds the text length
		 */
		public void setGlobalCaret(int caret) throws BadLocationException {
			int globalCaret = caret;

			for (int i = 0; i < fieldStates.size(); i++) {
				FieldState fs = fieldStates.get(i);

				if (i > 0) {
					caret -= linkedFields.get(i - 1).sep.length();
				}
				if (caret <= 0) {
					whichFocus = i;
					fs.caret = 0;
					return;
				}
				if (caret <= fs.text.length()) {
					whichFocus = i;
					fs.caret = caret;
					return;
				}
				caret -= fs.text.length();
			}
			throw new BadLocationException("caret position (" + globalCaret + ") too large",
				globalCaret);
		}

		/**
		 * Re-parse the composite string and place the components into their proper fields
		 */
		public void reformat() {
			String text = getText();
			int globalCaret = getGlobalCaret();
			globalCaret += setText(text);
			try {
				setGlobalCaret(globalCaret);
			}
			catch (BadLocationException e) {
				// throw new RuntimeException(e);
			}
		}
	}

	/**
	 * Once all fields are added, register all the listeners
	 */
	protected void instrument() {
		state = new LinkerState(); // This should initialize itself based on linked fields
		for (LinkedField lf : linkedFields) {
			lf.registerListener();
		}
	}

	/**
	 * Unregister all the listeners, effectively unlinking the fields
	 */
	protected void dispose() {
		for (LinkedField lf : linkedFields) {
			lf.unregisterListener();
		}
	}

	/**
	 * Add a new text field to this linker
	 * 
	 * Links the given field with the others present in this linker, if any. {@code exp} is a
	 * regular expression that dictates where the given field ends, and the next field begins.
	 * When {@code exp} matches a part of the text in {@code field}, the text is split and
	 * re-flowed so that the second part is removed into the next linked field. The separator is
	 * omitted from both fields. The packing of the fields -- and surrounding labels -- ought to
	 * imply that the separator is still present, because {@link #getText()} or and
	 * {@link #getTextBeforeCursor(JTextField)} insert {@code sep} between the fields.
	 * 
	 * Any number of fields may be added in this fashion, but the last field -- having no
	 * associated pattern or separator -- must be added using
	 * {@link #linkLastField(JTextField)}. Thus, before linking is actually activated, at least one
	 * field must be present. To be meaningful, at least two fields should be linked.
	 * 
	 * NOTE: {@code exp} must match {@code sep}.
	 * 
	 * @param field the field to link
	 * @param exp the separator following the field
	 * @param sep the separator that replaces {@code exp} when matched
	 */
	public void linkField(JTextField field, String exp, String sep) {
		Pattern pat = Pattern.compile(exp);
		linkField(field, pat, sep);
	}

	/**
	 * @see #linkField(JTextField, String, String)
	 */
	public void linkField(JTextField field, Pattern pat, String sep) {
		checkLast();
		if (!pat.matcher(sep).matches()) {
			throw new IllegalArgumentException(pat + " must match " + sep);
		}
		linkedFields.add(new LinkedField(field, pat, sep, linkedFields.size()));
	}

	/**
	 * Add the final field, and actually link the fields
	 * 
	 * The fields are not effectively linked until this method is called. Additionally, once this
	 * method is called, the linker cannot take any additional fields.
	 * @param field the final field
	 */
	public void linkLastField(JTextField field) {
		checkLast();
		linkedFields.add(new LinkedField(field, null, null, linkedFields.size()));
		lastField = field;
		instrument();
	}

	/**
	 * Check if this linker is mutable
	 */
	protected void checkLast() {
		if (lastField != null) {
			throw new IllegalStateException("last field has already been linked");
		}
	}

	/**
	 * Get the index of a field.
	 * @param field the field
	 * @return the index, or -1 if the field does not belong to this composite field
	 */
	protected int findField(Component field) {
		for (int i = 0; i < linkedFields.size(); i++) {
			if (linkedFields.get(i).field == field) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Provides an opportunity to compose the field from an extension of {@link JTextField}
	 * @param i the index of the field to construct
	 * @return a newly-constructed text field
	 */
	protected JTextField buildField(int i) {
		return new JTextField();
	}

	/**
	 * A listener for all my callbacks
	 * 
	 * A separate listener is constructed and installed on each field so that we have a reference
	 * to the field in every callback.
	 */
	private class DualFieldListener extends KeyAdapter
			implements CaretListener, FocusListener, DocumentListener {
		private LinkedField linked;

		public DualFieldListener(LinkedField linked) {
			this.linked = linked;
		}

		@Override
		public void caretUpdate(CaretEvent e) {
			if (mute.get() != 0) {
				return;
			}
			LinkerState old = state.copy();
			state.fieldStates.get(linked.index).caret = linked.field.getCaretPosition();
			state.reformat();
			if (!old.equals(state)) {
				syncStateLater();
			}
		}

		@Override
		public void keyPressed(KeyEvent e) {
			Caret caret = linked.field.getCaret();
			boolean sel = caret.getMark() != caret.getDot();
			switch (e.getKeyCode()) {
				case KeyEvent.VK_BACK_SPACE:
					if (!sel && state.isAfterSep(linked.index)) {
						state.removeSep(linked.index - 1);
						e.consume();
					}
					break;
				case KeyEvent.VK_CLEAR:
					clear();
					break;
				case KeyEvent.VK_DELETE:
					if (!sel && state.isBeforeSep(linked.index)) {
						state.removeSep(linked.index);
						e.consume();
					}
					break;
				case KeyEvent.VK_KP_LEFT:
				case KeyEvent.VK_LEFT:
					if (state.isAfterSep(linked.index)) {
						state.navigateFieldLeft(linked.index - 1);
					}
					break;
				case KeyEvent.VK_KP_RIGHT:
				case KeyEvent.VK_RIGHT:
					if (state.isBeforeSep(linked.index)) {
						state.navigateFieldRight(linked.index + 1);
					}
					break;
				default:
					return;
			}
			syncStateLater();
		}

		@Override
		public void focusGained(FocusEvent e) {
			if (!haveFocus) {
				haveFocus = true;
				fireFocusListeners(e);
			}
			state.whichFocus = linked.index;
		}

		@Override
		public void focusLost(FocusEvent e) {
			int i = findField(e.getOppositeComponent());
			if (i == -1) {
				if (haveFocus) {
					haveFocus = false;
					fireFocusListeners(e);
				}
			}
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			if (mute.get() != 0) {
				return;
			}
			//DualState old = state.copy();
			state.fieldStates.get(linked.index).text = linked.field.getText();
			/*state.reformat();
			if (!old.equals(state)) {
				syncStateLater();
			}*/
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			if (mute.get() != 0) {
				return;
			}
			//DualState old = state.copy();
			state.fieldStates.get(linked.index).text = linked.field.getText();
			/*state.reformat();
			if (!old.equals(state)) {
				syncStateLater();
			}*/
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			// Ignore attribute changes
		}
	}

	/**
	 * Schedule a state synchronization.
	 */
	protected void syncStateLater() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				doSyncState();
			}
		});
	}

	/**
	 * Clear the composite field, i.e., clear all the linked fields
	 */
	public void clear() {
		state.reset();
		syncStateLater();
	}

	/*
	 * Copies the state from the internal representation to the actual components
	 */
	private void doSyncState() {
		mute.incrementAndGet();
		try {
			for (int i = 0; i < linkedFields.size(); i++) {
				LinkedField lf = linkedFields.get(i);
				FieldState fs = state.fieldStates.get(i);

				if (!fs.text.equals(lf.field.getText())) {
					lf.field.setText(fs.text);
				}
				if (fs.caret != lf.field.getCaretPosition()) {
					lf.field.setCaretPosition(fs.clampedCaret());
				}
			}
			if (haveFocus) {
				linkedFields.get(state.whichFocus).field.grabFocus();
			}
		}
		finally {
			mute.decrementAndGet();
		}
	}

	/**
	 * Get the full composite text
	 * @return the text, including separators
	 */
	public String getText() {
		return state.getText();
	}

	/**
	 * Set the full composite text
	 * @param text the text, including separators
	 */
	public void setText(String text) {
		LinkerState old = state.copy();
		state.setText(text);
		if (!old.equals(state)) {
			syncStateLater();
		}
	}

	/**
	 * Set the location of the caret among the composite text
	 * @param pos the position, including separators
	 * @throws BadLocationException if the position is larger than the composite text
	 */
	public void setCaretPosition(int pos) throws BadLocationException {
		LinkerState old = state.copy();
		state.setGlobalCaret(pos);
		if (!old.equals(state)) {
			syncStateLater();
		}
	}

	/**
	 * Get the text preceding the caret in the given field
	 * @param where the field whose caret to consider
	 * @return the text
	 */
	public String getTextBeforeCursor(JTextField where) {
		int i = findField(where);
		if (i == -1) {
			throw new IllegalArgumentException("" + where);
		}
		return state.getTextBeforeCursor(i);
	}

	/**
	 * Get an individual field in the composite
	 * @param i
	 * @return
	 */
	public JTextField getField(int i) {
		return linkedFields.get(i).field;
	}

	/**
	 * Get the individual field last having focus
	 * 
	 * Effectively, this gives the field containing the composite caret
	 * @return
	 */
	public JTextField getFocusedField() {
		return getField(state.whichFocus);
	}

	/**
	 * Get the number of fields in this composite
	 * @return the field count
	 */
	public int getNumFields() {
		return linkedFields.size();
	}

	/**
	 * Set the visibility of all the component fields
	 * @param visible true to show, false to hide
	 */
	public void setVisible(boolean visible) {
		for (LinkedField lf : linkedFields) {
			lf.field.setVisible(visible);
		}
	}

	/**
	 * Add a focus listener
	 * 
	 * The focus listener will receive a callback only when focus is passed completely outside the
	 * composite text field. No events are generated when focus passes from one field in the
	 * composite to another.
	 * 
	 * @param listener the focus listener to add
	 */
	public void addFocusListener(FocusListener listener) {
		focusListeners.add(listener);
	}

	/**
	 * Remove a focus listener
	 * @param listener the focus listener to remove
	 */
	public void removeFocusListener(FocusListener listener) {
		focusListeners.remove(listener);
	}

	/**
	 * Fire the given event on all registered focus listeners
	 * @param ev
	 */
	protected void fireFocusListeners(FocusEvent ev) {
		switch (ev.getID()) {
			case FocusEvent.FOCUS_GAINED:
				for (FocusListener listener : focusListeners) {
					listener.focusGained(ev);
				}
				break;
			case FocusEvent.FOCUS_LOST:
				for (FocusListener listener : focusListeners) {
					listener.focusLost(ev);
				}
				break;
			default:
				throw new IllegalArgumentException("" + ev);
		}
	}

	/**
	 * A convenient factory to build two fields separated by spaces
	 * @return the linker containing two new linked {@link JTextField}s
	 */
	public static TextFieldLinker twoSpacedFields() {
		TextFieldLinker linker = new TextFieldLinker();
		linker.linkField(new JTextField(), "\\s+", " ");
		linker.linkLastField(new JTextField());
		return linker;
	}

}
