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

import java.awt.Color;
import java.awt.event.FocusEvent;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

import javax.swing.InputVerifier;
import javax.swing.JFormattedTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import ghidra.util.SystemUtilities;

/**
 * {@link GFormattedTextField} provides an implementation of {@link JFormattedTextField} 
 * which facilitates entry validation with an indication of its current status.
 * <br>
 * When modified from its default value the field background will reflect its 
 * current status.
 */
public class GFormattedTextField extends JFormattedTextField {
	private static final Color ERROR_BACKGROUND_COLOR =
		new GColor("color.bg.formatted.field.error");
	private static final Color EDITING_BACKGROUND_COLOR =
		new GColor("color.bg.formatted.field.editing");
	private static final Color EDITING_FOREGROUND_COLOR =
		new GColor("color.fg.formatted.field.editing");

	public static enum Status {
		UNCHANGED, CHANGED, INVALID;
	}

	private Set<TextEntryStatusListener> listeners = new HashSet<>();

	private Status currentStatus = Status.UNCHANGED;
	private Object defaultValue;
	private String defaultText;
	private boolean isError;
	private boolean ignoreFocusEditChanges;

	/** A flag to let us know when we can ignore focus updates */
	private boolean isProcessingFocusEvent;

	public GFormattedTextField(AbstractFormatterFactory factory, Object defaultValue) {
		super(factory);

		setValue(defaultValue);

		getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				updateText();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				updateText();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateText();
			}
		});

		setDefaultValue(defaultValue);

		addPropertyChangeListener("value", evt -> editingFinished());
	}

	/**
	 * Establish default value.  Text field value should be set before invoking this method.
	 * @param defaultValue default value
	 */
	public void setDefaultValue(Object defaultValue) {
		this.defaultValue = defaultValue;
		this.defaultText = getText(); // get the formatted text
		update();
	}

	/**
	 * Returns the default text.  This is useful to know what the original text is after the user
	 * has edited the text.
	 * @return the default text
	 */
	public String getDefaultText() {
		return defaultText;
	}

	public void disableFocusEventProcessing() {
		ignoreFocusEditChanges = true;
	}

	@Override
	public int getFocusLostBehavior() {
		if (ignoreFocusEditChanges) {
			return -1; // force us to ignore the focus event
		}
		return super.getFocusLostBehavior();
	}

	@Override
	protected void processFocusEvent(FocusEvent e) {
		isProcessingFocusEvent = true;
		super.processFocusEvent(e);
		isProcessingFocusEvent = false;
	}

	public Status getTextEntryStatus() {
		return currentStatus;
	}

	public void addTextEntryStatusListener(TextEntryStatusListener listener) {
		listeners.add(listener);
	}

	private void textEntryStatusChanged(Status status) {
		currentStatus = status;
		if (listeners == null) {
			return; // happens during construction
		}

		for (TextEntryStatusListener listener : listeners) {
			listener.statusChanged(this);
		}
	}

	private void updateText() {
		if (isProcessingFocusEvent) {
			return; // ignore transient events
		}

		InputVerifier verifier = getInputVerifier();
		if (verifier != null) {
			setIsError(!verifier.verify(this));
		}

		update();
	}

	@Override
	public void setText(String t) {
		if (SystemUtilities.isEqual(getText(), t)) {
			return;
		}
		super.setText(t);
		update();
	}

	public void setIsError(boolean isError) {
		//            if ( isError && !this.isError ) {
		//                warn(); // only warn if we were not already in an error situation
		//            }
		this.isError = isError;
		update();
	}

	/**
	 * Restores this field to its default text.
	 */
	public void reset() {
		setText(defaultText);
		update();
	}

	/**
	 * Returns true if the contents of this field do not match the default.
	 * @return true if the contents of this field do not match the default.
	 */
	public boolean isChanged() {
		return getTextEntryStatus() != Status.UNCHANGED;
	}

	/**
	 * Returns true if the contents of this field are invalid, as determined by the InputValidator.
	 * @return true if the contents of this field are invalid, as determined by the InputValidator.
	 */
	public boolean isInvalid() {
		return getTextEntryStatus() == Status.INVALID;
	}

	public void editingFinished() {
		update();
	}

	private boolean hasNonDefaultValue() {
		if (defaultText == null) {
			return false; // not yet initialized
		}

		AbstractFormatter formatter = getFormatter();
		if (formatter == null) {
			return hasNonDefaultText(); // no formatter implies a text only field
		}

		try {
			Object value = formatter.stringToValue(getText());
			if (value == null) {
				return true; // assume empty string or invalid text
			}
			return !value.equals(defaultValue);
		}
		catch (ParseException e) {
			return true;
		}
	}

	private boolean hasNonDefaultText() {
		return !getText().equals(defaultText);
	}

	private void update() {
		updateStatus();
		if (isError) {
			setForeground(Colors.FOREGROUND);
			setBackground(ERROR_BACKGROUND_COLOR);
		}
		else if (hasNonDefaultValue()) {
			setForeground(EDITING_FOREGROUND_COLOR);
			setBackground(EDITING_BACKGROUND_COLOR);
		}
		else { // default
			setForeground(Colors.FOREGROUND);
			setBackground(Colors.BACKGROUND);
		}

		textEntryStatusChanged(currentStatus);
	}

	private void updateStatus() {
		Status oldStatus = currentStatus;
		if (isError) {
			currentStatus = Status.INVALID;
		}

		else if (hasNonDefaultValue()) {
			currentStatus = Status.CHANGED;
		}
		else {
			currentStatus = Status.UNCHANGED;
		}

		if (oldStatus != currentStatus) {
			textEntryStatusChanged(currentStatus);
		}
	}
}
