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
package docking.theme.gui;

import java.awt.BorderLayout;
import java.beans.*;

import javax.swing.*;

import docking.DockingWindowManager;
import docking.ReusableDialogComponentProvider;
import generic.theme.ThemeValue;

/**
 * Base class for Theme property Editors (Colors, Fonts, and Icons)
 *
 * @param <T> the base property (Color, Font, or Icon)
 */
public abstract class ThemeValueEditor<T> {
	private PropertyChangeListener clientListener;
	protected ThemeValue<T> currentThemeValue;
	private EditorDialog dialog;
	private String typeName;
	protected PropertyEditor editor;

	/**
	 * Constructor
	 * 
	 * @param typeName the name of the type (Used in the dialog title)
	 * @param listener the {@link PropertyChangeListener} to be notified for changes
	 * @param editor the standard property editor for the type
	 */
	protected ThemeValueEditor(String typeName, PropertyChangeListener listener,
			PropertyEditor editor) {
		this.typeName = typeName;
		this.clientListener = listener;
		this.editor = editor;
	}

	/**
	 * Edits the ThemeValue by invoking the appropriate dialog for editing the type
	 * @param themeValue the value to be edited
	 */
	public void editValue(ThemeValue<T> themeValue) {
		this.currentThemeValue = themeValue;
		if (dialog == null) {
			dialog = new EditorDialog(themeValue);
			DockingWindowManager.showDialog(dialog);
		}
		else {
			dialog.setValue(themeValue);
			dialog.toFront();
		}

	}

	/**
	 * Called when the user has pressed ok.  This allows sub-classes to store any state for
	 * future dialog invocations.
	 */
	protected void storeState() {
		// for sub-classes
	}

	/**
	 * Returns the actual value (Color, Font, or Icon)
	 * @param id the theme property id for the value
	 * @return the current stored value for the id
	 */
	protected abstract T getRawValue(String id);

	/**
	 * Factory method for creating the ThemeValue of the correct type.
	 * @param id the id for theme property
	 * @param newValue the new value for the underlying type (Color, Font, or Icon)
	 * @return the new ThemeValue for the type
	 */
	protected abstract ThemeValue<T> createNewThemeValue(String id, T newValue);

	private void valueChanged(T value) {
		ThemeValue<T> oldValue = currentThemeValue;
		String id = oldValue.getId();
		ThemeValue<T> newValue = createNewThemeValue(id, value);
		firePropertyChangeEvent(oldValue, newValue);
		PropertyChangeEvent event =
			new PropertyChangeEvent(this, id, oldValue, newValue);
		clientListener.propertyChange(event);
	}

	private void firePropertyChangeEvent(ThemeValue<T> oldValue, ThemeValue<T> newValue) {
		PropertyChangeEvent event =
			new PropertyChangeEvent(this, oldValue.getId(), oldValue, newValue);
		clientListener.propertyChange(event);
	}

	class EditorDialog extends ReusableDialogComponentProvider {
		private PropertyChangeListener internalListener = ev -> editorChanged();
		private ThemeValue<T> originalValue;

		protected EditorDialog(ThemeValue<T> initialValue) {
			super("Edit " + typeName + ": " + currentThemeValue.getId(), false, false, true, false);
			this.originalValue = initialValue;
			addWorkPanel(buildWorkPanel(getRawValue(initialValue.getId())));
			addOKButton();
			addCancelButton();
			setRememberSize(false);
		}

		@SuppressWarnings("unchecked")
		private void editorChanged() {
			valueChanged((T) editor.getValue());
		}

		JComponent buildWorkPanel(T initialValue) {
			JPanel panel = new JPanel(new BorderLayout());
			panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
			panel.add(editor.getCustomEditor(), BorderLayout.CENTER);

			editor.setValue(initialValue);
			storeState(); // save the initial value to the history

			editor.addPropertyChangeListener(internalListener);
			return panel;
		}

		void setValue(ThemeValue<T> value) {
			originalValue = value;
			editor.removePropertyChangeListener(internalListener);
			editor.setValue(getRawValue(value.getId()));
			editor.addPropertyChangeListener(internalListener);
		}

		@Override
		protected void okCallback() {
			close();
			storeState();
			dialog = null;
		}

		@Override
		protected void cancelCallback() {
			firePropertyChangeEvent(currentThemeValue, originalValue);
			close();
			dialog = null;
		}

	}
}
