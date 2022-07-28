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

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.theme.ThemeValue;

/**
 * Base class for Theme properties (Colors, Fonts, and Icons)
 *
 * @param <T> the base property (Color, Font, or Icon)
 */
public abstract class ThemeValueEditor<T> {
	private PropertyChangeListener clientListener;
	protected ThemeValue<T> currentThemeValue;
	private EditorDialog dialog;
	private String typeName;
	private PropertyEditor editor;

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
		T value = getRawValue(themeValue.getId());
		if (dialog == null) {
			dialog = new EditorDialog(value);
			DockingWindowManager.showDialog(dialog);
		}
		else {
			dialog.setValue(value);
			dialog.toFront();
		}

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

	private void valueChanged(T newValue) {
		ThemeValue<T> oldValue = currentThemeValue;
		String id = oldValue.getId();
		PropertyChangeEvent event =
			new PropertyChangeEvent(this, id, oldValue, createNewThemeValue(id, newValue));
		clientListener.propertyChange(event);
	}

	class EditorDialog extends DialogComponentProvider {
		private PropertyChangeListener internalListener = ev -> editorChanged();
		private T originalValue;

		protected EditorDialog(T initialValue) {
			super("Edit " + typeName + ": " + currentThemeValue.getId(), false, false, true, false);
			this.originalValue = initialValue;
			addWorkPanel(buildWorkPanel(initialValue));
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
			editor.addPropertyChangeListener(internalListener);
			return panel;
		}

		void setValue(T value) {
			originalValue = value;
			editor.removePropertyChangeListener(internalListener);
			editor.setValue(value);
			editor.addPropertyChangeListener(internalListener);
		}

		@Override
		protected void okCallback() {
			close();
			dialog = null;
		}

		@Override
		protected void cancelCallback() {
			valueChanged(originalValue);
			close();
			dialog = null;
		}
	}
}
