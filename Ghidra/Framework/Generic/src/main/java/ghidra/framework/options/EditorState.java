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
package ghidra.framework.options;

import java.awt.Component;
import java.beans.*;
import java.util.*;

import ghidra.framework.Application;

public class EditorState implements PropertyChangeListener {

	private Object originalValue;
	private Object currentValue;
	private PropertyEditor editor;
	private Set<PropertyChangeListener> listeners = new HashSet<>();
	private Options options;
	private String name;

	public EditorState(Options options, String name) {
		this.options = options;
		this.name = name;
		this.currentValue = options.getObject(name, null);
		this.originalValue = currentValue;
		this.editor = options.getPropertyEditor(name);
		if (editor != null) {
			editor.setValue(currentValue);

			editor.removePropertyChangeListener(this); // don't repeatedly add editors
			editor.addPropertyChangeListener(this);
		}
	}

	void addListener(PropertyChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		EditorState other = (EditorState) obj;
		if (!options.equals(other.options)) {
			return false;
		}
		if (!name.equals(other.name)) {
			return false;
		}

		// editor instances are re-used
		return editor == other.editor;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		currentValue = editor.getValue();
		for (PropertyChangeListener listener : listeners) {
			listener.propertyChange(evt);
		}
	}

	public boolean isValueChanged() {
		return !Objects.equals(currentValue, originalValue);
	}

	public void applyNonDefaults(Options save) {
		if (!Objects.equals(currentValue, options.getDefaultValue(name))) {
			Options sub = save.getOptions(options.getName());
			sub.putObject(name, currentValue);
		}
	}

	public void loadFrom(Options loadFrom) {
		Options sub = loadFrom.getOptions(options.getName());
		Object newValue = sub.getObject(name, options.getDefaultValue(name));
		if (editor != null && !Objects.equals(currentValue, newValue)) {
			editor.setValue(newValue);
		}
	}

	public boolean hasSameValue(Options compareTo) {
		Options sub = compareTo.getOptions(options.getName());
		Object newValue = sub.getObject(name, options.getDefaultValue(name));
		return Objects.equals(newValue, currentValue);
	}

	public void applyValue() {
		if (Objects.equals(currentValue, originalValue)) {
			return;
		}
		boolean success = false;
		try {
			options.putObject(name, currentValue);
			Object newValue = options.getObject(name, null);
			originalValue = newValue;
			currentValue = newValue;
			success = true;
		}
		finally {
			if (!success) {
				editor.setValue(originalValue);
				currentValue = originalValue;
			}
		}
	}

	/**
	 * Returns true if the contained PropertyEditor desired to render and handle it's options
	 * directly, as opposed to using the generic framework.
	 * @return true if the contained PropertyEditor desired to render and handle it's options
	 * directly, as opposed to using the generic framework.
	 */
	public boolean supportsCustomOptionsEditor() {
		return editor == null || (editor instanceof CustomOptionsEditor);
	}

	public Component getEditorComponent() {
		if (editor == null) {
			// can occur if support has been dropped for custom state/option
			editor = new ErrorPropertyEditor(
				"Ghidra does not know how to render state: " + name, null);
			return editor.getCustomEditor();
		}
		if (editor.supportsCustomEditor()) {
			return editor.getCustomEditor();
		}
		if (editor.getValue() instanceof Boolean) {
			return new PropertyBoolean(editor);
		}
		if (editor.getTags() != null) {
			return new PropertySelector(editor);
		}
		if (editor.getAsText() != null) {
			return new PropertyText(editor);
		}

		Class<? extends PropertyEditor> clazz = editor.getClass();
		String clazzName = clazz.getSimpleName();
		if (clazzName.startsWith("String")) {
			// Most likely some kind of string editor with a null value.  Just use a string 
			// property and let the value be empty.
			return new PropertyText(editor);
		}

		editor.removePropertyChangeListener(this);
		editor = new ErrorPropertyEditor(
			Application.getName() + " does not know how to use PropertyEditor: " +
				editor.getClass().getName(),
			null);
		return editor.getCustomEditor();
	}

	public String getTitle() {
		return name;
	}

	public String getDescription() {
		return options.getDescription(name);
	}

}
