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
package ghidra.app.plugin.core.debug.utils;

import java.awt.Component;
import java.beans.PropertyEditor;

import ghidra.framework.options.*;

public enum MiscellaneousUtils {
	;
	/**
	 * Obtain a swing component which may be used to edit the property.
	 * 
	 * <p>
	 * This has been shamelessly stolen from {@link EditorState#getEditorComponent()}, which seems
	 * entangled with Ghidra's whole options system. I think this portion could be factored out.
	 * 
	 * @param editor the editor for which to obtain an interactive component for editing
	 * @return the component
	 */
	public static Component getEditorComponent(PropertyEditor editor) {
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

		throw new IllegalStateException(
			"Ghidra does not know how to use PropertyEditor: " + editor.getClass().getName());
	}
}
