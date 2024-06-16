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

import java.beans.PropertyChangeListener;

import javax.swing.JComponent;

import ghidra.util.exception.InvalidInputException;

/**
 *
 * Interface to define methods for an editor that supplies its own
 * component to be displayed in the OptionsDialog.
 */
public interface OptionsEditor {

	/**
	 * Apply the changes.
	 */
	public void apply() throws InvalidInputException;

	/**
	 * Cancel the changes.
	 */
	public void cancel();

	/**
	 * A signal to reload the GUI widgets in the component created by this editor.  This will 
	 * happen when the options change out from under the editor, such as when the user restores
	 * the default options values.
	 */
	public void reload();

	/**
	 * Sets the options change listener
	 * @param listener
	 */
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener);

	/**
	 * Get the editor component.
	 * 
	 * @param options The editable options that for which a GUI component will be created
	 * @param editorStateFactory The factory that will provide state objects this options editor
	 */
	public JComponent getEditorComponent(Options options, EditorStateFactory editorStateFactory);

	/**
	 * Dispose this editor
	 */
	public void dispose();
}
