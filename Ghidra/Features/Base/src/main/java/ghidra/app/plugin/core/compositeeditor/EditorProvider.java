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
package ghidra.app.plugin.core.compositeeditor;

import docking.ComponentProvider;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;

/**
 * Interface implemented by data type editors.
 */
public interface EditorProvider {

	/**
	 * Get the name of this editor.
	 * @return the name of this editor
	 */
	public String getName();

	/**
	 * Get the pathname of the data type being edited.
	 * @return the pathname of the data type being edited
	 */
	public DataTypePath getDtPath();

	/**
	 * Get the component provider for this editor.
	 * @return the component provider for this editor
	 */
	public ComponentProvider getComponentProvider();

	/**
	 * {@return the edited datatype's original datatype manager.}
	 */
	public DataTypeManager getDataTypeManager();

	/**
	 * Return whether this editor is editing the data type with the given path.
	 * @param dtPath path of a data type
	 * @return true if the data type for the pathname is being edited
	 */
	public boolean isEditing(DataTypePath dtPath);

	/**
	 * Add an editor listener that will be notified when the edit window is closed.
	 * @param listener the listener
	 */
	public void addEditorListener(EditorListener listener);

	/**
	 * Show the editor.
	 */
	public void show();

	/**
	 * Returns whether changes need to be saved.
	 * @return whether changes need to be saved
	 */
	public boolean needsSave();

	/**
	  * Prompt the user if this editor has changes that need saving.
	  * @param allowCancel true means that the user can cancel the edits
	  * @return true if the user doesn't cancel.
	  */
	public boolean checkForSave(boolean allowCancel);

	/**
	 * Dispose of resource that this editor may be using.
	 */
	public void dispose();
}
