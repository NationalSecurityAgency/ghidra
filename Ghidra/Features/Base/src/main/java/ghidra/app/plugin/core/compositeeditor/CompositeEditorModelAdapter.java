/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * Adapter for a composite editor model listener. 
 */
public class CompositeEditorModelAdapter
	implements CompositeEditorModelListener {

	public CompositeEditorModelAdapter() {
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#compositeEditStateChanged(int)
	 */
	public void compositeEditStateChanged(int type) {
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#endFieldEditing()
	 */
	public void endFieldEditing() {
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeViewerModelListener#componentDataChanged()
	 */
	public void componentDataChanged() {
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeViewerModelListener#compositeInfoChanged()
	 */
	public void compositeInfoChanged() {
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeViewerModelListener#statusChanged(java.lang.String, boolean)
	 */
	public void statusChanged(String message, boolean beep) {
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeViewerModelListener#selectionChanged()
	 */
	public void selectionChanged() {
	}

	public void showUndefinedStateChanged(boolean showUndefinedBytes) {
		// TODO Auto-generated method stub
		
	}

}
