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

/**
 * Adapter for a composite editor model listener. 
 */
public class CompositeEditorModelAdapter implements CompositeEditorModelListener {

	public CompositeEditorModelAdapter() {
	}

	@Override
	public void compositeEditStateChanged(int type) {
		// do nothing by default
	}

	@Override
	public void endFieldEditing() {
		// do nothing by default
	}

	@Override
	public void componentDataChanged() {
		// do nothing by default
	}

	@Override
	public void compositeInfoChanged() {
		// do nothing by default
	}

	@Override
	public void statusChanged(String message, boolean beep) {
		// do nothing by default
	}

	@Override
	public void selectionChanged() {
		// do nothing by default
	}

	@Override
	public void showUndefinedStateChanged(boolean showUndefinedBytes) {
		// do nothing by default
	}

}
