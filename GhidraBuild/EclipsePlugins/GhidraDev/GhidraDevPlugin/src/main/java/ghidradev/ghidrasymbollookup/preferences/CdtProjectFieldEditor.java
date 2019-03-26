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
package ghidradev.ghidrasymbollookup.preferences;

import org.eclipse.jface.preference.StringButtonFieldEditor;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.ui.dialogs.ElementListSelectionDialog;

import ghidradev.ghidrasymbollookup.utils.CdtUtils;

/**
 * A field editor that lets the user select an open CDT project.
 */
public class CdtProjectFieldEditor extends StringButtonFieldEditor {

	/**
	 * Creates a new CDT project field editor.
	 * 
	 * @param name the name of the preference this field editor works on
	 * @param labelText the label text of the field editor
	 * @param parent the parent of the field editor's control
	 */
	public CdtProjectFieldEditor(String name, String labelText, Composite parent) {
		super(name, labelText, parent);
	}

	@Override
	protected String changePressed() {
		ElementListSelectionDialog dialog =
			new ElementListSelectionDialog(getShell(), new LabelProvider());
		dialog.setTitle("CDT project selection");
		dialog.setMessage("Select an open CDT project:");
		dialog.setElements(CdtUtils.getCDTProjects().stream().map(p -> p.getName()).toArray());
		dialog.open();
		Object[] result = dialog.getResult();
		if (result != null && result.length > 0 && result[0] instanceof String) {
			return (String) result[0];
		}
		return null;
	}
}
