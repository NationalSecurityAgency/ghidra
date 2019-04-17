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
package ghidradev.ghidrascripteditor.preferences;

import org.eclipse.jface.preference.*;
import org.eclipse.jface.util.PropertyChangeEvent;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

import ghidradev.Activator;
import ghidradev.ghidrascripteditor.ScriptEditorInitializer;

/**
 * This class represents a preference page that
 * is contributed to the Preferences dialog. By 
 * subclassing <samp>FieldEditorPreferencePage</samp>, we
 * can use the field support built into JFace that allows
 * us to create a page that is small and knows how to 
 * save, restore and apply itself.
 * <p>
 * This page is used to modify preferences only. They
 * are stored in the preference store that belongs to
 * the main plug-in class. That way, preferences can
 * be accessed directly via the preference store.
 */

public class GhidraScriptEditorPreferencePage extends FieldEditorPreferencePage implements
		IWorkbenchPreferencePage {

	private BooleanFieldEditor enabledField;
	private StringFieldEditor portField;

	private String previousEnabledString = null;
	private String currentEnabledString = null;
	private String previousPortString = null;
	private String currentPortString = null;

	public GhidraScriptEditorPreferencePage() {
		super(GRID);
	}

	@Override
	public void init(IWorkbench workbench) {
		setPreferenceStore(Activator.getDefault().getPreferenceStore());
	}

	@Override
	public void createFieldEditors() {
		enabledField =
			new BooleanFieldEditor(GhidraScriptEditorPreferences.GHIDRA_SCRIPT_EDITOR_ENABLED,
				"Enabled", getFieldEditorParent());
		portField =
			new StringFieldEditor(GhidraScriptEditorPreferences.GHIDRA_SCRIPT_EDITOR_PORT_NUMBER,
				"Port:", getFieldEditorParent());

		addField(enabledField);
		addField(portField);
	}

	@Override
	public void checkState() {
		super.checkState();
		if (!isValid()) {
			return;
		}
		String portValue = portField.getStringValue();
		if (!portValue.isEmpty()) {
			try {
				int portNumber = Integer.parseInt(portValue);
				if (portNumber < 1024 || portNumber > 0xFFFF) {
					setErrorMessage("Port must be between 1024 and 65535.");
					setValid(false);
					return;
				}
			}
			catch (NumberFormatException e) {
				setErrorMessage("Port must be an integer.");
				setValid(false);
				return;
			}
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent event) {
		super.propertyChange(event);
		if (event.getProperty().equals(FieldEditor.VALUE)) {
			checkState();
		}
		if (event.getSource() == enabledField) {
			if (previousEnabledString == null) {
				previousEnabledString = event.getOldValue().toString();
			}
			currentEnabledString = event.getNewValue().toString();
		}
		else if (event.getSource() == portField) {
			if (previousPortString == null) {
				previousPortString = event.getOldValue().toString();
			}
			currentPortString = event.getNewValue().toString();
		}
	}

	@Override
	public boolean performOk() {
		super.performOk();
		boolean enabledWasChanged = false;
		boolean portWasChanged = false;
		if (currentEnabledString != null && previousEnabledString != null) {
			if (!currentEnabledString.equals(previousEnabledString)) {
				enabledWasChanged = true;
			}
		}
		if (currentPortString != null && previousPortString != null) {
			if (!currentPortString.equals(previousPortString)) {
				portWasChanged = true;
			}
		}
		ScriptEditorInitializer.notifyPreferencesChanged(enabledWasChanged, portWasChanged);
		previousEnabledString = null;
		previousPortString = null;
		return true;
	}

	@Override
	public boolean performCancel() {
		super.performCancel();
		previousEnabledString = null;
		previousPortString = null;
		return true;
	}

}
