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
package ghidradev.ghidraprojectcreator.wizards.pages;

import java.util.*;

import org.eclipse.jface.wizard.WizardPage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.*;

import ghidradev.ghidraprojectcreator.utils.GhidraModuleUtils.ModuleTemplateType;

/**
 * A wizard page that lets the user configure a new Ghidra module project.
 */
public class ConfigureGhidraModuleProjectWizardPage extends WizardPage {

	private Map<Button, ModuleTemplateType> moduleTemplateCheckboxMap;

	/**
	 * Creates a new Ghidra module project configuration wizard page.
	 */
	public ConfigureGhidraModuleProjectWizardPage() {
		super("ConfigureGhidraModuleProjectWizardPage");
		setTitle("Configure Ghidra Module Project");
		setDescription("Configure a new Ghidra module project.");

		moduleTemplateCheckboxMap = new HashMap<>();
	}

	@Override
	public void createControl(Composite parent) {

		Composite container = new Composite(parent, SWT.NULL);
		container.setLayout(new GridLayout(1, false));

		Label moduleTemplateLabel = new Label(container, SWT.NULL);
		moduleTemplateLabel.setText("Module template:");
		Group moduleTemplateGroup = new Group(container, SWT.SHADOW_ETCHED_OUT);
		moduleTemplateGroup.setLayout(new RowLayout(SWT.VERTICAL));

		SelectionListener selectionListener = new SelectionListener() {
			@Override
			public void widgetSelected(SelectionEvent evt) {
				validate();
			}

			@Override
			public void widgetDefaultSelected(SelectionEvent evt) {
				validate();
			}
		};

		for (ModuleTemplateType moduleTemplateType : ModuleTemplateType.values()) {
			Button checkboxButton = new Button(moduleTemplateGroup, SWT.CHECK);
			checkboxButton.setSelection(true);
			checkboxButton.setText(
				moduleTemplateType.getName() + " - " + moduleTemplateType.getDescription());
			checkboxButton.setToolTipText(moduleTemplateType.getDescription());
			checkboxButton.addSelectionListener(selectionListener);
			moduleTemplateCheckboxMap.put(checkboxButton, moduleTemplateType);

		}

		validate();
		setControl(container);
	}

	/**
	 * Gets the selected module template types.
	 * 
	 * @return The selected module template types.
	 */
	public Set<ModuleTemplateType> getModuleTemplateTypes() {
		Set<ModuleTemplateType> moduleTemplateTypes = new HashSet<>();
		for (Button checkboxButton : moduleTemplateCheckboxMap.keySet()) {
			if (checkboxButton.isEnabled() && checkboxButton.getSelection()) {
				moduleTemplateTypes.add(moduleTemplateCheckboxMap.get(checkboxButton));
			}
		}
		return moduleTemplateTypes;
	}

	/**
	 * Validates the fields on the page and updates the page's status.
	 * Should be called every time a field on the page changes.
	 */
	private void validate() {
		setErrorMessage(null);
		setPageComplete(true);
	}
}
