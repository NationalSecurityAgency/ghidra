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
package ghidra.feature.vt.gui.wizard.add;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.util.HelpLocation;

/**
 * Wizard step for configuring address sets when adding correlations to an existing version 
 * tracking session.
 */
public class AddressSetOptionsStep extends WizardStep<AddToSessionData> {
	private AddressSetOptionsPanel panel;

	protected AddressSetOptionsStep(WizardModel<AddToSessionData> model) {
		super(model, "Address Set Options",
			new HelpLocation("VersionTrackingPlugin", "Address_Set_Panel"));
		panel = new AddressSetOptionsPanel();
	}

	@Override
	public void initialize(AddToSessionData data) {
		panel.initialize(data);
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public void populateData(AddToSessionData data) {
		panel.updateChoices(data);
	}

	@Override
	public boolean canFinish(AddToSessionData data) {
		return true;
	}

	@Override
	public boolean apply(AddToSessionData data) {
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
