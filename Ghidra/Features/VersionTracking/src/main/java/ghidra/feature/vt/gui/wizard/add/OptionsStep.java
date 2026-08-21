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

import java.util.Map;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.util.HelpLocation;

/**
 * Wizard step for configuring options for the selected correlators when adding to an existing
 * version tracking session.
 */
public class OptionsStep extends WizardStep<AddToSessionData> {
	private OptionsPanel panel;

	protected OptionsStep(WizardModel<AddToSessionData> model) {
		super(model, "Correlator Options",
			new HelpLocation("VersionTrackingPlugin", "Options_Panel"));

		panel = new OptionsPanel(this::notifyStatusChanged);
	}

	@Override
	public void initialize(AddToSessionData data) {
		panel.initialize(data.getCorrelators(), data.getOptions());
	}

	@Override
	public boolean isApplicable(AddToSessionData data) {
		Map<VTProgramCorrelatorFactory, VTOptions> options = data.getOptions();
		return !options.isEmpty();
	}

	@Override
	public boolean isValid() {
		return panel.hasValidOptions();
	}

	@Override
	public boolean canFinish(AddToSessionData data) {
		return true;
	}

	@Override
	public void populateData(AddToSessionData data) {
		// stub
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
