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

import java.util.List;

import javax.swing.JComponent;

import docking.wizard.WizardStep;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.util.HelpLocation;

/**
 * Wizard step for choosing which correlators to run when adding to an existing version
 * tracking session.
 */
public class CorrelatorChooserStep extends WizardStep<AddToSessionData> {
	private CorrelatorChooserPanel panel;

	public CorrelatorChooserStep(VTAddToSessionWizardModel model, VTSession session) {
		super(model, "Select Correlation Algorithm(s)",
			new HelpLocation("VersionTrackingPlugin", "Correlator_Panel"));

		panel = new CorrelatorChooserPanel(session, this::notifyStatusChanged);
	}

	@Override
	public void initialize(AddToSessionData data) {
		// nothing to do
	}

	@Override
	public boolean isValid() {
		List<VTProgramCorrelatorFactory> correlators = panel.getSelectedCorrelators();
		if (!correlators.isEmpty()) {
			return true;
		}
		return false;
	}

	@Override
	public void populateData(AddToSessionData data) {
		data.setCorrelators(panel.getSelectedCorrelators());
	}

	@Override
	public boolean apply(AddToSessionData data) {
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public boolean canFinish(AddToSessionData data) {
		return data.getCorrelators() != null;
	}

}
