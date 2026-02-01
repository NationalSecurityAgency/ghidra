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

import docking.wizard.WizardStep;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Wizard step for choosing the addresses to apply for adding correlation runs to an existing
 * version tracking session.
 */
public class LimitAddressSetsStep extends WizardStep<AddToSessionData> {
	private LimitAddressSetsPanel panel;

	public LimitAddressSetsStep(VTAddToSessionWizardModel model, PluginTool tool) {
		super(model, "Select Address Range(s)",
			new HelpLocation("VersionTrackingPlugin", "Select_Address_Ranges_Panel"));

		panel = new LimitAddressSetsPanel(tool);
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
	public boolean apply(AddToSessionData data) {
		return true;
	}

	@Override
	public void populateData(AddToSessionData data) {
		panel.apply(data);
	}

	@Override
	public boolean isApplicable(AddToSessionData data) {
		return data.shouldLimitAddressSets();
	}

	@Override
	public boolean canFinish(AddToSessionData data) {
		return true;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
