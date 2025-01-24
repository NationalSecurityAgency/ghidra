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
package ghidra.feature.vt.gui.wizard.session;

import javax.swing.JComponent;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Wizard step for running version tracking precondition tests when creating a new version tracking
 * session.
 */
public class PreconditionsStep extends WizardStep<NewSessionData> {
	private PreconditionsPanel preconditionsPanel;

	protected PreconditionsStep(WizardModel<NewSessionData> model) {
		super(model, "Precondition Checklist",
			new HelpLocation("VersionTrackingPlugin", "Preconditions_Panel"));

		preconditionsPanel = new PreconditionsPanel(model, this::notifyStatusChanged);
	}

	@Override
	public void initialize(NewSessionData data) {
		if (!data.hasPerformedPreconditionChecks()) {
			Program sourceProgram = data.getSourceProgram();
			Program destinationProgram = data.getDestinationProgram();
			preconditionsPanel.initializeTests(sourceProgram, destinationProgram);
		}
	}

	@Override
	public boolean isValid() {
		boolean hasRunTests = preconditionsPanel.hasRunTests();
		if (hasRunTests) {
			return true;
		}
		return false;
	}

	@Override
	public void populateData(NewSessionData data) {
		data.setPerformedPreconditionChecks(true);
	}

	@Override
	public boolean apply(NewSessionData data) {
		return true;
	}

	@Override
	public boolean canFinish(NewSessionData data) {
		return data.hasPerformedPreconditionChecks();
	}

	@Override
	public JComponent getComponent() {
		return preconditionsPanel;
	}

	@Override
	protected void dispose(NewSessionData data) {
		preconditionsPanel.dispose();
	}

}
