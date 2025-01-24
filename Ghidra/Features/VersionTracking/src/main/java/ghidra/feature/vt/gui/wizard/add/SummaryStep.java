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

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.gui.wizard.add.AddToSessionData.AddressSetChoice;
import ghidra.feature.vt.gui.wizard.session.SummaryPanel;
import ghidra.framework.model.DomainFile;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;

/**
 * Wizard step in the "add to tracking session" wizard for summarizing the information that
 * will be used to add correlations to a version tracking session.
 */
public class SummaryStep extends WizardStep<AddToSessionData> {
	private SummaryPanel summaryPanel;

	protected SummaryStep(WizardModel<AddToSessionData> model) {
		super(model, "Summary",
			new HelpLocation("VersionTrackingPlugin", "New_Session_Summary_Panel"));

		summaryPanel = new SummaryPanel();
	}

	@Override
	public void initialize(AddToSessionData data) {
		StringBuilder label = new StringBuilder();
		StringBuilder summary = new StringBuilder();

		label.append("<html>");
		summary.append("<html>");

		// session mode

		label.append("Operation:");
		summary.append("Add to Version Tracking Session");
		label.append("<br>");
		summary.append("<br>");

		String sessionName = data.getSession().getName();

		label.append("Session Name:");
		summary.append(sessionName);
		label.append("<br>");
		summary.append("<br>");

		String sourceProgramName = null;
		String destinationProgramName = null;

		DomainFile sourceProgram = data.getSourceFile();
		sourceProgramName = sourceProgram.getName();

		DomainFile destinationProgram = data.getDestinationFile();
		destinationProgramName = destinationProgram.getName();

		// source program

		label.append("Source Program:");
		summary.append(HTMLUtilities.escapeHTML(sourceProgramName));
		label.append("<br>");
		summary.append("<br>");

		// destination program

		label.append("Destination Program:");
		summary.append(HTMLUtilities.escapeHTML(destinationProgramName));
		label.append("<br>");
		summary.append("<br>");

		String correlatorLabel = "";
		String correlatorName = null;

		List<VTProgramCorrelatorFactory> correlators = data.getCorrelators();
		for (VTProgramCorrelatorFactory correlatorFactory : correlators) {
			correlatorName = correlatorFactory.getName();

			label.append(correlatorLabel + "Program Correlator:");
			summary.append(correlatorName == null ? "(null)" : correlatorName);
			label.append("<br>");
			summary.append("<br>");
		}
		boolean excludeAcceptedMatches = data.shouldExcludeAcceptedMatches();
		label.append("Exclude Accepted Matches:");
		summary.append(excludeAcceptedMatches ? "Yes" : "No");
		label.append("<br>");
		summary.append("<br>");

		AddressSetChoice sourceAddressSetChoice = data.getSourceAddressSetChoice();
		AddressSetChoice destinationAddressSetChoice = data.getDestinationAddressSetChoice();
		String sourceAddressesInfo =
			(sourceAddressSetChoice == AddressSetChoice.MANUALLY_DEFINED) ? "Manually Defined"
					: ((sourceAddressSetChoice == AddressSetChoice.SELECTION))
							? "Source Tool Selection"
							: "Entire Source Program";
		String destinationAddressesInfo =
			(destinationAddressSetChoice == AddressSetChoice.MANUALLY_DEFINED)
					? "Manually Defined"
					: ((destinationAddressSetChoice == AddressSetChoice.SELECTION))
							? "Destination Tool Selection"
							: "Entire Destination Program";

		label.append("Source Address Set:");
		summary.append(sourceAddressesInfo);
		label.append("<br>");
		summary.append("<br>");

		label.append("Destination Address Set:");
		summary.append(destinationAddressesInfo);
		label.append("<br>");
		summary.append("<br>");

		label.append("</html>");
		summary.append("</html>");

		summaryPanel.initialize(label.toString(), summary.toString());
	}

	@Override
	public boolean isValid() {
		return true;
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
	public void populateData(AddToSessionData data) {
		// nothing to do
	}

	@Override
	public JComponent getComponent() {
		return summaryPanel;
	}

}
