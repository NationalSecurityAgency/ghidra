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
package ghidra.feature.vt.gui.wizard;

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.*;

import docking.widgets.label.GDHtmlLabel;
import docking.wizard.*;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.gui.wizard.ChooseAddressSetEditorPanel.AddressSetChoice;
import ghidra.framework.model.DomainFile;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;
import util.CollectionUtils;

public class SummaryPanel extends AbstractMageJPanel<VTWizardStateKey> {
	private JLabel labelLabel;
	private JLabel summaryLabel;
	private static String NEW_SUMMARY_PANEL = "New_Session_Summary_Panel";
	private static String ADD_SUMMARY_PANEL = "Add_To_Session_Summary_Panel";
	private String helpName = ADD_SUMMARY_PANEL;

	SummaryPanel() {

		labelLabel = new GDHtmlLabel();
		summaryLabel = new GDHtmlLabel();

		JPanel mainPanel = new JPanel(new PairLayout(5, 10));
		mainPanel.add(labelLabel);
		mainPanel.add(summaryLabel);

		setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
		setLayout(new BorderLayout());
		add(mainPanel, BorderLayout.CENTER);
	}

	@Override
	public void dispose() {
		// nothing to do
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", helpName);
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		StringBuilder label = new StringBuilder();
		StringBuilder summary = new StringBuilder();

		label.append("<html>");
		summary.append("<html>");

		// session mode

		label.append("Operation:");
		String opDescription = (String) state.get(VTWizardStateKey.WIZARD_OP_DESCRIPTION);
		helpName = ((opDescription != null) && opDescription.startsWith("New")) ? NEW_SUMMARY_PANEL
				: ADD_SUMMARY_PANEL;
		summary.append(opDescription);
		label.append("<br>");
		summary.append("<br>");

		String sessionName = (String) state.get(VTWizardStateKey.SESSION_NAME);

		label.append("Session Name:");
		summary.append(sessionName);
		label.append("<br>");
		summary.append("<br>");

		String sourceProgramName = null;
		String destinationProgramName = null;

		DomainFile sourceProgram = (DomainFile) state.get(VTWizardStateKey.SOURCE_PROGRAM_FILE);
		sourceProgramName = sourceProgram.getName();

		DomainFile destinationProgram =
			(DomainFile) state.get(VTWizardStateKey.DESTINATION_PROGRAM_FILE);
		destinationProgramName = destinationProgram.getName();

		// source program

		label.append("Source Program:");
		summary.append(
			sourceProgramName == null ? "(null)" : HTMLUtilities.escapeHTML(sourceProgramName));
		label.append("<br>");
		summary.append("<br>");

		// destination program

		label.append("Destination Program:");
		summary.append(destinationProgramName == null ? "(null)"
				: HTMLUtilities.escapeHTML(destinationProgramName));
		label.append("<br>");
		summary.append("<br>");

		String correlatorLabel = "";
		String correlatorName = null;

		List<VTProgramCorrelatorFactory> correlators = getCorrelators(state);
		if (correlators != null) {
			for (VTProgramCorrelatorFactory correlatorFactory : correlators) {
				correlatorName = correlatorFactory.getName();

				label.append(correlatorLabel + "Program Correlator:");
				summary.append(correlatorName == null ? "(null)" : correlatorName);
				label.append("<br>");
				summary.append("<br>");

			}
		}

		Boolean excludeAcceptedMatches =
			(Boolean) state.get(VTWizardStateKey.EXCLUDE_ACCEPTED_MATCHES);
		if (excludeAcceptedMatches != null) {
			label.append("Exclude Accepted Matches:");
			summary.append(excludeAcceptedMatches.booleanValue() ? "Yes" : "No");
			label.append("<br>");
			summary.append("<br>");
		}

		Boolean showAddressSetPanels =
			(Boolean) state.get(VTWizardStateKey.SHOW_ADDRESS_SET_PANELS);
		if (showAddressSetPanels != null) {
			boolean manuallySpecifiedAddresses = showAddressSetPanels.booleanValue();
			AddressSetChoice sourceAddressSetChoice =
				(AddressSetChoice) state.get(VTWizardStateKey.SOURCE_ADDRESS_SET_CHOICE);
			AddressSetChoice destinationAddressSetChoice =
				(AddressSetChoice) state.get(VTWizardStateKey.DESTINATION_ADDRESS_SET_CHOICE);
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
		}

		label.append("</html>");
		summary.append("</html>");

		labelLabel.setText(label.toString());
		summaryLabel.setText(summary.toString());
	}

	private List<VTProgramCorrelatorFactory> getCorrelators(WizardState<VTWizardStateKey> state) {
		List<?> list = (List<?>) state.get(VTWizardStateKey.PROGRAM_CORRELATOR_FACTORY_LIST);
		if (list == null) {
			return null;
		}
		return CollectionUtils.asList(list, VTProgramCorrelatorFactory.class);
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(
			WizardState<VTWizardStateKey> state) {
		return WizardPanelDisplayability.CAN_BE_DISPLAYED;
	}

	@Override
	public void leavePanel(WizardState<VTWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<VTWizardStateKey> state) {
		// Do nothing. The summary panel only displays information.
	}

	@Override
	public String getTitle() {
		return "Summary";
	}

	@Override
	public void initialize() {
		// nothing to do
	}

	@Override
	public boolean isValidInformation() {
		return true;
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		// no dependencies; we just confirm what's going to happen
	}
}
