/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

import java.awt.GridLayout;

import docking.wizard.*;

public class LimitAddressSetsPanel extends AbstractMageJPanel<VTWizardStateKey> {

	private AddressSetPanel sourcePanel;
	private AddressSetPanel destinationPanel;

	public LimitAddressSetsPanel(PluginTool tool) {

		setLayout(new GridLayout());
		sourcePanel =
			new AddressSetPanel(tool, "Source", VTWizardStateKey.SOURCE_PROGRAM_FILE,
				VTWizardStateKey.SOURCE_PROGRAM, VTWizardStateKey.SOURCE_ADDRESS_SET_VIEW,
				VTWizardStateKey.SOURCE_SELECTION, VTWizardStateKey.SOURCE_ADDRESS_SET_CHOICE);
		destinationPanel =
			new AddressSetPanel(tool, "Destination", VTWizardStateKey.DESTINATION_PROGRAM_FILE,
				VTWizardStateKey.DESTINATION_PROGRAM,
				VTWizardStateKey.DESTINATION_ADDRESS_SET_VIEW,
				VTWizardStateKey.DESTINATION_SELECTION,
				VTWizardStateKey.DESTINATION_ADDRESS_SET_CHOICE);
		add(sourcePanel);
		add(destinationPanel);
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", "Select_Address_Ranges_Panel");
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		sourcePanel.addDependencies(state);
		destinationPanel.addDependencies(state);
	}

	@Override
	public void dispose() {
		sourcePanel.dispose();
		destinationPanel.dispose();
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		sourcePanel.enterPanel(state);
		destinationPanel.enterPanel(state);
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(
			WizardState<VTWizardStateKey> state) {
		WizardPanelDisplayability sourceDisplayability =
			sourcePanel.getPanelDisplayabilityAndUpdateState(state);
		destinationPanel.getPanelDisplayabilityAndUpdateState(state);
		// Use the displayability of the source panel as that of the source/destination combined.
		return sourceDisplayability;
	}

	@Override
	public void leavePanel(WizardState<VTWizardStateKey> state) {
		sourcePanel.leavePanel(state);
		destinationPanel.leavePanel(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<VTWizardStateKey> state) {
		sourcePanel.updateStateObjectWithPanelInfo(state);
		destinationPanel.updateStateObjectWithPanelInfo(state);
	}

	@Override
	public String getTitle() {
		return "Select Address Range(s)";
	}

	@Override
	public void initialize() {
		sourcePanel.initialize();
		destinationPanel.initialize();
	}

	@Override
	public boolean isValidInformation() {
		return sourcePanel.isValidInformation() && destinationPanel.isValidInformation();

	}
}
