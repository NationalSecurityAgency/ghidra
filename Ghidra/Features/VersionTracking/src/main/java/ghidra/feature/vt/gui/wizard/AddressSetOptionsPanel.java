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

import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;

import docking.widgets.checkbox.GCheckBox;
import docking.wizard.*;
import ghidra.feature.vt.api.main.VTProgramCorrelatorAddressRestrictionPreference;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VerticalLayout;

public class AddressSetOptionsPanel extends AbstractMageJPanel<VTWizardStateKey> {

	private JCheckBox excludeCheckbox;
	private JCheckBox showAddressSetPanelsCheckbox;

	public AddressSetOptionsPanel() { //
		setBorder(BorderFactory.createEmptyBorder(40, 40, 0, 0));

		excludeCheckbox = new GCheckBox("Exclude accepted matches", false);
		String excludeAcceptedTooltip = "This option will cause the correlator algorithm " +
			"to <b>not</b> consider any functions or data that have already been " +
			"accepted. Using this option can greatly speed up the processing time " +
			"of the correlator algorithm; however, this options should only be " +
			"used when you trust that your accepted matches are correct.";
		excludeCheckbox.setToolTipText(HTMLUtilities.toWrappedHTML(excludeAcceptedTooltip));

		showAddressSetPanelsCheckbox = new GCheckBox("Limit source and destination address sets");
		String manuallyLimitTooltip = "Selecting this checkbox will trigger additional wizard " +
			" panels allowing you to customize the address sets used " +
			" by the selected algorithm.  When not selected, the entire address space is used.";

		showAddressSetPanelsCheckbox.setToolTipText(
			HTMLUtilities.toWrappedHTML(manuallyLimitTooltip));

		add(excludeCheckbox);
		add(showAddressSetPanelsCheckbox);
		setLayout(new VerticalLayout(20));
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		// none
	}

	@Override
	public void dispose() {
		// nothing to do
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		@SuppressWarnings("unchecked")
		List<VTProgramCorrelatorFactory> list = (List<VTProgramCorrelatorFactory>) state.get(
			VTWizardStateKey.PROGRAM_CORRELATOR_FACTORY_LIST);

		Boolean value = (Boolean) state.get(VTWizardStateKey.EXCLUDE_ACCEPTED_MATCHES);
		if (value != null) {
			excludeCheckbox.setSelected(value.booleanValue());
		}
		value = (Boolean) state.get(VTWizardStateKey.SHOW_ADDRESS_SET_PANELS);
		if (value != null) {
			showAddressSetPanelsCheckbox.setSelected(value.booleanValue());
		}
		else {
			AddressSetView sourceSelection =
				(AddressSetView) state.get(VTWizardStateKey.SOURCE_SELECTION);
			AddressSetView destinationSelection =
				(AddressSetView) state.get(VTWizardStateKey.DESTINATION_SELECTION);
			boolean somethingSelected = (sourceSelection != null && !sourceSelection.isEmpty()) ||
				(destinationSelection != null && !destinationSelection.isEmpty());
			showAddressSetPanelsCheckbox.setSelected(somethingSelected);
		}

		if (allowRestrictions(list)) {
			excludeCheckbox.setEnabled(true);
		}
		else {
			excludeCheckbox.setSelected(false);
			excludeCheckbox.setEnabled(false);
		}

	}

	private boolean allowRestrictions(List<VTProgramCorrelatorFactory> list) {
		for (VTProgramCorrelatorFactory factory : list) {
			if (factory.getAddressRestrictionPreference() != VTProgramCorrelatorAddressRestrictionPreference.RESTRICTION_NOT_ALLOWED) {
				return true;
			}
		}
		return false;
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
		state.put(VTWizardStateKey.EXCLUDE_ACCEPTED_MATCHES, excludeCheckbox.isSelected());
		state.put(VTWizardStateKey.SHOW_ADDRESS_SET_PANELS,
			showAddressSetPanelsCheckbox.isSelected());
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", "Address_Set_Panel");
	}

	@Override
	public String getTitle() {
		return "Address Set Options";
	}

	@Override
	public void initialize() {
		// nothing to do
	}

	@Override
	public boolean isValidInformation() {
		return true;
	}

}
