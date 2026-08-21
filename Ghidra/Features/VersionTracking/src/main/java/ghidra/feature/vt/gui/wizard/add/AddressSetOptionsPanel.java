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

import static ghidra.feature.vt.api.main.VTProgramCorrelatorAddressRestrictionPreference.*;

import java.util.List;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel for choosing the address set to used for performing new correlations when adding to
 * a version tracking session. Used by the {@link AddressSetOptionsStep}.
 */
public class AddressSetOptionsPanel extends JPanel {

	private JCheckBox excludeCheckbox;
	private JCheckBox limitAddressSetsCheckbox;

	public AddressSetOptionsPanel() { //
		setBorder(BorderFactory.createEmptyBorder(40, 40, 0, 0));

		excludeCheckbox = new GCheckBox("Exclude accepted matches", false);
		String excludeAcceptedTooltip = "This option will cause the correlator algorithm " +
			"to <b>not</b> consider any functions or data that have already been " +
			"accepted. Using this option can greatly speed up the processing time " +
			"of the correlator algorithm; however, this options should only be " +
			"used when you trust that your accepted matches are correct.";
		excludeCheckbox.setToolTipText(HTMLUtilities.toWrappedHTML(excludeAcceptedTooltip));

		limitAddressSetsCheckbox = new GCheckBox("Limit source and destination address sets");
		String manuallyLimitTooltip = "Selecting this checkbox will trigger additional wizard " +
			" panels allowing you to customize the address sets used " +
			" by the selected algorithm.  When not selected, the entire address space is used.";

		limitAddressSetsCheckbox.setToolTipText(
			HTMLUtilities.toWrappedHTML(manuallyLimitTooltip));

		add(excludeCheckbox);
		add(limitAddressSetsCheckbox);
		setLayout(new VerticalLayout(20));
	}

	public void initialize(AddToSessionData data) {

		excludeCheckbox.setSelected(data.shouldExcludeAcceptedMatches());
		limitAddressSetsCheckbox.setSelected(data.shouldLimitAddressSets());

		if (allowRestrictions(data.getCorrelators())) {
			excludeCheckbox.setEnabled(true);
		}
		else {
			excludeCheckbox.setSelected(false);
			excludeCheckbox.setEnabled(false);
		}
	}

	private boolean allowRestrictions(List<VTProgramCorrelatorFactory> list) {
		for (VTProgramCorrelatorFactory factory : list) {
			if (factory.getAddressRestrictionPreference() != RESTRICTION_NOT_ALLOWED) {
				return true;
			}
		}
		return false;
	}

	void updateChoices(AddToSessionData data) {
		data.setShouldExcludeAcceptedMatches(excludeCheckbox.isSelected());
		data.setShouldLimitAddressSets(limitAddressSetsCheckbox.isSelected());
	}

}
