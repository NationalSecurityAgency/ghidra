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
package ghidra.feature.vt.gui.provider.matchtable;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JCheckBox;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.filters.CheckBoxBasedAncillaryFilter;
import ghidra.feature.vt.gui.filters.CheckBoxInfo;

public class MatchTypeFilter extends CheckBoxBasedAncillaryFilter<VTMatch> {

	public MatchTypeFilter() {
		super("Match Type");
	}

	@Override
	protected void createCheckBoxInfos() {
		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				fireStatusChanged(getFilterStatus());
			}
		};

		VTAssociationType[] values = VTAssociationType.values();
		for (VTAssociationType status : values) {
			GCheckBox checkBox = new GCheckBox(status.toString(), true);
			checkBox.addItemListener(listener);
			CheckBoxInfo<VTMatch> info = new AssociationTypeCheckBoxInfo(checkBox, status);
			checkBoxInfos.add(info);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class AssociationTypeCheckBoxInfo extends CheckBoxInfo<VTMatch> {

		private VTAssociationType associationType;

		public AssociationTypeCheckBoxInfo(JCheckBox checkBox, VTAssociationType associationType) {
			super(checkBox);
			this.associationType = associationType;
		}

		@Override
		public boolean matchesStatus(VTMatch match) {
			if (!isSelected()) {
				return false;
			}
			return match.getAssociation().getType().equals(associationType);
		}
	}
}
