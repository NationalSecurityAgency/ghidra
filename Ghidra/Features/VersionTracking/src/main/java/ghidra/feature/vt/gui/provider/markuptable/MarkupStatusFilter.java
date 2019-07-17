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
package ghidra.feature.vt.gui.provider.markuptable;

import java.awt.event.ItemListener;

import javax.swing.JCheckBox;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.feature.vt.gui.filters.CheckBoxBasedAncillaryFilter;
import ghidra.feature.vt.gui.filters.CheckBoxInfo;

public class MarkupStatusFilter extends CheckBoxBasedAncillaryFilter<VTMarkupItem> {

	public MarkupStatusFilter() {
		super("Markup Status");
	}

	@Override
	protected void createCheckBoxInfos() {
		ItemListener listener = e -> fireStatusChanged(getFilterStatus());

		VTMarkupItemStatus[] values = VTMarkupItemStatus.values();
		for (VTMarkupItemStatus status : values) {
			GCheckBox checkBox = new GCheckBox(status.getDescription());
			checkBox.setSelected(true);
			checkBox.addItemListener(listener);
			CheckBoxInfo<VTMarkupItem> info = new MatchStatusCheckBoxInfo(checkBox, status);
			checkBoxInfos.add(info);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MatchStatusCheckBoxInfo extends CheckBoxInfo<VTMarkupItem> {

		private VTMarkupItemStatus status;

		public MatchStatusCheckBoxInfo(JCheckBox checkBox, VTMarkupItemStatus status) {
			super(checkBox);
			this.status = status;
		}

		@Override
		public boolean matchesStatus(VTMarkupItem adapter) {
			if (!isSelected()) {
				return false;
			}
			return adapter.getStatus().equals(status);
		}
	}
}
