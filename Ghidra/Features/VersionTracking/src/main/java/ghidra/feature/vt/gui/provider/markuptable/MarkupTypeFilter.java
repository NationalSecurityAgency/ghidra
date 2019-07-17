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

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;

import javax.swing.JCheckBox;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.markuptype.VTMarkupTypeFactory;
import ghidra.feature.vt.gui.filters.CheckBoxBasedAncillaryFilter;
import ghidra.feature.vt.gui.filters.CheckBoxInfo;

public class MarkupTypeFilter extends CheckBoxBasedAncillaryFilter<VTMarkupItem> {

	public MarkupTypeFilter() {
		super("Markup Type");
	}

	@Override
	protected void createCheckBoxInfos() {
		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				fireStatusChanged(getFilterStatus());
			}
		};

		List<VTMarkupType> markupTypes = VTMarkupTypeFactory.getMarkupTypes();
		for (VTMarkupType markupType : markupTypes) {
			GCheckBox checkBox = new GCheckBox(markupType.getDisplayName());
			checkBox.setSelected(true);
			checkBox.addItemListener(listener);
			CheckBoxInfo<VTMarkupItem> info = new MarkupTypeCheckBoxInfo(checkBox, markupType);
			checkBoxInfos.add(info);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MarkupTypeCheckBoxInfo extends CheckBoxInfo<VTMarkupItem> {

		private VTMarkupType markupType;

		public MarkupTypeCheckBoxInfo(JCheckBox checkBox, VTMarkupType markupType) {
			super(checkBox);
			this.markupType = markupType;
		}

		@Override
		public boolean matchesStatus(VTMarkupItem adapter) {
			if (!isSelected()) {
				return false;
			}
			return adapter.getMarkupType().equals(markupType);
		}
	}
}
