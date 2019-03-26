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

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.table.column.AbstractGColumnRenderer;

/**
 * A renderer for {@link VTMatch} that shows an icon for the match's status
 */
public class MatchMarkupStatusBatteryRenderer extends AbstractGColumnRenderer<VTMatch> {

	private VTMarkupStatusIcon markupStatusIcon = new VTMarkupStatusIcon();

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		// be sure to let our parent perform any initialization needed
		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		JTable table = data.getTable();
		boolean isSelected = data.isSelected();

		setText("");
		setHorizontalAlignment(CENTER);
		VTMatch match = (VTMatch) value;
		VTAssociation association = match.getAssociation();
		VTAssociationStatus associationStatus = association.getStatus();

		if (!isSelected) {
			// gray out our background if we are locked-out
			renderer.setBackground(MatchTableRenderer.getBackgroundColor(association, table,
				renderer.getBackground()));
		}
		if (associationStatus == VTAssociationStatus.ACCEPTED) {
			VTAssociationMarkupStatus markupStatus = association.getMarkupStatus();
			markupStatusIcon.setStatus(markupStatus);
			setIcon(markupStatusIcon);
			setToolTipText(HTMLUtilities.toHTML(markupStatus.getDescription()));
		}
		else {
			setIcon(null);
		}
		return this;
	}

	@Override
	public String getFilterString(VTMatch t, Settings settings) {
		VTAssociation association = t.getAssociation();
		VTAssociationStatus associationStatus = association.getStatus();
		if (associationStatus == VTAssociationStatus.ACCEPTED) {
			VTAssociationMarkupStatus markupStatus = association.getMarkupStatus();
			return HTMLUtilities.toHTML(markupStatus.getDescription());
		}

		return "";
	}

}
