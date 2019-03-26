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

import javax.swing.*;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

/**
 * A renderer for the {@link VTMatch} to show an icon for its applied status
 */
public class MatchMarkupStatusRenderer extends AbstractGhidraColumnRenderer<VTMatch> {

	private static ImageIcon DISABLED_ICON =
		ResourceManager.getDisabledIcon(ResourceManager.loadImage("images/ledgreen.png"), 50);
	private static final ImageIcon APPLIED_BASE_ICON =
		ResourceManager.loadImage("images/ledgreen.png", 8, 8);
	private static final ImageIcon REJECTED_BASE_ICON =
		ResourceManager.loadImage("images/ledpurple.png", 8, 8);
	private static final ImageIcon NOT_APPLIED_BASE_ICON =
		ResourceManager.loadImage("images/ledorange.png", 8, 8);
	private static final ImageIcon IGNORED_BASE_ICON =
		ResourceManager.loadImage("images/ledblue.png", 8, 8);
	private static final ImageIcon ERROR_BASE_ICON =
		ResourceManager.loadImage("images/ledred.png", 8, 8);

	private static Icon NOT_APPLIED_ICON = new TranslateIcon(NOT_APPLIED_BASE_ICON, 0, 4);
	private static Icon APPLIED_ICON = new TranslateIcon(APPLIED_BASE_ICON, 9, 4);
	private static Icon REJECTED_ICON = new TranslateIcon(REJECTED_BASE_ICON, 18, 4);
	private static Icon IGNORED_ICON = new TranslateIcon(IGNORED_BASE_ICON, 27, 4);
	private static Icon ERROR_ICON = new TranslateIcon(ERROR_BASE_ICON, 36, 4);

	private static Icon DISABLED_NOT_APPLIED_ICON = new TranslateIcon(DISABLED_ICON, 0, 4);
	private static Icon DISABLED_APPLIED_ICON = new TranslateIcon(DISABLED_ICON, 9, 4);
	private static Icon DISABLED_REJECTED_ICON = new TranslateIcon(DISABLED_ICON, 18, 4);
	private static Icon DISABLED_IGNORED_ICON = new TranslateIcon(DISABLED_ICON, 27, 4);
	private static Icon DISABLED_ERROR_ICON = new TranslateIcon(DISABLED_ICON, 36, 4);

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
		if (!isSelected) {
			// gray out our background if we are locked-out
			renderer.setBackground(MatchTableRenderer.getBackgroundColor(association, table,
				renderer.getBackground()));
		}

		VTAssociationMarkupStatus markupStatus = association.getMarkupStatus();
		MultiIcon icon = new MultiIcon(new EmptyIcon(36, 16));
		icon.addIcon(
			markupStatus.hasUnexaminedMarkup() ? NOT_APPLIED_ICON : DISABLED_NOT_APPLIED_ICON);
		icon.addIcon(markupStatus.hasAppliedMarkup() ? APPLIED_ICON : DISABLED_APPLIED_ICON);
		icon.addIcon(markupStatus.hasRejectedMarkup() ? REJECTED_ICON : DISABLED_REJECTED_ICON);
		icon.addIcon(
			markupStatus.hasDontKnowMarkup() || markupStatus.hasDontCareMarkup() ? IGNORED_ICON
					: DISABLED_IGNORED_ICON);
		icon.addIcon(markupStatus.hasErrors() ? ERROR_ICON : DISABLED_ERROR_ICON);
		setIcon(icon);
		setToolTipText(getDescription(markupStatus));
		return this;
	}

	private String getDescription(VTAssociationMarkupStatus status) {
		StringBuffer buf = new StringBuffer("<html>");

		if (!status.isInitialized()) {
			buf.append("Match has not been accepted; unknown markup status");
			return buf.toString();
		}

		ImageIcon icon = DISABLED_ICON;
		String message = "Has one or more \"Unexamined\" markup items";
		String fontColor = "gray";
		if (status.hasUnexaminedMarkup()) {
			icon = NOT_APPLIED_BASE_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(icon.getDescription()).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = DISABLED_ICON;
		message = "Has one or more \"Applied\" markup items";
		fontColor = "gray";
		if (status.hasAppliedMarkup()) {
			icon = APPLIED_BASE_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(icon.getDescription()).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = DISABLED_ICON;
		message = "Has one or more \"Rejected\" markup items to apply";
		fontColor = "gray";
		if (status.hasRejectedMarkup()) {
			icon = REJECTED_BASE_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(icon.getDescription()).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = DISABLED_ICON;
		message = "Has one or more \"Ignored (Don't Know or Don't Care)\" markup items";
		fontColor = "gray";
		if (status.hasDontCareMarkup() || status.hasDontKnowMarkup()) {
			icon = IGNORED_BASE_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(icon.getDescription()).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = DISABLED_ICON;
		message = "Has one or more \"Error\" markup items";
		fontColor = "gray";
		if (status.hasErrors()) {
			icon = ERROR_BASE_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(icon.getDescription()).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		return buf.toString();
	}

	@Override
	public String getFilterString(VTMatch t, Settings settings) {

		VTAssociation association = t.getAssociation();
		VTAssociationMarkupStatus markupStatus = association.getMarkupStatus();
		String htmlDescription = getDescription(markupStatus);
		String raw = HTMLUtilities.fromHTML(htmlDescription);
		return raw;
	}
}
