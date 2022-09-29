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

import java.awt.Color;
import java.awt.Component;
import java.net.URL;

import javax.swing.*;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.WebColors;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import resources.MultiIcon;
import resources.icons.*;

/**
 * A renderer for the {@link VTMatch} to show an icon for its applied status
 */
public class MatchMarkupStatusRenderer extends AbstractGhidraColumnRenderer<VTMatch> {

	private static final Color FG_TOOLTIP_DEFAULT = new GColor("color.fg.version.tracking.tooltip");
	private static final Color FG_TOOLTIP_UNEXAMINED =
		new GColor("color.bg.version.tracking.match.table.markup.status.tooltip.unexamined");

	private static Icon EMPTY_ICON = new GIcon("icon.empty");
	private static Icon DISABLED_ICOL =
		new GIcon("icon.version.tracking.match.table.markup.status.disabled");
	private static final Icon NOT_APPLIED_ICON =
		new GIcon("icon.version.tracking.match.table.markup.status.not.applied");
	private static final Icon APPLIED_ICON =
		new GIcon("icon.version.tracking.match.table.markup.status.applied");
	private static final Icon REJECTED_ICON =
		new GIcon("icon.version.tracking.match.table.markup.status.rejected");
	private static final Icon IGNORED_ICON =
		new GIcon("icon.version.tracking.match.table.markup.status.ignored");
	private static final Icon ERROR_ICON =
		new GIcon("icon.version.tracking.match.table.markup.status.error");

	private static Icon DISABLED_NOT_APPLIED_ICON = new TranslateIcon(DISABLED_ICOL, 0, 4);
	private static Icon DISABLED_APPLIED_ICON = new TranslateIcon(DISABLED_ICOL, 9, 4);
	private static Icon DISABLED_REJECTED_ICON = new TranslateIcon(DISABLED_ICOL, 18, 4);
	private static Icon DISABLED_IGNORED_ICON = new TranslateIcon(DISABLED_ICOL, 27, 4);
	private static Icon DISABLED_ERROR_ICON = new TranslateIcon(DISABLED_ICOL, 36, 4);

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
		MultiIcon icon = new MultiIcon(new EmptyIcon(45, 16));
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

		Icon icon = EMPTY_ICON;
		String message = "Has one or more \"Unexamined\" markup items";
		Color color = FG_TOOLTIP_DEFAULT;
		if (status.hasUnexaminedMarkup()) {
			icon = NOT_APPLIED_ICON;
			color = FG_TOOLTIP_UNEXAMINED;
		}

		String fontColor = WebColors.toString(color, false);
		buf.append("<img src=\"").append(getIconSource(icon)).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = EMPTY_ICON;

		message = "Has one or more \"Applied\" markup items";
		fontColor = "gray";
		if (status.hasAppliedMarkup()) {
			icon = APPLIED_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(getIconSource(icon)).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = EMPTY_ICON;

		message = "Has one or more \"Rejected\" markup items to apply";
		fontColor = "gray";
		if (status.hasRejectedMarkup()) {
			icon = REJECTED_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(getIconSource(icon)).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = EMPTY_ICON;
		message = "Has one or more \"Ignored (Don't Know or Don't Care)\" markup items";
		fontColor = "gray";
		if (status.hasDontCareMarkup() || status.hasDontKnowMarkup()) {
			icon = IGNORED_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(getIconSource(icon)).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		icon = EMPTY_ICON;
		message = "Has one or more \"Error\" markup items";
		fontColor = "gray";
		if (status.hasErrors()) {
			icon = ERROR_ICON;
			fontColor = "black";
		}
		buf.append("<img src=\"").append(getIconSource(icon)).append("\" />");
		buf.append("<font color=\"").append(fontColor).append("\">");
		buf.append(message).append("</font><br>");

		return buf.toString();
	}

	private String getIconSource(Icon icon) {
		if (icon instanceof GIcon gIcon) {
			URL url = gIcon.getUrl();
			if (url != null) {
				return url.toString();
			}
		}
		else if (icon instanceof UrlImageIcon urlIcon) {
			return urlIcon.getUrl().toString();
		}
		return "";
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
