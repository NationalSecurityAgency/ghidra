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
package ghidra.features.bsim.gui.search.results;

import java.awt.Component;

import javax.swing.Icon;
import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GIcon;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;
import resources.Icons;

/**
 * Renderer for display BSim apply results from attempting to apply function names and signatures
 * from BSim Search results.
 */
public class BSimStatusRenderer extends AbstractGColumnRenderer<BSimResultStatus> {
	private static final Icon NOT_APPLIED_ICON = null;
	private static final Icon NAME_APPLIED_ICON =
		new GIcon("icon.bsim.results.status.name.applied");
	private static final Icon SIGNATURE_APPLIED_ICON =
		new GIcon("icon.bsim.results.status.signature.applied");
	private static final Icon ERROR_ICON = Icons.ERROR_ICON;
	private static final Icon MATCHES_ICON = new GIcon("icon.bsim.results.status.matches");
	private static final Icon APPLIED_NO_LONGER_MATCHES_ICON = Icons.WARNING_ICON;
	private static final Icon NO_FUNCTION_ICON = Icons.STRONG_WARNING_ICON;
	private static final Icon IGNORED_ICON = new GIcon("icon.bsim.results.status.ignored");

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel label = (JLabel) super.getTableCellRendererComponent(data);
		BSimResultStatus status = (BSimResultStatus) data.getValue();
		label.setText("");
		label.setIcon(getIcon(status));
		label.setToolTipText(status.getDescription());
		return label;
	}

	private Icon getIcon(BSimResultStatus status) {
		switch (status) {
			case NAME_APPLIED:
				return NAME_APPLIED_ICON;
			case SIGNATURE_APPLIED:
				return SIGNATURE_APPLIED_ICON;
			case ERROR:
				return ERROR_ICON;
			case MATCHES:
				return MATCHES_ICON;
			case NOT_APPLIED:
				return NOT_APPLIED_ICON;
			case APPLIED_NO_LONGER_MATCHES:
				return APPLIED_NO_LONGER_MATCHES_ICON;
			case NO_FUNCTION:
				return NO_FUNCTION_ICON;
			case IGNORED:
				return IGNORED_ICON;
			default:
				return ERROR_ICON;
		}
	}

	@Override
	public String getFilterString(BSimResultStatus t, Settings settings) {
		return t.toString();
	}

}
