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
package ghidra.feature.vt.gui.util;

import java.awt.Component;

import javax.swing.Icon;
import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.util.table.GhidraTableCellRenderer;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class MatchStatusRenderer extends GhidraTableCellRenderer {

//	private static final Icon DISABLED_APPLIED_ICON =
//		ResourceManager.getDisabledIcon(ResourceManager.loadImage("images/flag.png"));
	private static final Icon ACCEPTED_ICON = ResourceManager.loadImage("images/flag.png");
	private static final Icon REJECTED_ICON = ResourceManager.loadImage("images/dialog-cancel.png");
//	private static final Icon REJECTED_ICON = ResourceManager.loadImage("images/delete.png");
	private static final Icon BLOCKED_ICON = ResourceManager.loadImage("images/kgpg.png");

//	private static final ImageIcon LOCK_ICON =
//		ResourceManager.loadImage("images/lock.png");

	private static final Icon WARN_ICON = new TranslateIcon(
		ResourceManager.loadImage("images/bullet_error.png"), 10, 8);
	private static final Icon FAILURE_ICON = new TranslateIcon(ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/edit-delete.png"), 8, 8), 10, 8);
	private static final Icon FULLY_APPLIED_ICON = new TranslateIcon(ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/checkmark_green.gif"), 8, 8), 10, 8);
	private static final Icon FULLY_CONSIDERED_ICON = new TranslateIcon(
		ResourceManager.getScaledIcon(ResourceManager.loadImage("images/checkmark_yellow.gif"), 8,
			8), 10, 8);

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		// be sure to let our parent perform any initialization needed
		JLabel renderer =
			(JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		renderer.setText("");
		renderer.setHorizontalAlignment(CENTER);

		MungedAssocationAndMarkupItemStatus status = (MungedAssocationAndMarkupItemStatus) value;

		if (status == null) {
			//
			// Hack Alert!  We should never get here, as any row will be backed by a match that 
			//              has a status. I believe this is some sort of timing issue related 
			//              to using a threaded table model.
			//
			return renderer;
		}

		Icon icon = null;
		switch (status) {
			case ACCEPTED_FULLY_APPLIED:
				icon = new MultiIcon(ACCEPTED_ICON, FULLY_APPLIED_ICON);
				break;
			case ACCEPTED_HAS_ERRORS:
				icon = new MultiIcon(ACCEPTED_ICON, FAILURE_ICON);
				break;
			case ACCEPTED_NO_UNEXAMINED:
				icon = new MultiIcon(ACCEPTED_ICON, FULLY_CONSIDERED_ICON);
				break;
			case ACCEPTED_SOME_UNEXAMINED:
				icon = new MultiIcon(ACCEPTED_ICON, WARN_ICON);
				break;
			case AVAILABLE:
				// no icon				
				break;
			case BLOCKED:
				icon = BLOCKED_ICON;
				break;
			case REJECTED:
				icon = REJECTED_ICON;
				break;
		}

		renderer.setIcon(icon);
		renderer.setToolTipText(status.getDescription());

		return renderer;
	}

}
