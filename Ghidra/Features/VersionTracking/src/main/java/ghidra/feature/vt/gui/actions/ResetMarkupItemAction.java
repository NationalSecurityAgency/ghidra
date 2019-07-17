/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.actions;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.task.UnapplyMarkupItemTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.program.util.AddressCorrelation;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

import java.util.List;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class ResetMarkupItemAction extends DockingAction {

	public static final Icon RESET_ICON = ResourceManager.loadImage("images/undo-apply.png");
	private static final String MENU_GROUP = VTPlugin.UNEDIT_MENU_GROUP;

	final VTController controller;

	public ResetMarkupItemAction(VTController controller, boolean addToToolbar) {
		super("Reset Mark-up", VTPlugin.OWNER);
		this.controller = controller;

		if (addToToolbar) {
			setToolBarData(new ToolBarData(RESET_ICON, MENU_GROUP));
		}
		setPopupMenuData(new MenuData(new String[] { "Reset Mark-up" }, RESET_ICON, MENU_GROUP));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Reset_Markup_Item"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTSession session = controller.getSession();
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		AddressCorrelation correlation = getCorrelation();
		UnapplyMarkupItemTask task = new UnapplyMarkupItemTask(session, correlation, markupItems);
		task.addTaskListener(new TaskListener() {
			@Override
			public void taskCompleted(Task t) {
				controller.refresh();
			}

			@Override
			public void taskCancelled(Task t) {
				// don't care; nothing to do
			}
		});
		controller.runVTTask(task);
	}

	private AddressCorrelation getCorrelation() {
		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return null;
		}
		VTAssociationType type = matchInfo.getMatch().getAssociation().getType();
		if (type == VTAssociationType.FUNCTION) {
			return controller.getCorrelator(matchInfo.getSourceFunction(),
				matchInfo.getDestinationFunction());
		}
		else if (type == VTAssociationType.DATA) {
			return controller.getCorrelator(matchInfo.getSourceData(),
				matchInfo.getDestinationData());
		}
		return null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);

		if (markupItems.size() == 0) {
			return false;
		}

		for (VTMarkupItem markupItem : markupItems) {
			if (!canReset(markupItem)) {
				return false;
			}
		}

		return true;
	}

	// Somewhat kludgy method to know when an item will have been put into the database and 
	// that we can undo that
	private boolean canReset(VTMarkupItem markupItem) {
		String addressSource = markupItem.getDestinationAddressSource();
		if (VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE.equals(addressSource)) {
			return true; // we can undo user defined addresses
		}

		VTMarkupItemStatus status = markupItem.getStatus();
		return !status.isDefault(); // this handled applied status and user-defined status
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return isEnabledForContext(context);
	}
}
