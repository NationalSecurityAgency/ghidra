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
package ghidra.feature.vt.gui.actions;

import static ghidra.feature.vt.gui.provider.markuptable.MarkupStatusIcons.APPLIED_ICON;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.feature.vt.gui.task.ForceApplyMarkupItemTask;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

import java.util.List;

import docking.ActionContext;
import docking.action.*;

public class ApplyUsingOptionsAndForcingMarkupItemAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP;
	private final VTController controller;

	public ApplyUsingOptionsAndForcingMarkupItemAction(VTController controller, boolean addToToolbar) {
		super("Apply Markup Using Options And Forcing", VTPlugin.OWNER);
		this.controller = controller;

		if (addToToolbar) {
			setToolBarData(new ToolBarData(APPLIED_ICON, VTPlugin.EDIT_MENU_GROUP));
		}
		MenuData menuData =
			new MenuData(new String[] { "Apply (Use Options; Force If Necessary)" }, APPLIED_ICON,
				MENU_GROUP);
		menuData.setMenuSubGroup("0");
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin",
			"Apply_Markup_Item_Using_Options_And_Forcing"));
	}

	protected ApplyMarkupItemTask createApplyTask(VTSession session,
			List<VTMarkupItem> markupItems, ToolOptions options) {
		return new ForceApplyMarkupItemTask(session, markupItems, options);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		ToolOptions options = controller.getOptions();
		ApplyMarkupItemTask task = createApplyTask(controller.getSession(), markupItems, options);
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

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);

		if (markupItems.size() == 0) {
			return false;
		}

		for (VTMarkupItem markupItem : markupItems) {

			if (!markupItem.canApply()) {
				return false;
			}

			Address address = markupItem.getDestinationAddress();
			if (address == null || address == Address.NO_ADDRESS) {
				return false; // disabled if we don't have an address to apply to
			}
		}

		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);

		if (markupItems.size() == 0) {
			return false;
		}

		for (VTMarkupItem markupItem : markupItems) {
			if (!markupItem.canApply()) {
				return false;
			}
		}
		return true;
	}
}
