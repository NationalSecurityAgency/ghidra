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

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;

public abstract class AbstractMarkupItemAction extends DockingAction {

	final VTController controller;

	AbstractMarkupItemAction(VTController controller, String actionName) {
		super(actionName, VTPlugin.OWNER);
		this.controller = controller;
	}

	abstract VTMarkupItemApplyActionType getActionType();

	abstract ToolOptions getApplyOptions();

	@Override
	public void actionPerformed(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		ApplyMarkupItemTask task =
			createApplyTask(controller.getSession(), markupItems, getApplyOptions());
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

	protected ApplyMarkupItemTask createApplyTask(VTSession session,
			List<VTMarkupItem> markupItems, ToolOptions options) {
		return new ApplyMarkupItemTask(session, markupItems, options);
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

			if (!markupItem.supportsApplyAction(getActionType())) {
				return false; // disabled if any of the items do not support our action type
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

			if (!markupItem.supportsApplyAction(getActionType())) {
				return false; // disabled if any of the items do not support our action type
			}
		}
		return true;
	}
}
