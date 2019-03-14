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
import ghidra.feature.vt.gui.task.TagMarkupItemTask;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;

abstract class SetMarkupItemConsideredAction extends DockingAction {

	final VTController controller;

	SetMarkupItemConsideredAction(VTController controller, String actionName) {
		super(actionName, VTPlugin.OWNER);
		this.controller = controller;
	}

	abstract VTMarkupItemConsideredStatus getTagType();

	@Override
	public void actionPerformed(ActionContext context) {
		VTSession session = controller.getSession();
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		TagMarkupItemTask task = new TagMarkupItemTask(session, markupItems, getTagType());
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

		VTMarkupItemStatus thisActionsStatus = getTagType().getMarkupItemStatus();

		for (VTMarkupItem markupItem : markupItems) {
			VTMarkupItemStatus status = markupItem.getStatus();
			if (!markupItem.canApply() || status.equals(thisActionsStatus)) {
				return false;
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
