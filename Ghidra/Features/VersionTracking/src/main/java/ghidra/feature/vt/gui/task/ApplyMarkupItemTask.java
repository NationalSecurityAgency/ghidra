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
package ghidra.feature.vt.gui.task;

import java.util.Collection;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.framework.options.ToolOptions;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ApplyMarkupItemTask extends VtTask {

	protected final Collection<VTMarkupItem> markupItems;
	protected final ToolOptions options;

	public ApplyMarkupItemTask(VTSession session, Collection<VTMarkupItem> markupItems,
			ToolOptions options) {
		this("Apply Markup Items", session, markupItems, options);
	}

	ApplyMarkupItemTask(String title, VTSession session, Collection<VTMarkupItem> markupItems,
			ToolOptions options) {
		super(title, session);
		this.markupItems = markupItems;
		this.options = options;
	}
	
	@Override
	protected boolean shouldSuspendSessionEvents() {
		return markupItems.size() > 20;
	}

	/**
	 * Template Method pattern to allow subclasses to plug-in to this task.
	 * @param markupItem the markup
	 * @param markupItemOptions
	 * @return
	 */
	protected VTMarkupItemApplyActionType getApplyActionType(VTMarkupItem markupItem,
			ToolOptions markupItemOptions) {
		VTMarkupType markupType = markupItem.getMarkupType();
		VTMarkupItemApplyActionType applyActionType = markupType.getApplyAction(markupItemOptions);
		return applyActionType;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws CancelledException {
		monitor.initialize(markupItems.size());

		for (VTMarkupItem markupItem : markupItems) {
			monitor.checkCanceled();
			try {
				markupItem.getAssociation().setAccepted();
				VTMarkupItemApplyActionType actionType = getApplyActionType(markupItem, options);
				if (actionType == null) {
					continue; // the markup item, based on the options, does not want to apply
				}
				markupItem.apply(actionType, options);
				monitor.incrementProgress(1);
			}
			catch (VersionTrackingApplyException | VTAssociationStatusException e) {
				reportError(e);
			}
		}
		return true;
	}
}
