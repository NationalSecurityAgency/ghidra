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
import java.util.List;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ApplyBlockedMatchTask extends VtTask {

	protected final VTController controller;
	private final ToolOptions applyOptions;
	private final VTMatch match;
	private final List<VTAssociation> conflicts;
	private boolean ignoreExcludedItem;
	private boolean ignoreIncompleteItem;

	public ApplyBlockedMatchTask(VTController controller, VTMatch match,
			List<VTAssociation> conflicts) {
		super("Apply Blocked Match", controller.getSession());
		this.controller = controller;
		this.applyOptions = controller.getOptions();
		this.match = match;
		this.conflicts = conflicts;

		ignoreExcludedItem = applyOptions.getBoolean(VTOptionDefines.IGNORE_EXCLUDED_MARKUP_ITEMS,
			VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS);

		ignoreIncompleteItem =
			applyOptions.getBoolean(VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS,
				VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS);

	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {

		Program destinationProgram = controller.getDestinationProgram();
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(destinationProgram);

		return manager.scheduleWorker(new AnalysisWorker() {
			@Override
			public String getWorkerName() {
				return getTaskTitle();
			}

			@Override
			public boolean analysisWorkerCallback(Program program, Object workerContext,
					TaskMonitor taskMonitor)
					throws CancelledException, VersionTrackingApplyException {
				// clear conflicts and apply blocked match without triggering auto-analysis on changes made
				clearAndApplyMatch(taskMonitor);
				return true;
			}
		}, null, false, monitor);
	}

	private void clearAndApplyMatch(TaskMonitor monitor)
			throws CancelledException, VersionTrackingApplyException {
		monitor.setMessage("Applying a blocked match");
		monitor.initialize(2);
		monitor.checkCanceled();
		VTAssociation association = match.getAssociation();
		VTAssociationStatus status = association.getStatus();
		if (status != VTAssociationStatus.BLOCKED) {
			return;
		}

		monitor.setMessage("Clearing conflicts...");
		clearConflicts(monitor);

		monitor.setMessage("Applying match...");
		acceptMatch();

		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
		if (markupItems == null || markupItems.size() == 0) {
			monitor.setProgress(2);
			return; // No markup items to apply.
		}

		applyMarkupItems(monitor, markupItems);

		monitor.setProgress(2);
	}

	private void clearConflicts(TaskMonitor monitor)
			throws CancelledException, VersionTrackingApplyException {
		for (VTAssociation association : conflicts) {
			monitor.checkCanceled();
			VTAssociationStatus status = association.getStatus();
			if (status != VTAssociationStatus.ACCEPTED) {
				continue;
			}

			Collection<VTMarkupItem> markupItems = association.getMarkupItems(monitor);
			for (VTMarkupItem item : markupItems) {
				monitor.checkCanceled();
				maybeUnapply(item);
				maybeClearStatus(item);
			}
			clearAssociation(association);
			monitor.incrementProgress(1);
		}
	}

	private void maybeUnapply(VTMarkupItem markupItem) throws VersionTrackingApplyException {
		if (markupItem.canUnapply()) {
			markupItem.unapply();
		}
	}

	private void maybeClearStatus(VTMarkupItem markupItem) {
		VTMarkupItemStatus status = markupItem.getStatus();
		if (!status.isDefault() && !status.isUnappliable()) {
			markupItem.setConsidered(VTMarkupItemConsideredStatus.UNCONSIDERED);
		}
	}

	private void clearAssociation(VTAssociation association) {
		try {
			association.clearStatus();
		}
		catch (VTAssociationStatusException e) {
			throw new AssertException("Should not have been given an association to clear " +
				"when it is not already accepted or rejected - current status: " +
				association.getStatus());
		}
	}

	private void acceptMatch() {
		VTAssociation association = match.getAssociation();
		VTAssociationStatus status = association.getStatus();
		if (status == VTAssociationStatus.ACCEPTED) {
			return;
		}

		try {
			association.setAccepted();
		}
		catch (VTAssociationStatusException e) {
			throw new AssertException("Should have been given an association that is not " +
				"blocked - current status: " + association.getStatus());
		}
	}

	private void applyMarkupItems(TaskMonitor monitor, Collection<VTMarkupItem> markupItems)
			throws CancelledException {
		for (VTMarkupItem item : markupItems) {
			monitor.checkCanceled();
			VTMarkupItemStatus status = item.getStatus();
			if (status != VTMarkupItemStatus.UNAPPLIED) {
				// for now we only handle items that have not been applied
				continue;
			}

			try {
				applyMarkupItem(item);
			}
			catch (VersionTrackingApplyException e) {
				reportError(e);
			}
		}
	}

	private void applyMarkupItem(VTMarkupItem item) throws VersionTrackingApplyException {
		if (item.getDestinationAddress() == null) {
			if (ignoreIncompleteItem) {
				item.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);
			}
			return;
		}

		VTMarkupType markupType = item.getMarkupType();
		VTMarkupItemApplyActionType applyAction = markupType.getApplyAction(applyOptions);
		if (applyAction == null) {
			// the default action is not applicable for the given options
			return;
		}

		item.apply(applyAction, applyOptions);

		if (item.canApply()) {
			if (ignoreExcludedItem) {
				item.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);
			}
		}
	}
}
