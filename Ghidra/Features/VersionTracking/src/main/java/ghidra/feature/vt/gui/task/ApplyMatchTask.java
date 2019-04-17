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
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ApplyMatchTask extends VtTask {

	protected final VTController controller;
	private final VTSessionDB sessionDB;
	private final List<VTMatch> matches;
	private final ToolOptions applyOptions;
	private boolean ignoreExcludedItem;
	private boolean ignoreIncompleteItem;

	public ApplyMatchTask(VTController controller, List<VTMatch> matches) {
		super("Apply Matches", controller.getSession());
		this.controller = controller;
		this.applyOptions = controller.getOptions();
		this.matches = matches;

		if (!(session instanceof VTSessionDB)) {
			throw new IllegalArgumentException(
				"Unexpected condition - VTSession is not a DB object!  Found: " + session);
		}

		this.sessionDB = (VTSessionDB) session;

		ignoreExcludedItem = applyOptions.getBoolean(VTOptionDefines.IGNORE_EXCLUDED_MARKUP_ITEMS,
			VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS);

		ignoreIncompleteItem =
			applyOptions.getBoolean(VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS,
				VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS);

	}

	@Override
	protected boolean shouldSuspendSessionEvents() {
		return matches.size() > 20;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		Program destinationProgram = sessionDB.getDestinationProgram();
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(destinationProgram);

		return manager.scheduleWorker(new AnalysisWorker() {
			@Override
			public String getWorkerName() {
				return getTaskTitle();
			}

			@Override
			public boolean analysisWorkerCallback(Program program, Object workerContext,
					TaskMonitor taskMonitor) throws CancelledException {
				// apply matches without triggering auto-analysis on changes made
				applyMatches(taskMonitor);
				return true;
			}
		}, null, false, monitor);

	}

	private void applyMatches(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Processing matches");
		monitor.initialize(matches.size());
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTAssociation association = match.getAssociation();
			VTAssociationStatus status = association.getStatus();
			if (!status.canApply()) {
				continue;
			}

			acceptMatch(match);

			long progress = monitor.getProgress();
			MatchInfo matchInfo = controller.getMatchInfo(match);
			Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
			if (markupItems == null || markupItems.size() == 0) {
				monitor.incrementProgress(1);
				continue;
			}

			monitor.setMessage("Processing matches");
			monitor.setProgress(progress);

			applyMarkupItems(monitor, markupItems);
			monitor.incrementProgress(1);
		}

		monitor.setProgress(matches.size());
	}

	private void acceptMatch(VTMatch match) {
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

		// Markup with no destination address is currently the only incomplete item.
		Address destinationAddress = item.getDestinationAddress();
		if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			if (ignoreIncompleteItem) {
				item.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);
			}
			return;
		}

		VTMarkupType markupType = item.getMarkupType();
		VTMarkupItemApplyActionType applyAction = markupType.getApplyAction(applyOptions);
		if (applyAction == null) {
			// The default action is an excluded, "Do Not Apply", item.
			if (item.canApply()) {
				if (ignoreExcludedItem) {
					item.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);
				}
			}
			return;
		}

		item.apply(applyAction, applyOptions);
	}
}
