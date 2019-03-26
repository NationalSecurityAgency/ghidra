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

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import java.util.Collection;
import java.util.List;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionNameMarkupType;
import ghidra.feature.vt.api.markuptype.LabelMarkupType;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.LabelChoices;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AcceptMatchTask extends VtTask {

	protected final VTController controller;
	private final List<VTMatch> matches;
	private boolean doApplyFunctionNames = true;
	private boolean doApplyDataNames = true;

	public AcceptMatchTask(VTController controller, List<VTMatch> matches) {
		super("Accept Matches", controller.getSession());
		this.controller = controller;
		this.matches = matches;

		Options options = controller.getOptions();
		doApplyFunctionNames = options.getBoolean(APPLY_FUNCTION_NAME_ON_ACCEPT, true);
		doApplyDataNames = options.getBoolean(APPLY_DATA_NAME_ON_ACCEPT, true);
	}

	@Override
	protected boolean shouldSuspendSessionEvents() {
		return matches.size() > 20;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) {
		Program destinationProgram = controller.getDestinationProgram();
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(destinationProgram);
		try {
			return manager.scheduleWorker(new AnalysisWorker() {
				@Override
				public String getWorkerName() {
					return getTaskTitle();
				}

				@Override
				public boolean analysisWorkerCallback(Program program, Object workerContext,
						TaskMonitor tm) throws CancelledException {
					// accept matches without triggering auto-analysis on changes made
					acceptMatches(tm);
					return true;
				}
			}, null, false, monitor);
		}
		catch (CancelledException e) {
			// don't care
		}
		catch (Exception e) {
			reportError(e);
		}
		return false;
	}

	private void acceptMatches(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Processing matches");
		monitor.initialize(matches.size());
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTAssociation association = match.getAssociation();
			VTAssociationStatus status = association.getStatus();
			if (status != VTAssociationStatus.AVAILABLE) {
				continue;
			}

			acceptMatch(match);
			if (match.getAssociation().getType() == VTAssociationType.FUNCTION) {
				if (doApplyFunctionNames) {
					applyFunctionNames(match, monitor);
				}
			}
			else if (doApplyDataNames) {
				applyDataNames(match, monitor);
			}

			monitor.incrementProgress(1);
		}

		monitor.setProgress(matches.size());
	}

	private void applyDataNames(VTMatch match, TaskMonitor monitor) throws CancelledException {

		VTAssociation association = match.getAssociation();
		Collection<VTMarkupItem> markupItems = association.getMarkupItems(monitor);
		VTMarkupItem vtMarkupItem =
			getDataLabelMarkupItem(association.getSourceAddress(), markupItems);
		if (vtMarkupItem == null) {
			return;
		}

		// since this markup item is always at the match destination, we can set it simply without
		// using a correlator.
		if (vtMarkupItem.getDestinationAddress() == null) {
			vtMarkupItem.setDestinationAddress(match.getAssociation().getDestinationAddress());
		}
		ToolOptions options = controller.getOptions();
		ToolOptions copyOfOptions = options.copy();
		// Force the label to be applied.
		if (copyOfOptions.getEnum(LABELS, DEFAULT_OPTION_FOR_LABELS) == LabelChoices.EXCLUDE) {
			copyOfOptions.setEnum(LABELS, DEFAULT_OPTION_FOR_LABELS);
		}
		try {
			vtMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, copyOfOptions);
		}
		catch (VersionTrackingApplyException e) {
			reportError(e);
		}

	}

	private void applyFunctionNames(VTMatch match, TaskMonitor monitor) throws CancelledException {
		VTAssociation association = match.getAssociation();
		Collection<VTMarkupItem> markupItems = association.getMarkupItems(monitor);
		VTMarkupItem vtMarkupItem = getFunctionNameMarkupItem(markupItems);
		if (vtMarkupItem == null) {
			return;
		}

		// since this markup item is always at the match destination, we can set it simply without
		// using a correlator.
		if (vtMarkupItem.getDestinationAddress() == null) {
			vtMarkupItem.setDestinationAddress(match.getAssociation().getDestinationAddress());
		}

		ToolOptions options = controller.getOptions();
		ToolOptions copyOfOptions = options.copy();
		// Force the function name to be applied.
		if (copyOfOptions.getEnum(FUNCTION_NAME,
			DEFAULT_OPTION_FOR_FUNCTION_NAME) == FunctionNameChoices.EXCLUDE) {
			copyOfOptions.setEnum(FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		}
		try {
			vtMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, copyOfOptions);
		}
		catch (VersionTrackingApplyException e) {
			reportError(e);
		}

	}

	private VTMarkupItem getFunctionNameMarkupItem(Collection<VTMarkupItem> markupItems) {
		for (VTMarkupItem vtMarkupItem : markupItems) {
			if (vtMarkupItem.getMarkupType() == FunctionNameMarkupType.INSTANCE) {
				return vtMarkupItem;
			}
		}
		return null;
	}

	private VTMarkupItem getDataLabelMarkupItem(Address source,
			Collection<VTMarkupItem> markupItems) {
		for (VTMarkupItem vtMarkupItem : markupItems) {
			if (vtMarkupItem.getMarkupType() == LabelMarkupType.INSTANCE &&
				vtMarkupItem.getSourceAddress().equals(source)) {
				return vtMarkupItem;
			}
		}
		return null;
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

}
