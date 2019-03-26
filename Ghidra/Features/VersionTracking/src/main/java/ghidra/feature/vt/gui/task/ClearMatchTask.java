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

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.util.AddressCorrelation;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ClearMatchTask extends VtTask {

	private final List<VTMatch> matches;
	protected final VTController controller;

	public ClearMatchTask(VTController controller, List<VTMatch> matches) {
		super("Clear Matches", controller.getSession());
		this.controller = controller;
		this.matches = matches;

		VTSession session = controller.getSession();

		if (!(session instanceof VTSessionDB)) {
			throw new IllegalArgumentException(
				"Unexpected condition - VTSession is not a DB object!");
		}

	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		clearMatches(monitor);
		return true;
	}

	private void clearMatches(TaskMonitor monitor)
			throws CancelledException, VersionTrackingApplyException {
		monitor.setMessage("Clearing matches");
		monitor.initialize(matches.size());
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTAssociation association = match.getAssociation();
			VTAssociationStatus status = association.getStatus();
			if (status == VTAssociationStatus.BLOCKED || status == VTAssociationStatus.AVAILABLE) {
				continue;
			}
			removeAppliedMarkup(match, monitor);
			clearMatch(match);
			monitor.incrementProgress(1);
		}

		monitor.setProgress(matches.size());
	}

	private void removeAppliedMarkup(VTMatch match, TaskMonitor monitor)
			throws CancelledException, VersionTrackingApplyException {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);

		AddressCorrelation correlation = getCorrelation(matchInfo);
		if (correlation == null) {
			// match is no longer valid, either the data or function has been removed from either
			// the source or destination
			return;
		}
		for (VTMarkupItem item : markupItems) {
			monitor.checkCanceled();
			maybeUnapply(item);
			maybeClearStatus(item);
			maybeResetDestinationAddressToDefault(item, correlation, monitor);
		}
	}

	private AddressCorrelation getCorrelation(MatchInfo matchInfo) {
		VTAssociationType type = matchInfo.getMatch().getAssociation().getType();
		if (type == VTAssociationType.FUNCTION) {
			Function source = matchInfo.getSourceFunction();
			Function destination = matchInfo.getDestinationFunction();
			if (source == null || destination == null) {
				return null;
			}
			return controller.getCorrelator(source, destination);
		}
		else if (type == VTAssociationType.DATA) {
			Data source = matchInfo.getSourceData();
			Data destination = matchInfo.getDestinationData();
			if (source == null || destination == null) {
				return null;
			}
			return controller.getCorrelator(source, destination);
		}
		return null;
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

	private void maybeResetDestinationAddressToDefault(VTMarkupItem markupItem,
			AddressCorrelation correlation, TaskMonitor monitor) throws CancelledException {
		if (correlation == null) {
			return;
		}

		Address destinationAddress = null;
		AddressRange range =
			correlation.getCorrelatedDestinationRange(markupItem.getSourceAddress(), monitor);
		if (range != null) {
			destinationAddress = range.getMinAddress();
		}
		markupItem.setDefaultDestinationAddress(destinationAddress, correlation.getName());
	}

	private void clearMatch(VTMatch match) {
		VTAssociation association = match.getAssociation();
		try {
			association.clearStatus();
		}
		catch (VTAssociationStatusException e) {
			throw new AssertException("Should not have been given an association to clear " +
				"when it is not already accepted or rejected - current status: " +
				association.getStatus());
		}
	}
}
