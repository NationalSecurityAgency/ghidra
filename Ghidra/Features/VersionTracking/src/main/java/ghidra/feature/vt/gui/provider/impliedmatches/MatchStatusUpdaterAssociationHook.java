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
package ghidra.feature.vt.gui.provider.impliedmatches;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTControllerListener;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.Options;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.Collection;
import java.util.List;

public class MatchStatusUpdaterAssociationHook implements AssociationHook, VTControllerListener {

	private VTController controller;
	private VTSession session;

	public MatchStatusUpdaterAssociationHook(VTController controller) {
		this.controller = controller;
		setSession(controller.getSession());
		controller.addListener(this);
	}

	@Override
	public void associationAccepted(VTAssociation association) {
		updateMarkupStatus(association);
	}

	@Override
	public void associationCleared(VTAssociation association) {
		association.setMarkupStatus(new VTAssociationMarkupStatus());
	}

	@Override
	public void markupItemStatusChanged(VTMarkupItem markupItem) {
		controller.markupItemStatusChanged(markupItem);
		updateMarkupStatus(markupItem.getAssociation());
	}

	public void sessionChanged(VTSession newSession) {
		setSession(newSession);
	}

	private void setSession(VTSession session) {
		if (this.session != null) {
			this.session.removeAssociationHook(this);
		}
		this.session = session;
		if (this.session != null) {
			this.session.addAssociationHook(this);
		}
	}

	private void updateMarkupStatus(VTAssociation association) {
		List<VTMatch> matches = association.getSession().getMatches(association);
		if (matches.isEmpty()) {
			return;
		}

		// changed getting markup items from a matchInfo to using the association directly.
		// The matchInfo way sets the destination addresses which is expensive.  Going directly to
		// the association should be quicker. The only thing we care about concerning the markup 
		// items is their status, therefor it doesn't matter that the destination address may not be
		// set, which is required to apply them.

//		MatchInfo matchInfo = controller.getMatchInfo(matches.get(0));
//		Collection<VTMarkupItem> markupItems =
//			matchInfo.getAppliableMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);

		Collection<VTMarkupItem> markupItems;
		try {
			markupItems =
				matches.get(0).getAssociation().getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
			VTAssociationMarkupStatus markupItemsStatus = getAppliedMarkupStatus(markupItems);
			association.setMarkupStatus(markupItemsStatus);
		}
		catch (CancelledException e) {
			// can't happen since we used a Dummy monitor
		}

	}

	private VTAssociationMarkupStatus getAppliedMarkupStatus(Collection<VTMarkupItem> markupItems) {
		int appliedCount = 0;
		int rejectedCount = 0;
		int unappliedCount = 0;
		int dontKnowCount = 0;
		int dontCareCount = 0;
		int errorCount = 0;
		if (markupItems != null) {
			for (VTMarkupItem markupItem : markupItems) {
				VTMarkupItemStatus status = markupItem.getStatus();
				switch (status) {
					case ADDED:
					case REPLACED:
						appliedCount++;
						break;
					case FAILED_APPLY:
						errorCount++;
						break;
					case DONT_KNOW:
						dontKnowCount++;
						break;
					case REJECTED:
						rejectedCount++;
						break;
					case UNAPPLIED:
						unappliedCount++;
						break;
					case DONT_CARE:
						dontCareCount++;
						break;
					case SAME:
						break;
					case CONFLICT:
						break;
				}
			}
		}
		return new VTAssociationMarkupStatus(unappliedCount > 0, appliedCount > 0,
			rejectedCount > 0, dontCareCount > 0, dontKnowCount > 0, errorCount > 0);
	}

	@Override
	public void disposed() {
		// don't care
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		// don't care
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		// don't care
	}

	@Override
	public void optionsChanged(Options options) {
		// don't care
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		// don't care
	}
}
