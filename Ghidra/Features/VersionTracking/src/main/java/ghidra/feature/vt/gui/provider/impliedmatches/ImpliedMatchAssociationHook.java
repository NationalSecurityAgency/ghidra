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

import java.util.List;
import java.util.Set;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.util.*;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class ImpliedMatchAssociationHook implements AssociationHook, VTControllerListener {
	private VTSession session;
	private final VTController controller;

	private boolean autoCreateImpliedMatches = true;

	public ImpliedMatchAssociationHook(VTController controller) {
		this.controller = controller;
		Options options = controller.getOptions();
		autoCreateImpliedMatches =
			options.getBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, false);
		setSession(controller.getSession());
		controller.addListener(this);
	}

	@Override
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

	@Override
	public void associationAccepted(VTAssociation association) {
		Function source = ImpliedMatchUtils.getSourceFunction(session, association);
		Function destination = ImpliedMatchUtils.getDestinationFunction(session, association);
		if (source == null || destination == null) {
			return;
		}
		AddressCorrelatorManager correlator = controller.getCorrelator();
		if (autoCreateImpliedMatches) {
			try {
				Set<VTImpliedMatchInfo> impliedMatches =
					ImpliedMatchUtils.findImpliedMatches(controller, source, destination, session,
						correlator, TaskMonitorAdapter.DUMMY_MONITOR);
				processAssociationAccepted(impliedMatches);
			}
			catch (Exception e) {
				Msg.error(this, "Error auto-creating implied matches for association: " +
					association);
			}
		}
	}

	/**
	 * When a match is accepted either create associated implied matches or if a match already
	 * exists, increase the vote count
	 * @param impliedMatches The implied matches set to either create or increase vote count 
	 */
	private void processAssociationAccepted(Set<VTImpliedMatchInfo> impliedMatches) {
		for (VTImpliedMatchInfo impliedMatch : impliedMatches) {
			Address sourceAddress = impliedMatch.getSourceAddress();
			Address destinationAddress = impliedMatch.getDestinationAddress();
			VTAssociation existingAssociation =
				session.getAssociationManager().getAssociation(sourceAddress, destinationAddress);

			if (existingAssociation == null) {
				VTMatchSet impliedMatchSet = session.getImpliedMatchSet();
				VTMatch match = impliedMatchSet.addMatch(impliedMatch);
				existingAssociation = match.getAssociation();
			}
			if (existingAssociation != null) {
				existingAssociation.setVoteCount(existingAssociation.getVoteCount() + 1);
			}
		}

	}

	@Override
	public void associationCleared(VTAssociation association) {
		Function source = ImpliedMatchUtils.getSourceFunction(session, association);
		Function destination = ImpliedMatchUtils.getDestinationFunction(session, association);
		if (source == null || destination == null) {
			return;
		}
		AddressCorrelatorManager correlator = controller.getCorrelator();
		try {
			Set<VTImpliedMatchInfo> impliedMatches =
				ImpliedMatchUtils.findImpliedMatches(controller, source, destination, session,
					correlator, TaskMonitorAdapter.DUMMY_MONITOR);
			processAssociationCleared(impliedMatches);
		}
		catch (CancelledException e) {
			// can't happen - using dummy monitor
		}
	}

	private void processAssociationCleared(Set<VTImpliedMatchInfo> impliedMatches) {
		for (VTImpliedMatchInfo impliedMatch : impliedMatches) {
			Address sourceAddress = impliedMatch.getSourceAddress();
			Address destinationAddress = impliedMatch.getDestinationAddress();
			VTAssociation existingAssociation =
				session.getAssociationManager().getAssociation(sourceAddress, destinationAddress);

			if (existingAssociation != null) {
				int newVoteCount = Math.max(0, existingAssociation.getVoteCount() - 1);
				existingAssociation.setVoteCount(newVoteCount);
				if (autoCreateImpliedMatches && newVoteCount == 0) {
					removeImpliedMatch(existingAssociation);
				}
			}
		}

	}

	private void removeImpliedMatch(VTAssociation existingAssociation) {
		List<VTMatch> matches = session.getMatches(existingAssociation);
		VTMatchSet impliedMatchSet = session.getImpliedMatchSet();
		for (VTMatch vtMatch : matches) {
			if (vtMatch.getMatchSet() == impliedMatchSet) {
				impliedMatchSet.removeMatch(vtMatch);
			}
		}

	}

	@Override
	public void optionsChanged(Options options) {
		autoCreateImpliedMatches =
			options.getBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, false);
	}

	@Override
	public void markupItemStatusChanged(VTMarkupItem markupItem) {
		// don't care
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
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		// don't care		
	}

}
