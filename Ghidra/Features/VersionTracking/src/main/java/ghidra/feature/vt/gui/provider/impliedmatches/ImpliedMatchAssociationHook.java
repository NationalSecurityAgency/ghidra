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
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.util.*;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

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
		if (!autoCreateImpliedMatches) {
			return;
		}

		try {
			TaskMonitor monitor = VTTaskMonitor.getTaskMonitor();
			ImpliedMatchUtils.updateImpliedMatchForAcceptedAssocation(source, destination, session,
				correlator, monitor);
		}
		catch (CancelledException e) {
			Msg.info(this, "User cancelled finding implied matches when accepting an assocation");
		}
	}

	@Override
	public void associationCleared(VTAssociation association) {
		Function source = ImpliedMatchUtils.getSourceFunction(session, association);
		Function destination = ImpliedMatchUtils.getDestinationFunction(session, association);
		if (source == null || destination == null) {
			return;
		}

		if (!autoCreateImpliedMatches) {
			return;
		}

		AddressCorrelatorManager correlator = controller.getCorrelator();
		try {
			TaskMonitor monitor = VTTaskMonitor.getTaskMonitor();
			ImpliedMatchUtils.updateImpliedMatchForClearedAssocation(source, destination, session,
				correlator, monitor);
		}
		catch (CancelledException e) {
			Msg.info(this, "User cancelled finding implied matches when clearing an assocation");
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
