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
package ghidra.feature.vt.gui.wizard.add;

import java.util.*;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTMatchUtil;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class AddToSessionTask extends Task {
	private final AddToSessionData data;
	private final VTController controller;

	public AddToSessionTask(VTController controller, AddToSessionData data) {
		super("Merge Version Tracking Session", true, true, true);
		this.controller = controller;
		this.data = data;
	}

	@Override
	public void run(TaskMonitor monitor) {
		VTSession session = null;
		session = controller.getSession();

		Program sourceProgram = session.getSourceProgram();
		Program destinationProgram = session.getDestinationProgram();

		boolean excludeAcceptedMatches = data.shouldExcludeAcceptedMatches();

		AddressSetView sourceAddressSet = getSourceAddressSet();
		AddressSetView destinationAddressSet = getDestinationAddressSet();

		if (excludeAcceptedMatches) {
			sourceAddressSet = excludeAcceptedMatches(sourceAddressSet, true);
			destinationAddressSet = excludeAcceptedMatches(destinationAddressSet, false);
		}

		int transactionID = startTransaction(session);
		boolean completedSucessfully = false;
		try {
			session.setEventsEnabled(false); // prevent table updates while busy
			List<VTProgramCorrelatorFactory> correlatorFactories = data.getCorrelators();
			Map<VTProgramCorrelatorFactory, VTOptions> optionsMap = data.getOptions();
			List<VTProgramCorrelator> noMatchList = new ArrayList<>();
			for (VTProgramCorrelatorFactory factory : correlatorFactories) {
				VTOptions options = optionsMap.get(factory);
				VTProgramCorrelator correlator =
					factory.createCorrelator(sourceProgram, sourceAddressSet, destinationProgram,
						destinationAddressSet, options);

				VTMatchSet resultSet = correlator.correlate(session, monitor);
				if (resultSet.getMatchCount() == 0) {
					noMatchList.add(correlator);
				}
			}
			if (!noMatchList.isEmpty()) {
				StringBuffer messageBuffer = new StringBuffer(
					"No matches were found by the following program correlators: ");
				for (VTProgramCorrelator vtProgramCorrelator : noMatchList) {
					messageBuffer.append("\n  " + vtProgramCorrelator.getName());
				}
				Msg.showInfo(this, null, "Version Tracking: Add To Session",
					messageBuffer.toString());
			}
			completedSucessfully = true;
		}
		catch (CancelledException e) {
			Throwable cause = e.getCause();		// CancelledException may hide more serious error
			if (cause == null) {
				Msg.showWarn(this, null, "Add to Session Cancelled",
					"Correlation canceled by user.");
			}
			else {
				Msg.showError(this, null, "Add to Session Cancelled - Unexpected Exception",
					"Correlation cancelled due to exception: " + cause.getMessage(), e);
			}
		}
		catch (Exception e) {
			Msg.showError(this, null, "Add to Session Cancelled - Unexpected Exception",
				"Correlation cancelled due to exception: " + e.getMessage(), e);
		}
		finally {
			session.setEventsEnabled(true);
			endTransaction(session, transactionID, completedSucessfully);
		}
	}

	private AddressSetView getSourceAddressSet() {
		if (!data.shouldLimitAddressSets()) {
			return data.getSourceProgram().getMemory();
		}
		switch (data.getSourceAddressSetChoice()) {
			case MANUALLY_DEFINED:
				return data.getCustomSourceAddressSet();
			case SELECTION:
				return data.getSourceSelection();
			case ENTIRE_PROGRAM:
			default:
				return data.getSourceProgram().getMemory();
		}
	}

	private AddressSetView getDestinationAddressSet() {
		if (!data.shouldLimitAddressSets()) {
			return data.getDestinationProgram().getMemory();
		}
		switch (data.getDestinationAddressSetChoice()) {
			case MANUALLY_DEFINED:
				return data.getCustomDestinationAddressSet();
			case SELECTION:
				return data.getDestinationSelection();
			case ENTIRE_PROGRAM:
			default:
				return data.getDestinationProgram().getMemory();
		}
	}

	private void endTransaction(VTSession session, int transactionID,
			boolean completedSucessfully) {
		if (transactionID == -1) {
			return;
		}
		((DomainObjectAdapterDB) session).endTransaction(transactionID, completedSucessfully);
	}

	private int startTransaction(VTSession session) {
		if (session instanceof DomainObjectAdapterDB) {
			return ((DomainObjectAdapterDB) session).startTransaction("Correlate");
		}
		return -1;
	}

	private AddressSet excludeAcceptedMatches(AddressSetView addrSetView, boolean source) {
		VTSession session = data.getSession();
		AddressSet addrSet = new AddressSet(addrSetView);
		if (session != null) {
			List<VTMatchSet> matchSets = session.getMatchSets();
			for (VTMatchSet vtMatchSet : matchSets) {
				Collection<VTMatch> matches = vtMatchSet.getMatches();
				for (VTMatch vtMatch : matches) {
					VTAssociationStatus status = vtMatch.getAssociation().getStatus();
					if (status == VTAssociationStatus.ACCEPTED) {
						AddressSetView matchAddresses =
							VTMatchUtil.getMatchAddresses(vtMatch, source);
						addrSet.delete(matchAddresses);
					}
				}
			}
		}
		return addrSet;
	}
}
