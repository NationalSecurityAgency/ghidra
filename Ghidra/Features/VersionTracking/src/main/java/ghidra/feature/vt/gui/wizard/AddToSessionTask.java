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
package ghidra.feature.vt.gui.wizard;

import java.util.*;

import docking.wizard.WizardState;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTMatchUtil;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.wizard.ChooseAddressSetEditorPanel.AddressSetChoice;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class AddToSessionTask extends Task {
	private final WizardState<VTWizardStateKey> state;
	private final VTController controller;

	public AddToSessionTask(VTController controller, WizardState<VTWizardStateKey> state) {
		super("Merge Version Tracking Session", true, true, true);
		this.controller = controller;
		this.state = state;
	}

	@Override
	public void run(TaskMonitor monitor) {
		VTSession session = null;
		session = controller.getSession();

		Program sourceProgram = session.getSourceProgram();
		Program destinationProgram = session.getDestinationProgram();

		Boolean value = (Boolean) state.get(VTWizardStateKey.EXCLUDE_ACCEPTED_MATCHES);
		boolean excludeAcceptedMatches = (value == null) ? false : value.booleanValue();

		AddressSetChoice sourceAddressSetChoice =
			(AddressSetChoice) state.get(VTWizardStateKey.SOURCE_ADDRESS_SET_CHOICE);
		AddressSetChoice destinationAddressSetChoice =
			(AddressSetChoice) state.get(VTWizardStateKey.DESTINATION_ADDRESS_SET_CHOICE);
		if (sourceAddressSetChoice == null) {
			sourceAddressSetChoice = AddressSetChoice.ENTIRE_PROGRAM;
		}
		if (destinationAddressSetChoice == null) {
			destinationAddressSetChoice = AddressSetChoice.ENTIRE_PROGRAM;
		}

		AddressSetView sourceAddressSet;
		switch (sourceAddressSetChoice) {
			case SELECTION:
				sourceAddressSet = (AddressSetView) state.get(VTWizardStateKey.SOURCE_SELECTION);
				break;
			case MANUALLY_DEFINED:
				sourceAddressSet =
					(AddressSetView) state.get(VTWizardStateKey.SOURCE_ADDRESS_SET_VIEW);
				break;
			case ENTIRE_PROGRAM:
			default:
				sourceAddressSet = sourceProgram.getMemory();
				break;
		}
		AddressSetView destinationAddressSet;
		switch (destinationAddressSetChoice) {
			case SELECTION:
				destinationAddressSet =
					(AddressSetView) state.get(VTWizardStateKey.DESTINATION_SELECTION);
				break;
			case MANUALLY_DEFINED:
				destinationAddressSet =
					(AddressSetView) state.get(VTWizardStateKey.DESTINATION_ADDRESS_SET_VIEW);
				break;
			case ENTIRE_PROGRAM:
			default:
				destinationAddressSet = destinationProgram.getMemory();
				break;
		}

		if (excludeAcceptedMatches) {
			sourceAddressSet = excludeAcceptedMatches(sourceAddressSet, true);
			destinationAddressSet = excludeAcceptedMatches(destinationAddressSet, false);
		}

		ServiceProvider serviceProvider = controller.getTool();

		int transactionID = startTransaction(session);
		boolean completedSucessfully = false;
		try {
			session.setEventsEnabled(false); // prevent table updates while busy
			List<VTProgramCorrelatorFactory> correlatorFactories = getCorrelators(state);
			List<VTOptions> correlatorOptions = getCorrelatorOptions(state);
			List<VTProgramCorrelator> noMatchList = new ArrayList<>();
			for (int i = 0; i < correlatorFactories.size(); i++) {
				VTProgramCorrelatorFactory factory = correlatorFactories.get(i);
				VTProgramCorrelator correlator =
					factory.createCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
						destinationProgram, destinationAddressSet, correlatorOptions.get(i));

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
			if (cause == null)
				Msg.showWarn(this, null, "Add to Session Cancelled",
					"Correlation canceled by user.");
			else
				Msg.showError(this, null, "Add to Session Cancelled - Unexpected Exception",
					"Correlation cancelled due to exception: " + cause.getMessage(), e);
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

	private List<VTOptions> getCorrelatorOptions(WizardState<VTWizardStateKey> stateKey) {
		return CollectionUtils.asList(
			(List<?>) stateKey.get(VTWizardStateKey.PROGRAM_CORRELATOR_OPTIONS_LIST),
			VTOptions.class);
	}

	private List<VTProgramCorrelatorFactory> getCorrelators(
			WizardState<VTWizardStateKey> stateKey) {
		return CollectionUtils.asList(
			(List<?>) stateKey.get(VTWizardStateKey.PROGRAM_CORRELATOR_FACTORY_LIST),
			VTProgramCorrelatorFactory.class);
	}

	private AddressSet excludeAcceptedMatches(AddressSetView addrSetView, boolean source) {
		VTSession session = (VTSession) state.get(VTWizardStateKey.EXISTING_SESSION);
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
