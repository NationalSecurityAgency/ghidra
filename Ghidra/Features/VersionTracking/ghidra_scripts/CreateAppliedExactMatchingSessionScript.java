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
// An example of how to create Version Tracking session, run some correlators to find matching
// data and and then save the session.
//@category Examples.Version Tracking

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.api.util.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

import java.util.Collection;
import java.util.List;

public class CreateAppliedExactMatchingSessionScript extends GhidraScript {
	@Override
	public void run() throws Exception {
		DomainFolder folder =
			askProjectFolder("Please choose a folder for the session domain object");
		String name = askString("Please enter a Version Tracking session name", "Session Name");
		Program sourceProgram = askProgram("Please select the source (existing annotated) program");
		Program destinationProgram = askProgram("Please select the destination (new) program");

		VTSession session =
			VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);

		// it seems clunky to have to create this separately, but I'm not sure how else to do it
		folder.createFile(name, session, monitor);

		String description = "CreateAppliedExactMatchingSession";

		int sessionTransaction = session.startTransaction(description);
		try {
			PluginTool serviceProvider = state.getTool();
			VTAssociationManager manager = session.getAssociationManager();

			// should we have convenience methods in VTCorrelator that don't
			// take address sets, thus implying the entire address space should be used?
			AddressSetView sourceAddressSet = sourceProgram.getMemory().getLoadedAndInitializedAddressSet();
			AddressSetView destinationAddressSet =
				destinationProgram.getMemory().getLoadedAndInitializedAddressSet();

			VTProgramCorrelatorFactory factory;

			factory = new ExactDataMatchProgramCorrelatorFactory();
			correlateAndPossiblyApply(sourceProgram, destinationProgram, session, serviceProvider,
				manager, sourceAddressSet, destinationAddressSet, factory);

			factory = new ExactMatchBytesProgramCorrelatorFactory();
			correlateAndPossiblyApply(sourceProgram, destinationProgram, session, serviceProvider,
				manager, sourceAddressSet, destinationAddressSet, factory);

			factory = new ExactMatchInstructionsProgramCorrelatorFactory();
			correlateAndPossiblyApply(sourceProgram, destinationProgram, session, serviceProvider,
				manager, sourceAddressSet, destinationAddressSet, factory);
		}
		finally {
			try {
				session.endTransaction(sessionTransaction, true);
				destinationProgram.save(description, monitor);
				session.save(description, monitor);
			}
			finally {
				session.release(this);
			}
		}
	}

	private void correlateAndPossiblyApply(Program sourceProgram, Program destinationProgram,
			VTSession session, PluginTool serviceProvider, VTAssociationManager manager,
			AddressSetView sourceAddressSet, AddressSetView destinationAddressSet,
			VTProgramCorrelatorFactory factory) throws CancelledException,
			VTAssociationStatusException {

		AddressSetView restrictedSourceAddresses =
			excludeAcceptedMatches(session, sourceAddressSet, true);
		AddressSetView restrictedDestinationAddresses =
			excludeAcceptedMatches(session, destinationAddressSet, false);
		VTOptions options = factory.createDefaultOptions();
		VTProgramCorrelator correlator =
			factory.createCorrelator(serviceProvider, sourceProgram, restrictedSourceAddresses,
				destinationProgram, restrictedDestinationAddresses, options);

		VTMatchSet results = correlator.correlate(session, monitor);
		applyMatches(manager, results.getMatches());
	}

	private void applyMatches(VTAssociationManager manager, Collection<VTMatch> matches)
			throws VTAssociationStatusException, CancelledException {
		for (VTMatch match : matches) {
			VTAssociation association = match.getAssociation();
			association.setAccepted();

			Collection<VTMarkupItem> markupItems = association.getMarkupItems(monitor);
			for (VTMarkupItem vtMarkupItem : markupItems) {
				maybeApplyMarkup(association, vtMarkupItem);
			}
		}
	}

	private void maybeApplyMarkup(VTAssociation association, VTMarkupItem vtMarkupItem) {
		//
		// Note: We use 'null' for options here, which signals to use the default apply
		//       operation.  To configure apply options, see GhidraVersionTrackingScript.
		//
		ToolOptions options = null;

		VTMarkupType markupType = vtMarkupItem.getMarkupType();
		if (markupType == FunctionNameMarkupType.INSTANCE) {
			try {
				vtMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, options);
			}
			catch (VersionTrackingApplyException e) {
				printerr("could not transfer function name " +
					vtMarkupItem.getSourceValue().getDisplayString());
			}
		}
		else if (markupType == LabelMarkupType.INSTANCE &&
			association.getType() == VTAssociationType.DATA) {
			try {
				vtMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, options);
			}
			catch (VersionTrackingApplyException e) {
				printerr("could not transfer data name " +
					vtMarkupItem.getSourceValue().getDisplayString());
			}
		}
	}

	private AddressSet excludeAcceptedMatches(VTSession session, AddressSetView addrSetView,
			boolean source) {

		AddressSet addrSet = new AddressSet(addrSetView);
		if (session == null) {
			return addrSet;
		}

		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				VTAssociationStatus status = match.getAssociation().getStatus();
				if (status == VTAssociationStatus.ACCEPTED) {
					AddressSetView matchAddresses = VTMatchUtil.getMatchAddresses(match, source);
					addrSet.delete(matchAddresses);
				}
			}
		}

		return addrSet;
	}
}
