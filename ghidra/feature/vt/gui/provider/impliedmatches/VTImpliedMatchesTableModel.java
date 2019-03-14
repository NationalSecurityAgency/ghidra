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

import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.db.DeletedMatch;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.EmptyVTSession;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel.*;
import ghidra.feature.vt.gui.util.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

import java.util.Set;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;

public class VTImpliedMatchesTableModel extends
		AddressBasedTableModel<ImpliedMatchWrapperRowObject> {
	private static final String TITLE = "Implied Match Table Model";

	protected VTSession session;
	protected final VTController controller;

	public VTImpliedMatchesTableModel(VTController controller) {
		super(TITLE, controller.getServiceProvider(), null, null);
		this.controller = controller;
	}

	void sessionChanged() {
		VTSession newSession = controller.getSession();
		if (newSession == null) {
			newSession = new EmptyVTSession();
		}
		setSession(newSession);
	}

	private void setSession(VTSession session) {
		this.session = session;
		super.setProgram(session.getSourceProgram());
		reload();
	}

	void clear() {
		clearData();
	}

	void matchAdded(VTMatch match) {
		for (ImpliedMatchWrapperRowObject rowObject : getAllData()) {
			if (hasSameAddresses(rowObject, match)) {
				// try to update the match contained by the row object
				rowObject.setMatch(ImpliedMatchUtils.resolveImpliedMatch(rowObject, session));
			}
		}
	}

	private boolean hasSameAddresses(ImpliedMatchWrapperRowObject rowObject, VTMatch match) {
		VTAssociation association = match.getAssociation();
		if (!rowObject.getSourceAddress().equals(association.getSourceAddress())) {
			return false;
		}

		return rowObject.getDestinationAddress().equals(association.getDestinationAddress());
	}

	void matchDeleted(DeletedMatch oldValue) {
		Address deletedSourceAddress = oldValue.getSourceAddress();
		Address deletedDestinationAddress = oldValue.getDestinationAddress();

		for (ImpliedMatchWrapperRowObject rowObject : getAllData()) {
			Address matchSourceAddres = rowObject.getSourceAddress();
			Address matchDestinationAddress = rowObject.getDestinationAddress();

			if (deletedSourceAddress.equals(matchSourceAddres) &&
				deletedDestinationAddress.equals(matchDestinationAddress)) {
				// try to update the match contained by the row object				
				rowObject.setMatch(ImpliedMatchUtils.resolveImpliedMatch(rowObject, session));
			}
		}
	}

	@Override
	public Address getAddress(int row) {
		ImpliedMatchWrapperRowObject rowObject = getRowObject(row);
		return rowObject.getSourceAddress();
	}

	@Override
	protected TableColumnDescriptor<ImpliedMatchWrapperRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<ImpliedMatchWrapperRowObject> descriptor =
			new TableColumnDescriptor<ImpliedMatchWrapperRowObject>();

		descriptor.addVisibleColumn(new SourceReferenceAddressTableColumn());
		descriptor.addVisibleColumn(new DestinationReferenceAddressTableColumn());
		descriptor.addHiddenColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new SessionNumberTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new StatusTableColumn()), 1, true);
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new MatchTypeTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new ScoreTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new ConfidenceScoreTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new ImpliedMatchCountColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new RelatedMatchCountColumn()));
		descriptor.addHiddenColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new MultipleSourceLabelsTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new SourceLabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new SourceAddressTableColumn()), 2,
			true);
		descriptor.addHiddenColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new MultipleDestinationLabelsTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new DestinationLabelTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new DestinationAddressTableColumn()));
		descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this,
			new AlgorithmTableColumn()));

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<ImpliedMatchWrapperRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return; // no match selected
		}

		VTMatch match = matchInfo.getMatch();
		VTAssociation association = match.getAssociation();
		Function sourceFunction = getSourceFunction(association);
		Function destinationFunction = getDestinationFunction(association);

		if (sourceFunction == null || destinationFunction == null) {
			return;
		}

		AddressCorrelatorManager correlator = controller.getCorrelator();
		Set<VTImpliedMatchInfo> matches =
			ImpliedMatchUtils.findImpliedMatches(controller, sourceFunction, destinationFunction,
				session, correlator, monitor);

		monitor.setMessage("Searching for existing matches...");
		monitor.initialize(matches.size());

		for (VTImpliedMatchInfo impliedMatch : matches) {
			monitor.checkCanceled();

			VTMatch existingMatch = ImpliedMatchUtils.resolveImpliedMatch(impliedMatch, session);
			ImpliedMatchWrapperRowObject rowObject =
				new ImpliedMatchWrapperRowObject(impliedMatch, existingMatch);
			accumulator.add(rowObject);

			monitor.incrementProgress(1);
		}
	}

	public Function getSourceFunction(VTAssociation association) {
		Program sourceProgram = session.getSourceProgram();
		Address sourceAddress = association.getSourceAddress();
		FunctionManager functionManager = sourceProgram.getFunctionManager();
		return functionManager.getFunctionAt(sourceAddress);
	}

	public Function getDestinationFunction(VTAssociation association) {
		Program destinationProgram = session.getDestinationProgram();
		Address destinationAddress = association.getDestinationAddress();
		FunctionManager functionManager = destinationProgram.getFunctionManager();
		return functionManager.getFunctionAt(destinationAddress);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	// Source Ref Address
	public static class SourceReferenceAddressTableColumn extends
			AbstractProgramBasedDynamicTableColumn<ImpliedMatchWrapperRowObject, String> {

		@Override
		public String getColumnName() {
			return "Source Reference Address";
		}

		@Override
		public String getValue(ImpliedMatchWrapperRowObject rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSourceReferenceAddress().toString(false);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	// Destination Ref Address
	public static class DestinationReferenceAddressTableColumn extends
			AbstractProgramBasedDynamicTableColumn<ImpliedMatchWrapperRowObject, String> {

		@Override
		public String getColumnName() {
			return "Dest Reference Address";
		}

		@Override
		public String getValue(ImpliedMatchWrapperRowObject rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDestinationReferenceAddress().toString(false);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}
}
