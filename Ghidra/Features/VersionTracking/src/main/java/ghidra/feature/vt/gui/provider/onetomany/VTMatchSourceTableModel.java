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
package ghidra.feature.vt.gui.provider.onetomany;

import java.util.*;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class VTMatchSourceTableModel extends VTMatchOneToManyTableModel {

	private static final String TITLE = "VTMatch Source Table Model";

	public VTMatchSourceTableModel(ServiceProvider serviceProvider, VTController vtController) {
		super(TITLE, vtController);
	}

	@Override
	protected TableColumnDescriptor<VTMatch> createTableColumnDescriptor() {
		TableColumnDescriptor<VTMatch> descriptor = new TableColumnDescriptor<>();

		descriptor.addHiddenColumn(new SessionNumberTableColumn());
		descriptor.addVisibleColumn(new StatusTableColumn(), 1, true);
		descriptor.addHiddenColumn(new MatchTypeTableColumn());
		descriptor.addVisibleColumn(new ScoreTableColumn());
		descriptor.addVisibleColumn(new ConfidenceScoreTableColumn());
		descriptor.addVisibleColumn(new ImpliedMatchCountColumn());
		descriptor.addVisibleColumn(new RelatedMatchCountColumn());
		descriptor.addHiddenColumn(new MultipleDestinationLabelsTableColumn());
		descriptor.addVisibleColumn(new DestinationNamespaceTableColumn());
		descriptor.addVisibleColumn(new DestinationLabelTableColumn());
		descriptor.addHiddenColumn(new DestinationLabelSourceTypeTableColumn());
		descriptor.addVisibleColumn(new DestinationAddressTableColumn(), 2, true);
		descriptor.addVisibleColumn(new SourceLengthTableColumn());
		descriptor.addVisibleColumn(new DestinationLengthTableColumn());
		descriptor.addHiddenColumn(new LengthDeltaTableColumn());
		descriptor.addVisibleColumn(new AlgorithmTableColumn());

		descriptor.addHiddenColumn(new TagTableColumn());
		descriptor.addHiddenColumn(new AppliedMarkupStatusBatteryTableColumn());
		descriptor.addHiddenColumn(new AppliedMarkupStatusTableColumn());

		return descriptor;
	}

	@Override
	public Address getAddress(int row) {
		VTMatch match = getRowObject(row);
		VTAssociation association = match.getAssociation();
		return association.getDestinationAddress();
	}

	@Override
	protected void doLoad(Accumulator<VTMatch> accumulator, TaskMonitor monitor)
			throws CancelledException {
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTAssociationManager associationManager = session.getAssociationManager();
		if (address != null && associationManager != null) {
			Collection<VTAssociation> associations =
				associationManager.getRelatedAssociationsBySourceAddress(address);
			monitor.initialize(associations.size());
			for (VTAssociation vtAssociation : associations) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				for (VTMatchSet matchSet : matchSets) {
					monitor.checkCanceled();
					Collection<VTMatch> matches = matchSet.getMatches(vtAssociation);
					for (VTMatch match : matches) {
						monitor.checkCanceled();
						accumulator.add(match);
					}
				}
			}
		}
	}

	@Override
	protected Comparator<VTMatch> createSortComparator(int columnIndex) {

		// 
		// Unusual Code Alert!: since we define some of our columns for this table model as 
		//                      off/hidden by default, we cannot rely on the ordinal of the 
		//                      ColumnDescriptor to match the 'columnIndex' parameter.  Instead, 
		//                      we have to lookup the model's index for the given ColumnDescriptor
		//                      and test that value against the index parameter (which is the 
		//                      value used by the column model.
		// 

		int destinationAddressColumnIndex = getColumnIndex(DestinationAddressTableColumn.class);
		if (destinationAddressColumnIndex == columnIndex) {
			return new DestinationAddressComparator();
		}

//		int sourceColumnAddressIndex =
//			getColumnIndex(ColumnDescriptor.SOURCE_ADDRESS.getColumnClass());
//		if (sourceColumnAddressIndex == columnIndex) {
//			return new SourceAddressComparator();
//		}

		return super.createSortComparator(columnIndex);
	}
}
