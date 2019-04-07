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
package ghidra.feature.vt.gui.provider.matchtable;

import java.util.*;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.AbstractVTMatchTableModel;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class VTMatchTableModel extends AbstractVTMatchTableModel {

	private static final String TITLE = "VTMatch Table Model";

	public VTMatchTableModel(VTController controller) {
		super(TITLE, controller);
	}

	@Override
	protected TableColumnDescriptor<VTMatch> createTableColumnDescriptor() {
		TableColumnDescriptor<VTMatch> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new TagTableColumn());
		descriptor.addVisibleColumn(new SessionNumberTableColumn());
		descriptor.addVisibleColumn(new StatusTableColumn(), 1, true);
		descriptor.addHiddenColumn(new AppliedMarkupStatusTableColumn());
		descriptor.addVisibleColumn(new MatchTypeTableColumn());
		descriptor.addVisibleColumn(new ScoreTableColumn());
		descriptor.addVisibleColumn(new ConfidenceScoreTableColumn());
		descriptor.addVisibleColumn(new ImpliedMatchCountColumn());
		descriptor.addVisibleColumn(new RelatedMatchCountColumn());
		descriptor.addVisibleColumn(new MultipleSourceLabelsTableColumn());
		descriptor.addVisibleColumn(new SourceNamespaceTableColumn());
		descriptor.addVisibleColumn(new SourceLabelTableColumn());
		descriptor.addHiddenColumn(new SourceLabelSourceTypeTableColumn());
		descriptor.addVisibleColumn(new SourceAddressTableColumn(), 2, true);
		descriptor.addVisibleColumn(new MultipleDestinationLabelsTableColumn());
		descriptor.addVisibleColumn(new DestinationNamespaceTableColumn());
		descriptor.addVisibleColumn(new DestinationLabelTableColumn());
		descriptor.addHiddenColumn(new DestinationLabelSourceTypeTableColumn());
		descriptor.addVisibleColumn(new DestinationAddressTableColumn());
		descriptor.addVisibleColumn(new SourceLengthTableColumn());
		descriptor.addVisibleColumn(new DestinationLengthTableColumn());
		descriptor.addHiddenColumn(new LengthDeltaTableColumn());
		descriptor.addVisibleColumn(new AlgorithmTableColumn());

		return descriptor;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		int tagColumnIndex = getColumnIndex(TagTableColumn.class);
		if (columnIndex == tagColumnIndex) {
			return true;
		}
		return super.isCellEditable(rowIndex, columnIndex);
	}

	@Override
	public Address getAddress(int row) {
		VTMatch match = getRowObject(row);
		VTAssociation association = match.getAssociation();
		return association.getSourceAddress();
	}

	@Override
	protected void doLoad(Accumulator<VTMatch> accumulator, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(getMatchCount());

		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			monitor.checkCanceled();
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				accumulator.add(match);
			}
		}
	}

	private int getMatchCount() {
		int count = 0;
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			count += matchSet.getMatchCount();
		}
		return count;
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

		int sourceColumnAddressIndex = getColumnIndex(SourceAddressTableColumn.class);
		if (sourceColumnAddressIndex == columnIndex) {
			return new SourceAddressComparator();
		}

		int markupStatusColumnIndex = getColumnIndex(AppliedMarkupStatusBatteryTableColumn.class);
		if (markupStatusColumnIndex == columnIndex) {
			return markupStatusColumnComparator;
		}

		markupStatusColumnIndex = getColumnIndex(AppliedMarkupStatusTableColumn.class);
		if (markupStatusColumnIndex == columnIndex) {
			return markupStatusColumnComparator;
		}

		return super.createSortComparator(columnIndex);
	}
}
