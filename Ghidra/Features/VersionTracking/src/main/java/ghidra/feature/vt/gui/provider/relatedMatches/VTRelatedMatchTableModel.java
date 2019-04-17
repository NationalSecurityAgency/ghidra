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
package ghidra.feature.vt.gui.provider.relatedMatches;

import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTRelatedMatch;
import ghidra.feature.vt.api.util.VTRelatedMatchUtil;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

import java.util.Collection;

import docking.widgets.table.TableColumnDescriptor;

public class VTRelatedMatchTableModel extends AddressBasedTableModel<VTRelatedMatch> {

	private static final String TITLE = "VTMatchMakupItem Table Model";
	private final VTController controller;

	public VTRelatedMatchTableModel(VTController controller) {
		super(TITLE, controller.getServiceProvider(), controller.getSourceProgram(), null);
		this.controller = controller;
	}

	@Override
	protected TableColumnDescriptor<VTRelatedMatch> createTableColumnDescriptor() {
		TableColumnDescriptor<VTRelatedMatch> descriptor =
			new TableColumnDescriptor<VTRelatedMatch>();

		descriptor.addVisibleColumn(new CorrelationTableColumn());
		descriptor.addVisibleColumn(new SourceAddressTableColumn(), 1, true);
		descriptor.addVisibleColumn(new SourceFunctionTableColumn());
		descriptor.addVisibleColumn(new DestinationAddressTableColumn());
		descriptor.addVisibleColumn(new DestinationFunctionTableColumn());

		return descriptor;
	}

	@Override
	public Address getAddress(int row) {
		VTRelatedMatch markupItem = getRowObject(row);
		return markupItem.getSourceAddress();
	}

	@Override
	protected void doLoad(Accumulator<VTRelatedMatch> accumulator, TaskMonitor monitor)
			throws CancelledException {
		VTSession session = controller.getSession();
		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return;
		}

		Collection<VTRelatedMatch> relatedMatches =
			VTRelatedMatchUtil.getRelatedMatches(monitor, session, matchInfo.getMatch());

		monitor.setMessage("Processing markup items");
		monitor.initialize(relatedMatches.size());

		for (VTRelatedMatch vtRelatedMatch : relatedMatches) {
			monitor.checkCanceled();
			accumulator.add(vtRelatedMatch);
			monitor.incrementProgress(1);
		}
	}

	@Override
	// overridden to force a clear of data before reloading (for painting responsiveness)
	public void reload() {
		clearData();
		super.reload();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================   

	private static class CorrelationTableColumn extends
			AbstractProgramBasedDynamicTableColumn<VTRelatedMatch, VTRelatedMatchType> {

		@Override
		public String getColumnName() {
			return "Correlation";
		}

		@Override
		public VTRelatedMatchType getValue(VTRelatedMatch rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getCorrelation();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	private static class SourceAddressTableColumn extends
			AbstractProgramBasedDynamicTableColumn<VTRelatedMatch, String> {

		@Override
		public String getColumnName() {
			return "Source Address";
		}

		@Override
		public String getValue(VTRelatedMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSourceAddress().toString(false);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	private static class SourceFunctionTableColumn extends
			AbstractProgramBasedDynamicTableColumn<VTRelatedMatch, String> {

		@Override
		public String getColumnName() {
			return "Source Function";
		}

		@Override
		public String getValue(VTRelatedMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSourceFunction().getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	private static class DestinationAddressTableColumn extends
			AbstractProgramBasedDynamicTableColumn<VTRelatedMatch, String> {

		@Override
		public String getColumnName() {
			return "Destination Address";
		}

		@Override
		public String getValue(VTRelatedMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDestinationAddress().toString(false);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	private static class DestinationFunctionTableColumn extends
			AbstractProgramBasedDynamicTableColumn<VTRelatedMatch, String> {

		@Override
		public String getColumnName() {
			return "Destination Function";
		}

		@Override
		public String getValue(VTRelatedMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDestinationFunction().getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}
}
