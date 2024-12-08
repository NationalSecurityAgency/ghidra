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
package ghidra.features.bsim.gui.search.results;

import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.features.bsim.gui.search.results.apply.AbstractBSimApplyTask;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AbstractProgramLocationTableColumn;
import ghidra.util.task.TaskMonitor;

/**
 * This is the model that backs the table in the {@link BSimApplyResultsDisplayDialog}. It defines
 * four columns for the following:
 * 		function address being changed
 * 		original function name
 * 		new function name
 * 		error/warning information.
 *
 * Also note that this table is address-based and will emit a GoTo service event when a row is double-clicked.
 *
 * @see BSimApplyResultsDisplayDialog
 * @see AbstractBSimApplyTask
 *
 */
public class BSimApplyResultsTableModel extends AddressBasedTableModel<BSimApplyResult> {

	// List of all results to be displayed in the table.
	private List<BSimApplyResult> results;

	// Columns in the table and their positions.
	static final int ADDRESS_INDEX = 0;
	static final int ORIGINAL_NAME_INDEX = 1;
	static final int DESTINATION_NAME_INDEX = 2;
	static final int STATUS_INDEX = 3;

	public BSimApplyResultsTableModel(String title, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor, List<BSimApplyResult> results) {
		super("Rename Results", serviceProvider, program, null);
		this.results = results;
	}

	@Override
	protected TableColumnDescriptor<BSimApplyResult> createTableColumnDescriptor() {
		TableColumnDescriptor<BSimApplyResult> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new StatusColumn());
		descriptor.addVisibleColumn(new AddressColumn());
		descriptor.addVisibleColumn(new OriginalNameColumn());
		descriptor.addVisibleColumn(new DestinationNameColumn());
		descriptor.addVisibleColumn(new MessageColumn());

		return descriptor;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		Address addr = getAddress(row);
		return new ProgramLocation(program, addr);
	}

	@Override
	protected void doLoad(Accumulator<BSimApplyResult> accumulator, TaskMonitor monitor)
			throws CancelledException {

		for (BSimApplyResult result : results) {
			accumulator.add(result);
		}
	}

	/**
	 * Returns the address for the given row.
	 */
	@Override
	public Address getAddress(int row) {
		String addressStr = (String) getValueAt(row, ADDRESS_INDEX);
		return program.getAddressFactory().getAddress(addressStr);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private static class StatusColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimApplyResult, BSimResultStatus> {

		private BSimStatusRenderer statusRenderer = new BSimStatusRenderer();

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public BSimResultStatus getValue(BSimApplyResult rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getStatus();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public GColumnRenderer<BSimResultStatus> getColumnRenderer() {
			return statusRenderer;
		}
	}

	private class AddressColumn
			extends AbstractProgramLocationTableColumn<BSimApplyResult, String> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public String getValue(BSimApplyResult rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			return rowObject.getAddress().toString();
		}

		@Override
		public ProgramLocation getProgramLocation(BSimApplyResult rowObject, Settings settings,
				Program p, ServiceProvider svcProvider) {
			return new ProgramLocation(p, rowObject.getAddress());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	/**
	 * Defines the column in the table for displaying the original function name (the name
	 * to be changed).
	 */
	private class OriginalNameColumn
			extends AbstractDynamicTableColumn<BSimApplyResult, String, Object> {

		@Override
		public String getColumnName() {
			return "Original Name";
		}

		@Override
		public String getValue(BSimApplyResult rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getTargetFunctionName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	/**
	 * Defines the column in the table for displaying the destination function name (the
	 * name to use as the replacement).
	 *
	 */
	private class DestinationNameColumn
			extends AbstractDynamicTableColumn<BSimApplyResult, String, Object> {

		@Override
		public String getColumnName() {
			return "Name From Database";
		}

		@Override
		public String getValue(BSimApplyResult rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getSourceFunctionName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	/**
	 * Defines the column for displaying any status information related to the rename. This
	 * is where error information will be displayed for rename operations that fail.
	 *
	 */
	private class MessageColumn
			extends AbstractDynamicTableColumn<BSimApplyResult, String, Object> {

		@Override
		public String getColumnName() {
			return "Errors/Warnings";
		}

		@Override
		public String getValue(BSimApplyResult rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getMessage();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 900;
		}
	}

}
