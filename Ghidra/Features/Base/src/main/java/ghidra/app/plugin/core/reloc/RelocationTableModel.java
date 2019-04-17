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
package ghidra.app.plugin.core.reloc;

import java.util.Iterator;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.NumericUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

class RelocationTableModel extends AddressBasedTableModel<Relocation> {

	final static String RELOCATION_ADDRESS = "Address";
	final static String RELOCATION_TYPE = "Type";
	final static String RELOCATION_VALUE = "Values";
	final static String RELOCATION_BYTES = "Original Bytes";
	static final String RELOCATION_NAME = "Name";

	public RelocationTableModel(ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		super("Relocation Table Model", serviceProvider, program, monitor);
	}

	@Override
	protected TableColumnDescriptor<Relocation> createTableColumnDescriptor() {
		TableColumnDescriptor<Relocation> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new RelocationTypeColumn());
		descriptor.addVisibleColumn(new RelocationValueColumn());
		descriptor.addVisibleColumn(new RelocationBytesColumn());
		descriptor.addVisibleColumn(new RelocationNameColumn());

		return descriptor;
	}

	@Override
	public void setProgram(Program p) {
		super.setProgram(p);
		reload();
		fireTableDataChanged();
	}

	@Override
	protected void doLoad(Accumulator<Relocation> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (getProgram() == null) {
			return;
		}

		RelocationTable relocationTable = getProgram().getRelocationTable();
		Iterator<Relocation> iterator = relocationTable.getRelocations();
		while (iterator.hasNext()) {
			Relocation r = iterator.next();
			accumulator.add(r);
		}
	}

	@Override
	public Address getAddress(int row) {
		Relocation relocation = filteredData.get(row);
		return relocation.getAddress();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	private static class RelocationTypeColumn extends
			AbstractProgramBasedDynamicTableColumn<Relocation, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_TYPE;
		}

		@Override
		public String getValue(Relocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return "0x" + Integer.toHexString(rowObject.getType());
		}

	}

	private static class RelocationValueColumn extends
			AbstractProgramBasedDynamicTableColumn<Relocation, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_VALUE;
		}

		@Override
		public String getValue(Relocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return packValues(rowObject.getValues());
		}

		private String packValues(long[] values) {
			if (values == null) {
				return "";
			}
			StringBuffer buf = new StringBuffer();
			for (long v : values) {
				if (buf.length() != 0) {
					buf.append(", ");
				}
				buf.append(NumericUtilities.toHexString(v));
			}
			return buf.toString();
		}
	}

	private static class RelocationBytesColumn extends
			AbstractProgramBasedDynamicTableColumn<Relocation, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_BYTES;
		}

		@Override
		public String getValue(Relocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return packBytes(rowObject.getBytes());
		}

		private String packBytes(byte[] bytes) {
			if (bytes == null) {
				return "";
			}
			StringBuffer buf = new StringBuffer();
			for (long b : bytes) {
				if (buf.length() != 0) {
					buf.append(' ');
				}
				String byteStr = Long.toHexString(b & 0xff);
				if (byteStr.length() == 1) {
					buf.append('0');
				}
				buf.append(byteStr);
			}
			return buf.toString();
		}
	}

	private static class RelocationNameColumn extends
			AbstractProgramBasedDynamicTableColumn<Relocation, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_NAME;
		}

		@Override
		public String getValue(Relocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSymbolName();
		}

	}
}
