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

import java.util.Comparator;
import java.util.Iterator;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.reloc.RelocationTableModel.RelocationRowObject;
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

class RelocationTableModel extends AddressBasedTableModel<RelocationRowObject> {

	private static Comparator<RelocationRowObject> ADDRESS_SORT_COMPARATOR =
		new Comparator<RelocationTableModel.RelocationRowObject>() {

			@Override
			public int compare(RelocationRowObject o1, RelocationRowObject o2) {
				int c = o1.relocation.getAddress().compareTo(o2.relocation.getAddress());
				if (c == 0) {
					c = o1.relocationIndex - o2.relocationIndex;
				}
				return c;
			}
		};

	static final int ADDRESS_COL = 0;
	static final int TYPE_COL = 1;
	static final int VALUE_COL = 2;
	static final int BYTES_COL = 3;
	static final int NAME_COL = 4;

	static final String RELOCATION_ADDRESS = "Address";
	static final String RELOCATION_TYPE = "Type";
	static final String RELOCATION_VALUE = "Values";
	static final String RELOCATION_BYTES = "Original Bytes";
	static final String RELOCATION_NAME = "Name";

	public RelocationTableModel(ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		super("Relocation Table Model", serviceProvider, program, monitor);
	}

	@Override
	protected TableColumnDescriptor<RelocationRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<RelocationRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new RelocationTypeColumn());
		descriptor.addVisibleColumn(new RelocationValueColumn());
		descriptor.addVisibleColumn(new RelocationBytesColumn());
		descriptor.addVisibleColumn(new RelocationNameColumn());

		return descriptor;
	}

	@Override
	protected Comparator<RelocationRowObject> createSortComparator(int columnIndex) {
		if (columnIndex == ADDRESS_COL) {
			return ADDRESS_SORT_COMPARATOR;
		}
		return super.createSortComparator(columnIndex);
	}

	@Override
	public void setProgram(Program p) {
		super.setProgram(p);
		reload();
		fireTableDataChanged();
	}

	@Override
	protected void doLoad(Accumulator<RelocationRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (getProgram() == null) {
			return;
		}

		int relocationIndex = 0;
		RelocationTable relocationTable = getProgram().getRelocationTable();
		Iterator<Relocation> iterator = relocationTable.getRelocations();
		while (iterator.hasNext()) {
			Relocation r = iterator.next();
			accumulator.add(new RelocationRowObject(r, ++relocationIndex));
		}
	}

	@Override
	public Address getAddress(int row) {
		RelocationRowObject rowObject = filteredData.get(row);
		return rowObject.relocation.getAddress();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	static class RelocationRowObject {

		/**
		 * The relocationIndex must be used to differentiate multiple relocations
		 * for the same address.  This must be used for secondary comparison when sorting on address.
		 */
		final int relocationIndex;
		final Relocation relocation;

		public RelocationRowObject(Relocation r, int relocationIndex) {
			this.relocationIndex = relocationIndex;
			this.relocation = r;
		}
	}

	private static class RelocationTypeColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_TYPE;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return "0x" + Integer.toHexString(rowObject.relocation.getType());
		}

	}

	private static class RelocationValueColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_VALUE;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return packValues(rowObject.relocation.getValues());
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
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_BYTES;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return packBytes(rowObject.relocation.getBytes());
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
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {

		@Override
		public String getColumnName() {
			return RELOCATION_NAME;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.relocation.getSymbolName();
		}

	}
}
