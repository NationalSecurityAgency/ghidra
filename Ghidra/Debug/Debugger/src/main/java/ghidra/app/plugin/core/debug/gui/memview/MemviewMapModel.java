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
package ghidra.app.plugin.core.debug.gui.memview;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.program.model.address.Address;

class MemviewMapModel extends AbstractSortedTableModel<MemoryBox> {

	final static byte NAME = 0;
	final static byte ASTART = 1;
	final static byte ASTOP = 2;
	final static byte TSTART = 3;
	final static byte TSTOP = 4;

	final static String NAME_COL = "Name";
	final static String ASTART_COL = "Start Address";
	final static String ASTOP_COL = "End Address";
	final static String TSTART_COL = "Start Time";
	final static String TSTOP_COL = "End Time";

	private List<MemoryBox> memList = new ArrayList<>();
	private Map<String, MemoryBox> memMap = new HashMap<>();
	private MemviewProvider provider;

	private final static String COLUMN_NAMES[] =
		{ NAME_COL, ASTART_COL, ASTOP_COL, TSTART_COL, TSTOP_COL };

	public MemviewMapModel(MemviewProvider provider) {
		super(ASTART);
		this.provider = provider;
	}

	public List<MemoryBox> getBoxes() {
		return memList;
	}

	public void addBoxes(Collection<MemoryBox> boxes) {
		if (memList == null) {
			memList = new ArrayList<>();
		}
		for (MemoryBox b : boxes) {
			if (memMap.containsKey(b.getId())) {
				MemoryBox mb = memMap.get(b.getId());
				memList.remove(mb);
			}
			memList.add(b);
			memMap.put(b.getId(), b);
		}
		fireTableDataChanged();
	}

	public void setBoxes(Collection<MemoryBox> boxes) {
		memList = new ArrayList<>();
		for (MemoryBox b : boxes) {
			memList.add(b);
			memMap.put(b.getId(), b);
		}
		fireTableDataChanged();
	}

	public void reset() {
		memList = new ArrayList<>();
		memMap.clear();
		fireTableDataChanged();
	}

	void update() {
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public String getName() {
		return "Memory vs Time Map";
	}

	@Override
	public int getColumnCount() {
		return COLUMN_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {

		if (column < 0 || column >= COLUMN_NAMES.length) {
			return "UNKNOWN";
		}

		return COLUMN_NAMES[column];
	}

	/**
	 * Convenience method for locating columns by name.
	 * Implementation is naive so this should be overridden if
	 * this method is to be called often. This method is not
	 * in the TableModel interface and is not used by the JTable.
	 */
	@Override
	public int findColumn(String columnName) {
		for (int i = 0; i < COLUMN_NAMES.length; i++) {
			if (COLUMN_NAMES[i].equals(columnName)) {
				return i;
			}
		}
		return 0;
	}

	/**
	 *  Returns Object.class by default
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == ASTART || columnIndex == ASTOP) {
			return Address.class;
		}
		return String.class;
	}

	/**
	 *  Return whether this column is editable.
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	/**
	 * Returns the number of records managed by the data source object. A
	 * <B>JTable</B> uses this method to determine how many rows it
	 * should create and display.  This method should be quick, as it
	 * is call by <B>JTable</B> quite frequently.
	 *
	 * @return the number or rows in the model
	 * @see #getColumnCount
	 */
	@Override
	public int getRowCount() {
		return memList.size();
	}

	public MemoryBox getBoxAt(int rowIndex) {
		if (memList == null) {
			return null;
		}
		if (rowIndex < 0 || rowIndex >= memList.size()) {
			return null;
		}
		MemoryBox box = memList.get(rowIndex);
		try {
			box.getStart();
		}
		catch (ConcurrentModificationException e) {
			update();
		}
		return memList.get(rowIndex);
	}

	public int getIndexForBox(MemoryBox box) {
		return memList.indexOf(box);
	}

	@Override
	public Object getColumnValueForRow(MemoryBox box, int columnIndex) {
		try {
			switch (columnIndex) {
				case NAME:
					return box.getId();
				case ASTART:
					return box.getRange().getMinAddress();
				case ASTOP:
					return box.getRange().getMaxAddress();
				case TSTART:
					return Long.toString(box.getStart());
				case TSTOP:
					long end = box.getEnd();
					if (end == Long.MAX_VALUE) {
						return "+" + '\u221e' + '\u2025';
					}
					return Long.toString(end);
				default:
					return "UNKNOWN";
			}
		}
		catch (ConcurrentModificationException e) {
			update();
		}
		return null;
	}

	@Override
	public List<MemoryBox> getModelData() {
		return memList;
	}

	@Override
	protected Comparator<MemoryBox> createSortComparator(int columnIndex) {
		return new MemoryMapComparator(columnIndex);
	}

	private class MemoryMapComparator implements Comparator<MemoryBox> {
		private final int sortColumn;

		public MemoryMapComparator(int sortColumn) {
			this.sortColumn = sortColumn;
		}

		@Override
		public int compare(MemoryBox b1, MemoryBox b2) {

			switch (sortColumn) {
				case NAME:
					return b1.getId().compareToIgnoreCase(b2.getId());
				case ASTART:
					return (int) (b1.getStartAddress() - b2.getStartAddress());
				case ASTOP:
					return (int) (b1.getStopAddress() - b2.getStopAddress());
				case TSTART:
					return (int) (b1.getStartTime() - b2.getStartTime());
				case TSTOP:
					return (int) (b1.getStopTime() - b2.getStopTime());
				default:
					return 0;
			}
		}
	}
}
