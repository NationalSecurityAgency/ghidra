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
package ghidra.app.plugin.core.bento;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;

class BentoMapModel extends AbstractSortedTableModel<BentoBox> {

	final static byte NAME = 0;
	final static byte XSTART = 1;
	final static byte XSTOP = 2;
	final static byte YSTART = 3;
	final static byte YSTOP = 4;

	final static String NAME_COL = "Name";
	final static String XSTART_COL = "Start X";
	final static String XSTOP_COL = "End X";
	final static String YSTART_COL = "Start Y";
	final static String YSTOP_COL = "End Y";

	private BentoProvider provider;
	private List<BentoBox> boxList = new ArrayList<>();
	private Map<String, BentoBox> boxMap = new HashMap<>();

	private List<Integer> columnIndices = new ArrayList<>(
		List.of(-1, 0, 0, 1, 1));
	private List<Boolean> columnBounds = new ArrayList<>(
		List.of(true, true, false, true, false));
	private List<String> columnNames = new ArrayList<>(
		List.of(NAME_COL, XSTART_COL, XSTOP_COL, YSTART_COL, YSTOP_COL));

	private List<String> names;
	private int xIndex = 0;
	private int yIndex = 1;

	public BentoMapModel(BentoProvider provider) {
		super(YSTART);
		this.provider = provider;
	}

	public List<BentoBox> getBoxes() {
		return Collections.unmodifiableList(boxList);
	}

	public void addBoxes(Collection<BentoBox> boxes) {
		boolean altered = false;
		for (BentoBox b : boxes) {
			if (b == null || b.getId() == null)
				continue;

			BentoBox oldBox = boxMap.put(b.getId(), b);
			if (oldBox != null) {
				boxList.remove(oldBox);
			}
			boxList.add(b);
			altered = true;
		}

		if (altered) {
			fireTableDataChanged();
		}
	}

	public void setBoxes(Collection<BentoBox> boxes) {
		boxList.clear();
		boxMap.clear();
		for (BentoBox b : boxes) {
			if (b == null || b.getId() == null) {
				continue;
			}
			boxList.add(b);
			boxMap.put(b.getId(), b);
		}
		fireTableDataChanged();
	}

	public void reset() {
		boxList.clear();
		boxMap.clear();
		fireTableDataChanged();
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public String getName() {
		return "X vs Y Map";
	}

	@Override
	public int getColumnCount() {
		return columnNames.size();
	}

	@Override
	public String getColumnName(int column) {

		if (column < 0 || column >= columnNames.size()) {
			return "UNKNOWN";
		}

		return columnNames.get(column);
	}

	/**
	 * Convenience method for locating columns by name. Implementation is naive so this should be
	 * overridden if this method is to be called often. This method is not in the TableModel
	 * interface and is not used by the JTable.
	 */
	@Override
	public int findColumn(String columnName) {
		for (int i = 0; i < columnNames.size(); i++) {
			if (columnNames.get(i).equals(columnName)) {
				return i;
			}
		}
		return 0;
	}

	/**
	 * Returns Object.class by default
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	/**
	 * Return whether this column is editable.
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	/**
	 * Returns the number of records managed by the data source object. A <B>JTable</B> uses this
	 * method to determine how many rows it should create and display. This method should be quick,
	 * as it is call by <B>JTable</B> quite frequently.
	 *
	 * @return the number or rows in the model
	 * @see #getColumnCount
	 */
	@Override
	public int getRowCount() {
		return boxList.size();
	}

	public BentoBox getBoxAt(int rowIndex) {
		if (rowIndex < 0 || rowIndex >= boxList.size()) {
			return null;
		}
		return boxList.get(rowIndex);
	}

	public int getIndexForBox(BentoBox box) {
		return boxList.indexOf(box);
	}

	@Override
	public Object getColumnValueForRow(BentoBox box, int columnIndex) {
		if (columnIndex == NAME) {
			return box.getId();
		}
		try {
			int objIndex = columnIndices.get(columnIndex);
			BoundedObject obj = box.getObj(objIndex);
			if (obj == null) {
				return "UNKNOWN";
			}

			Object rep = columnBounds.get(columnIndex) ? obj.getLowRep() : obj.getHiRep();
			if (rep instanceof Long lrep) {
				BentoRadix radix = provider.getRadix(columnIndices.get(columnIndex));
				rep = radix.format(lrep);
			}
			return rep;
		}
		catch (IndexOutOfBoundsException e) {
			return "UNKNOWN";
		}
	}

	@Override
	public List<BentoBox> getModelData() {
		return boxList;
	}

	@Override
	protected Comparator<BentoBox> createSortComparator(int columnIndex) {
		return new BentoComparator(columnIndex);
	}

	public List<String> getColumnNames() {
		return columnNames;
	}

	public void setColumnNames(List<String> names) {
		this.names = names;
		columnIndices.clear();
		columnBounds.clear();
		columnNames.clear();

		columnIndices.add(-1);
		columnBounds.add(true);
		columnNames.add(NAME_COL);

		int index = 0;
		for (String n : names) {
			columnIndices.add(index);
			columnIndices.add(index);
			columnBounds.add(true);
			columnBounds.add(false);
			columnNames.add("Start" + n);
			columnNames.add("Stop" + n);
			index++;
		}
		fireTableStructureChanged();
	}

	private class BentoComparator implements Comparator<BentoBox> {
		private final int sortColumn;

		public BentoComparator(int sortColumn) {
			this.sortColumn = sortColumn;
		}

		@Override
		public int compare(BentoBox b1, BentoBox b2) {
			if (b1 == b2) {
				return 0;
			}
			if (sortColumn == 0) {
				return b1.getId().compareToIgnoreCase(b2.getId());
			}
			if (sortColumn == xIndex * 2 + 1) {
				return (int) (b1.getObj(xIndex).getStart() - b2.getObj(xIndex).getStart());
			}
			if (sortColumn == xIndex * 2 + 2) {
				return (int) (b1.getObj(xIndex).getStop() - b2.getObj(xIndex).getStop());
			}
			if (sortColumn == yIndex * 2 + 1) {
				return (int) (b1.getObj(yIndex).getStart() - b2.getObj(yIndex).getStart());
			}
			if (sortColumn == yIndex * 2 + 2) {
				return (int) (b1.getObj(yIndex).getStop() - b2.getObj(yIndex).getStop());
			}
			return 0;
		}
	}

	public int getColumnIndex(int i) {
		return columnIndices.get(i);
	}

	protected void setIndex(boolean x, int index) {
		if (x) {
			this.xIndex = index;
		}
		else {
			this.yIndex = index;
		}
	}

	public String getTitle() {
		if (names.isEmpty()) {
			return "X \u00d7 Y";
		}
		return names.get(xIndex) + " \u00d7 " + names.get(yIndex);
	}
}
