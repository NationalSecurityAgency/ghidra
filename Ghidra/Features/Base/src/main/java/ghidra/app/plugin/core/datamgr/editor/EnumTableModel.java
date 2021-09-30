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
package ghidra.app.plugin.core.datamgr.editor;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortState;
import ghidra.program.model.data.EnumDataType;
import ghidra.util.NumericUtilities;

/**
 * Model for the enum editor table.
 */
class EnumTableModel extends AbstractSortedTableModel<EnumEntry> {

	final static int NAME_COL = 0;
	final static int VALUE_COL = 1;
	final static int COMMENT_COL = 2;

	final static String NAME = "Name";
	final static String VALUE = "Value";
	final static String COMMENT = "Comment";
	private static String[] columnNames = { NAME, VALUE, COMMENT };

	private EnumDataType enuum;
	private List<EnumEntry> enumEntryList;

	private boolean isChanged;
	private EnumEditorPanel editorPanel;

	EnumTableModel(EnumDataType enuum, EnumEditorPanel editorPanel) {
		super(VALUE_COL);
		this.enuum = enuum;
		this.editorPanel = editorPanel;
		initialize();
	}

	@Override
	public String getName() {
		return "Enum Editor";
	}

	@Override
	public int getRowCount() {
		return enuum.getCount();
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return true;
	}

	@Override
	public Object getColumnValueForRow(EnumEntry v, int columnIndex) {
		switch (columnIndex) {
			case NAME_COL:
				return v.getName();

			case VALUE_COL:
				long mask;

				switch (enuum.getLength()) {
					case 1:
						mask = 0xffL;
						break;
					case 2:
						mask = 0xffffL;
						break;
					case 4:
						mask = 0xffffffffL;
						break;
					default:
					case 8:
						mask = 0xffffffffffffffffL;
						break;
				}

				return "0x" + Long.toHexString(v.getValue() & mask);

			case COMMENT_COL:
				return v.getComment();
		}
		return null;
	}

	@Override
	public List<EnumEntry> getModelData() {
		return enumEntryList;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		int size = enumEntryList.size();

		if (rowIndex < 0 || rowIndex >= size) {
			return;
		}

		boolean notifyListener = false;
		EnumEntry entry = enumEntryList.get(rowIndex);
		Long oldValue = entry.getValue();
		String oldName = entry.getName();
		String oldComment = entry.getComment();

		switch (columnIndex) {
			case NAME_COL:
				String newName = (String) aValue;
				if (!oldName.equals(newName) && isNameValid(newName)) {
					enuum.remove(oldName);
					enuum.add(newName, oldValue, oldComment);
					entry.setName(newName);
					notifyListener = true;
				}
				break;

			case VALUE_COL:
				try {
					if ("".equals(aValue)) {
						// Ignore attempts to erase the value
						// This is useful for an invalid paste, and also addresses failed
						// setText() calls in the unit tests
						return;
					}
					Long newValue = NumericUtilities.parseLong((String) aValue);
					if (!oldValue.equals(newValue)) {
						enuum.remove(oldName);
						try {
							enuum.add(oldName, newValue, oldComment);
							entry.setValue(newValue);
							notifyListener = true;
						}
						catch (IllegalArgumentException e) {
							enuum.add(oldName, oldValue, oldComment);
							editorPanel.setStatusMessage(e.getMessage());
						}
					}
				}
				catch (NumberFormatException e) {
					editorPanel.setStatusMessage("Invalid number entered");
				}
				break;

			case COMMENT_COL:
				String newComment = (String) aValue;
				if (!oldComment.equals(newComment) && newComment != null) {
					enuum.remove(oldName);
					enuum.add(oldName, oldValue, newComment);
					entry.setComment(newComment);
					notifyListener = true;
				}
				break;
		}
		if (notifyListener) {
			editorPanel.stateChanged(null);
			isChanged = true;
			editorPanel.restoreSelection(oldName, true);
		}
		else {
			editorPanel.restoreSelection(oldName, false);
		}
	}

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public void setTableSortState(TableSortState sortState) {
		editorPanel.stopCellEditing();
		super.setTableSortState(sortState);
	}

	@Override
	protected Comparator<EnumEntry> createSortComparator(int columnIndex) {
		if (columnIndex == NAME_COL) {
			return new EnumNameComparator();
		}
		return new EnumValueComparator();
	}

	EnumDataType getEnum() {
		return enuum;
	}

	boolean hasChanges() {
		return isChanged;
	}

	@Override
	public void dispose() {
		super.dispose();
		isChanged = false;
		enumEntryList.clear();
	}

	int getRow(String name) {
		for (int i = 0; i < enumEntryList.size(); i++) {
			if (enumEntryList.get(i).getName().equals(name)) {
				return i;
			}
		}
		return -1;
	}

	String getNameAt(int index) {
		return enumEntryList.get(index).getName();
	}

	void setEnum(EnumDataType enuum, boolean isChanged) {
		this.enuum = enuum;
		this.isChanged = isChanged;
		initialize();
	}

	/**
	 * Add a new enum entry that has default values.
	 * @return the new value
	 */
	int addEntry(int afterRow) {
		Long value = findNextValue(afterRow);
		String name = getUniqueName();
		String comment = "";
		EnumEntry newEntry = new EnumEntry(name, value, comment);
		try {
			enuum.add(name, value.longValue(), comment);
			int index = getIndexForRowObject(newEntry);
			if (index < 0) {
				index = -index - 1;
			}
			enumEntryList.add(newEntry);

			fireTableDataChanged();
			isChanged = true;
			return index;

		}
		catch (IllegalArgumentException e) {
			editorPanel.setStatusMessage(e.getMessage());
			return -1;
		}
	}

	private long findNextValue(int afterRow) {
		if (enumEntryList.isEmpty()) {
			return 0;
		}
		if (afterRow < 0 || afterRow >= enumEntryList.size()) {
			afterRow = 0;
		}
		long value = enumEntryList.get(afterRow).getValue() + 1;
		if (isTooBig(value)) {
			value = 0;
		}
		boolean wrapOK = value != 0;
		while (enuum.getName(value) != null) {
			if (isTooBig(++value)) {
				if (wrapOK) {
					value = 0;
				}
				else {
					break;
				}
			}
		}
		return value;
	}

	boolean isValueTooBigForLength(long value, int length) {
		if (length < 8) {
			long max = (1L << (8 * length)) - 1;
			return value > max || value < 0;
		}
		return false;
	}

	private boolean isTooBig(long value) {
		int len = enuum.getLength();
		return isValueTooBigForLength(value, len);
	}

	private String getUniqueName() {
		String name = "New_Name";
		int count = 0;
		while (enumContainsName(name)) {
			++count;
			name = "New_Name_(" + count + ")";
		}
		return name;
	}

	private void initialize() {
		enumEntryList = new ArrayList<>();
		String[] names = enuum.getNames();
		for (String name : names) {
			enumEntryList.add(new EnumEntry(name, enuum.getValue(name), enuum.getComment(name)));
		}
		fireTableDataChanged();
	}

	private boolean isNameValid(String name) {
		if (name == null || name.length() == 0) {
			editorPanel.setStatusMessage("Please enter a name");
			return false;
		}

		if (enumContainsName(name)) {
			editorPanel.setStatusMessage(name + " already exists");
			return false;
		}
		return true;
	}

	private boolean enumContainsName(String name) {
		try {
			enuum.getValue(name);
			return true;
		}
		catch (NoSuchElementException e) {
			return false;
		}
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	public void setLength(int length) {
		enuum.setLength(length);
		if (getRowCount() > 0) {
			fireTableRowsUpdated(0, getRowCount() - 1);
		}
	}

	private class EnumNameComparator implements Comparator<EnumEntry> {
		@Override
		public int compare(EnumEntry entry1, EnumEntry entry2) {
			return entry1.getName().compareTo(entry2.getName());
		}
	}

	private class EnumValueComparator implements Comparator<EnumEntry> {
		@Override
		public int compare(EnumEntry entry1, EnumEntry entry2) {
			return Long.valueOf(entry1.getValue()).compareTo(Long.valueOf(entry2.getValue()));
		}
	}

}
