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
package docking.widgets.filechooser;

import java.io.File;
import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;

class DirectoryTableModel extends AbstractSortedTableModel<File> {
	private static final long serialVersionUID = 1L;

	final static int FILE_COL = 0;
	final static int SIZE_COL = 1;
	final static int TIME_COL = 2;

	private GhidraFileChooser chooser;
	private File[] files = new File[0];

	DirectoryTableModel(GhidraFileChooser chooser) {
		super(FILE_COL);
		this.chooser = chooser;
	}

	void insert(File file) {
		int len = files.length;
		File[] arr = new File[len + 1];
		System.arraycopy(files, 0, arr, 0, len);
		arr[len] = file;
		files = arr;
		fireTableRowsInserted(len, len);
	}

	void setFiles(List<File> fileList) {
		this.files = new File[fileList.size()];
		files = fileList.toArray(files);
		System.arraycopy(files, 0, this.files, 0, files.length);
		fireTableDataChanged();
	}

	File getFile(int row) {
		if (row >= 0 && row < files.length) {
			return files[row];
		}
		return null;
	}

	void setFile(int row, File file) {
		if (row >= 0 && row < files.length) {
			files[row] = file;
			fireTableRowsUpdated(row, row);
		}
	}

	@Override
	public String getName() {
		return "Directory";
	}

	@Override
	public int getRowCount() {
		return files == null ? 0 : files.length;
	}

	@Override
	public boolean isCellEditable(int row, int column) {
		return false;
	}

	@Override
	public int getColumnCount() {
		return 3;
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case FILE_COL:
				return File.class;
			case SIZE_COL:
				return Long.class;
			case TIME_COL:
				return Date.class;
		}
		return String.class;
	}

	@Override
	public String getColumnName(int column) {
		switch (column) {
			case FILE_COL:
				return "Filename";
			case SIZE_COL:
				return "Size";
			case TIME_COL:
				return "Modified";
		}
		return "<<unknown>>";
	}

	@Override
	public Object getColumnValueForRow(File file, int columnIndex) {
		switch (columnIndex) {
			case FILE_COL:
				return file;
			case SIZE_COL:
				if (!chooser.getModel().isDirectory(file)) {
					return file.length();
				}
				break;
			case TIME_COL:
				return new Date(file.lastModified());
		}
		return null;
	}

	@Override
	public List<File> getModelData() {
		return Arrays.asList(files);
	}

	@Override
	// overridden to provide access in this package
	protected int getIndexForRowObject(File rowObject) {
		return super.getIndexForRowObject(rowObject);
	}

	@Override
	public void setValueAt(Object aValue, int row, int column) {
		if (row < 0 || row >= files.length) {
			return;
		}

		if (aValue == null) {
			return;
		}

		switch (column) {
			case FILE_COL:
				files[row] = (File) aValue;
				update();
				break;
		}
	}

	void update() {
		fireTableDataChanged();
	}

	@Override
	protected Comparator<File> createSortComparator(int columnIndex) {
		switch (columnIndex) {
			case FILE_COL:
				return new FileComparator(chooser.getModel(), FileComparator.SORT_BY_NAME);
			case SIZE_COL:
				return new FileComparator(chooser.getModel(), FileComparator.SORT_BY_SIZE);
			case TIME_COL:
				return new FileComparator(chooser.getModel(), FileComparator.SORT_BY_TIME);
			default:
				return super.createSortComparator(columnIndex);
		}
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}
}
