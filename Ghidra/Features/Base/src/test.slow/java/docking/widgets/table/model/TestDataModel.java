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
package docking.widgets.table.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;

public class TestDataModel extends AbstractSortedTableModel<DirData> {
	List<DirData> data = new ArrayList<>();

	public TestDataModel() throws IOException {
		this("dirlist.txt");
	}

	public TestDataModel(String dataFile) throws IOException {
		super(4);

		data = DirData.loadTestData(dataFile);
	}

	@Override
	public String getName() {
		return "Test";
	}

	@Override
	public int getRowCount() {
		return data.size();
	}

	@Override
	public int getColumnCount() {
		return 5;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return "Date";
			case 1:
				return "Time";
			case 2:
				return "Directory";
			case 3:
				return "Size";
			case 4:
				return "Name";
		}
		return null;
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return String.class;
			case 1:
				return String.class;
			case 2:
				return Boolean.class;
			case 3:
				return Integer.class;
			case 4:
				return String.class;
		}
		return null;
	}

	@Override
	public Object getColumnValueForRow(DirData t, int columnIndex) {
		switch (columnIndex) {
			case 0:
				return t.getDate();
			case 1:
				return t.getTime();
			case 2:
				return t.isDir();
			case 3:
				return t.getSize();
			case 4:
				return t.getName();
		}
		return null;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<DirData> getModelData() {
		return data;
	}

}
