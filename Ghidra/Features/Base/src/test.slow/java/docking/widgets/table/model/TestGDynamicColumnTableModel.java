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
import java.util.List;

import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.framework.plugintool.ServiceProviderStub;

public class TestGDynamicColumnTableModel extends GDynamicColumnTableModel<DirData, Object> {

	private List<DirData> data;

	public TestGDynamicColumnTableModel() throws IOException {
		super(new ServiceProviderStub());

		data = DirData.loadTestData("dirlist.txt");
	}

	@Override
	public String getName() {
		return "Test";
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<DirData> getModelData() {
		return data;
	}

	@Override
	protected TableColumnDescriptor<DirData> createTableColumnDescriptor() {
		TableColumnDescriptor<DirData> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new DirDataNameColumn());
		descriptor.addVisibleColumn(new DirDataSizeColumn());
		descriptor.addVisibleColumn(new DirDataTimeColumn());
		descriptor.addVisibleColumn(new DirDataDateColumn());
		descriptor.addVisibleColumn(new DirDataTypeColumn());
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}
}
