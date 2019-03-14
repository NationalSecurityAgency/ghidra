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
package ghidra.app.util.bean;

import java.util.Comparator;
import java.util.List;

import docking.widgets.table.*;
import ghidra.app.util.bean.SetEquateDialog.EquateRowObject;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;

public class SetEquateTableModel extends GDynamicColumnTableModel<EquateRowObject, Program> {

	private List<EquateRowObject> data;
	private Program program;

	public SetEquateTableModel(ServiceProvider serviceProvider, List<EquateRowObject> data,
			Program program) {
		super(serviceProvider);
		this.data = data;
		this.program = program;
	}

	@Override
	public String getName() {
		return "Set Equate";
	}

	@Override
	public List<EquateRowObject> getModelData() {
		return data;
	}

	@Override
	protected TableColumnDescriptor<EquateRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<EquateRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new NameColumn(), 2, true);
		descriptor.addVisibleColumn(new PathColumn());
		descriptor.addVisibleColumn(new RefsColumn(), 1, false);

		return descriptor;
	}

	@Override
	public Program getDataSource() {
		return program;
	}

	private class NameColumn extends AbstractDynamicTableColumn<EquateRowObject, String, Object> {
		private Comparator<String> comparator = new CaseInsensitiveComparator();

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(EquateRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getEntryName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 280;
		}

		@Override
		public Comparator<String> getComparator() {
			return comparator;
		}
	}

	private class PathColumn extends AbstractDynamicTableColumn<EquateRowObject, String, Object> {

		private Comparator<String> comparator = new CaseInsensitiveComparator();

		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public String getValue(EquateRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getPath();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 310;
		}

		@Override
		public Comparator<String> getComparator() {
			return comparator;
		}
	}

	private class RefsColumn extends AbstractDynamicTableColumn<EquateRowObject, Integer, Object> {
		@Override
		public String getColumnName() {
			return "# Refs";
		}

		@Override
		public Integer getValue(EquateRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getRefCount();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	private class CaseInsensitiveComparator implements Comparator<String> {

		@Override
		public int compare(String o1, String o2) {

			if (o1 == null && o2 == null) {
				return 0;
			}
			else if (o1 != null && o2 == null) {
				return -1;
			}
			else if (o1 == null && o2 != null) {
				return 1;
			}
			return o1.compareToIgnoreCase(o2);
		}
	}

}
