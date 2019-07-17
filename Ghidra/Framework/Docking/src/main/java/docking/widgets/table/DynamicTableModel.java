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
package docking.widgets.table;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class DynamicTableModel<T> extends AbstractSortedTableModel<T> {
	private List<T> data;
	private List<AnnotatedColumn> columns = new ArrayList<>();

	public DynamicTableModel(List<T> data, Class<T> tClass) {
		this.data = data;
		Method[] methods = tClass.getMethods();
		for (Method method : methods) {
			if (method.isAnnotationPresent(ColumnAnnotation.class)) {
				columns.add(new AnnotatedColumn(method));
			}
		}
	}

	@Override
	public String getName() {
		return "Dynamic Table Model";
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public List<T> getModelData() {
		return data;
	}

	@Override
	public String getColumnName(int column) {
		return columns.get(column).getName();
	}

	@Override
	public Object getColumnValueForRow(T rowObject, int columnIndex) {
		return columns.get(columnIndex).getValue(rowObject);
	}

	class AnnotatedColumn {
		private String name;
		private Method method;

		public AnnotatedColumn(Method method) {
			this.method = method;
			name = method.getName();
			if (name.startsWith("get")) {
				name = name.substring(3);
			}
		}

		public String getName() {
			return name;
		}

		public Object getValue(T t) {

			try {
				return method.invoke(t);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e) {
				e.printStackTrace();
			}
			return null;
		}

	}
}
