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

import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

import javax.help.UnsupportedOperationException;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

public interface EnumeratedColumnTableModel<R> extends RowObjectTableModel<R> {

	public interface EditableDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>
			extends DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> {
		default public boolean isEditable(ROW_TYPE row, Settings settings, DATA_SOURCE dataSource,
				ServiceProvider serviceProvider) {
			return false;
		}

		default public void setValueOf(ROW_TYPE row, COLUMN_TYPE value, Settings settings,
				DATA_SOURCE dataSource, ServiceProvider serviceProvider) {
			throw new UnsupportedOperationException("Cell is not editable");
		}
	}

	void add(R row);

	void addAll(Collection<R> c);

	void notifyUpdated(R row);

	List<R> notifyUpdatedWith(Predicate<R> predicate);

	void delete(R row);

	List<R> deleteWith(Predicate<R> predicate);

	R findFirst(Predicate<R> predicate);

	public void clear();
}
