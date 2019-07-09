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

import java.util.List;
import java.util.Objects;

import docking.widgets.filter.TextFilter;

public class TableTextFilter<ROW_OBJECT> implements TableFilter<ROW_OBJECT> {

	private TextFilter textFilter;
	private RowFilterTransformer<ROW_OBJECT> transformer;

	public TableTextFilter(TextFilter textFilter, RowFilterTransformer<ROW_OBJECT> transformer) {
		this.textFilter = textFilter;
		this.transformer = transformer;
	}

	@Override
	public boolean isSubFilterOf(TableFilter<?> tableFilter) {
		if (!(tableFilter instanceof TableTextFilter)) {
			return false;
		}

		TableTextFilter<?> other = (TableTextFilter<?>) tableFilter;
		if (!textFilter.isSubFilterOf(other.textFilter)) {
			return false;
		}

		Class<?> clazz = transformer.getClass();
		Class<?> otherClazz = other.transformer.getClass();
		return clazz.equals(otherClazz);
	}

	@Override
	public boolean acceptsRow(ROW_OBJECT rowObject) {
		List<String> transform = transformer.transform(rowObject);
		for (String string : transform) {
			if (textFilter.matches(string)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public int hashCode() {
		// not meant to put in hashing structures; the data for equals may change over time
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		TableTextFilter<?> other = (TableTextFilter<?>) obj;
		if (!Objects.equals(textFilter, other.textFilter)) {
			return false;
		}

		if (!Objects.equals(transformer, other.transformer)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - filter='" + textFilter.getFilterText() + "'";
	}
}
