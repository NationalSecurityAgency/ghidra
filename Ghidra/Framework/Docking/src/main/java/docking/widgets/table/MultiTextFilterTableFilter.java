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

import docking.widgets.filter.MultitermEvaluationMode;
import docking.widgets.filter.TextFilter;

public class MultiTextFilterTableFilter<ROW_OBJECT> implements TableFilter<ROW_OBJECT> {

	private final List<TextFilter> filters;
	private final RowFilterTransformer<ROW_OBJECT> transformer;
	private final MultitermEvaluationMode evalMode;

	public MultiTextFilterTableFilter(List<TextFilter> filters,
			RowFilterTransformer<ROW_OBJECT> transformer, MultitermEvaluationMode evalMode) {
		this.filters = filters;
		this.transformer = transformer;
		this.evalMode = evalMode;
	}

	@Override
	public boolean isSubFilterOf(TableFilter<?> tableFilter) {
		if (!(tableFilter instanceof MultiTextFilterTableFilter)) {
			return false;
		}

		MultiTextFilterTableFilter<?> other = (MultiTextFilterTableFilter<?>) tableFilter;
		if (filters.size() != other.filters.size()) {
			return false;
		}

		for (int i = 0; i < filters.size(); i++) {
			TextFilter filter = filters.get(i);
			TextFilter otherFilter = other.filters.get(i);
			if (!filter.isSubFilterOf(otherFilter)) {
				return false;
			}
		}

		Class<?> clazz = transformer.getClass();
		Class<?> otherClazz = other.transformer.getClass();
		return clazz.equals(otherClazz);
	}

	@Override
	public boolean acceptsRow(ROW_OBJECT rowObject) {
		if (filters.isEmpty()) {
			return true;
		}

		List<String> columnData = transformer.transform(rowObject);

		if (evalMode == MultitermEvaluationMode.AND) {
			// @formatter:off
			return filters.parallelStream()
				.map(f -> matches(f, columnData))
				.allMatch(m -> m == true);
			// @formatter:on

		}
		// @formatter:off
		return filters.parallelStream()
				.map(f -> matches(f, columnData))
				.anyMatch(m -> m == true);
		// @formatter:on
	}

	private static boolean matches(TextFilter filter, List<String> columnData) {
		// @formatter:off
		return columnData.parallelStream()
			.map(data -> filter.matches(data))
			.anyMatch(r -> r == true);
		// @formatter:on
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

		MultiTextFilterTableFilter<?> other = (MultiTextFilterTableFilter<?>) obj;
		if (evalMode != other.evalMode) {
			return false;
		}

		if (!Objects.equals(filters, other.filters)) {
			return false;
		}

		if (!Objects.equals(transformer, other.transformer)) {
			return false;
		}
		return true;
	}

}
