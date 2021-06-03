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
package docking.widgets.table.threaded;

import docking.widgets.table.TableFilter;

/**
 * A table filter that represents the state of having no filter.  This allows us to not have to
 * use <code>null</code> to have multiple meanings.
 *
 * @param <ROW_OBJECT> the type of the row of the table model using this filter
 */
public class NullTableFilter<ROW_OBJECT> implements TableFilter<ROW_OBJECT> {

	@Override
	public boolean acceptsRow(ROW_OBJECT rowObject) {
		return true;
	}

	@Override
	public boolean isSubFilterOf(TableFilter<?> tableFilter) {
		// We want this to be false, as it represents the default state, with no filter applied.
		// It makes some sense to return true, as no filter implies all shall pass the filter, but
		// if this returns true, then any other filters can be used as the source of the data
		// to filter, which doesn't make sense if this is meant to only be used by itself.
		return false;
	}

	@Override
	public boolean isEmpty() {
		return true;
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
		return true;
	}

	@Override
	public int hashCode() {
		return getClass().hashCode();
	}
}
