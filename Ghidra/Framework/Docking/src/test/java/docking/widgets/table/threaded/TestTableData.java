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

import java.util.List;

import docking.widgets.table.TableSortingContext;

/**
 * A version of {@link TableData} that can be used for testing
 *
 * @param <ROW_OBJECT> the row type
 */
public class TestTableData<ROW_OBJECT> extends TableData<ROW_OBJECT> {

	public TestTableData(List<ROW_OBJECT> data, TableSortingContext<ROW_OBJECT> sortContext) {
		super(data, sortContext);
	}
}
