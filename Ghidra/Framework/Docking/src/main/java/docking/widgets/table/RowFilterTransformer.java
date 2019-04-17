/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * Instances of this class converts table rows into lists of strings.  These objects can be set
 * on GTableFilterPanel to customize how the user typed text filters are applied to a table row.
 * For example, a custom row transformer could be used to limit which columns of a table are 
 * included in the filter.
 * @param <ROW_OBJECT> the table row object.
 */
public interface RowFilterTransformer<ROW_OBJECT> {
	public List<String> transform(ROW_OBJECT rowObject);
}
