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
package ghidra.app.plugin.core.debug.gui.model.columns;

import docking.widgets.table.DynamicTableColumn;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

public interface EditableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>
		extends DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> {
	boolean isEditable(ROW_TYPE row,
			Settings settings, DATA_SOURCE dataSource, ServiceProvider serviceProvider);

	// TODO: getCellEditor?

	void setValue(ROW_TYPE row, COLUMN_TYPE value, Settings settings, DATA_SOURCE dataSource,
			ServiceProvider serviceProvider);
}
