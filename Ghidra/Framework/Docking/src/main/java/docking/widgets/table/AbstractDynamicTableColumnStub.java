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

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

/**
 * This class is meant to be used by DynamicTableColumn implementations that do not care about
 * the DATA_SOURCE parameter of DynamicTableColumn.  This class will stub the default 
 * {@link #getValue(Object, Settings, Object, ServiceProvider)} method and
 * call a version of the method that does not have the DATA_SOURCE parameter.
 */
public abstract class AbstractDynamicTableColumnStub<ROW_TYPE, COLUMN_TYPE> extends
		AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Object> {

	@Override
	public COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, Object data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return getValue(rowObject, settings, serviceProvider);
	}

	public abstract COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings,
			ServiceProvider serviceProvider) throws IllegalArgumentException;
}
