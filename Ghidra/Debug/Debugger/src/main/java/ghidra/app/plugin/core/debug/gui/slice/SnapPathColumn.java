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
package ghidra.app.plugin.core.debug.gui.slice;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

class SnapPathColumn extends AbstractDynamicTableColumnStub<PathRow, Long> {
	@Override
	public String getColumnName() {
		return "Snapshot";
	}

	@Override
	public Long getValue(PathRow row, Settings settings, ServiceProvider serviceProvider) {
		return row.getSnap();
	}
}
