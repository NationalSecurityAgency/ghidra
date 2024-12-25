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

import docking.widgets.table.AbstractDynamicTableColumn;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.util.table.column.GColumnRenderer;

public class TracePathStringColumn extends AbstractDynamicTableColumn<PathRow, String, Trace> {
	private final TracePathColumnRenderer<String> renderer = new TracePathColumnRenderer<>();

	@Override
	public String getColumnName() {
		return "Path";
	}

	@Override
	public GColumnRenderer<String> getColumnRenderer() {
		return renderer;
	}

	@Override
	public String getValue(PathRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return rowObject.getPath().getPath().toString();
	}
}
