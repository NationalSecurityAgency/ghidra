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
package ghidra.app.plugin.core.debug.gui.console;

import java.awt.Component;

import javax.swing.JTable;

import docking.widgets.table.CustomToStringCellRenderer;
import ghidra.debug.api.progress.MonitorReceiver;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;

public enum HtmlOrProgressCellRenderer implements GColumnRenderer<Object> {
	INSTANCE;

	static final CustomToStringCellRenderer<String> FOR_STRING =
		CustomToStringCellRenderer.HTML;
	static final MonitorCellRenderer FOR_MONITOR = MonitorCellRenderer.INSTANCE;

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {
		if (value == null) {
			return FOR_STRING.getTableCellRendererComponent(table, value, isSelected,
				hasFocus, row, column);
		}
		if (value instanceof String message) {
			return FOR_STRING.getTableCellRendererComponent(table, message, isSelected,
				hasFocus, row, column);
		}
		if (value instanceof MonitorReceiver monitor) {
			return FOR_MONITOR.getTableCellRendererComponent(table, monitor, isSelected,
				hasFocus, row, column);
		}
		throw new AssertionError();
	}

	int getRowHeight(int colWidth) {
		return FOR_STRING.getRowHeight(colWidth);
	}

	@Override
	public String getFilterString(Object t, Settings settings) {
		if (t == null) {
			return FOR_STRING.getFilterString(null, settings);
		}
		if (t instanceof String message) {
			return FOR_STRING.getFilterString(message, settings);
		}
		if (t instanceof MonitorReceiver monitor) {
			return FOR_MONITOR.getFilterString(monitor, settings);
		}
		throw new AssertionError();
	}
}
