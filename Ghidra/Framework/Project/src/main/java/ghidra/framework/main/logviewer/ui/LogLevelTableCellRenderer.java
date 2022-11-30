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
package ghidra.framework.main.logviewer.ui;

import java.awt.Color;
import java.awt.Component;

import org.apache.logging.log4j.Level;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GColor;

/**
 * Renderer for the {@link FVTable} that will set the background color based on
 * the text contents. This is intended to be used only for the log level 
 * column.
 */
public class LogLevelTableCellRenderer extends GTableCellRenderer {

	private static final Color TRACE_COLOR = new GColor("color.bg.logviwer.table.trace");
	private static final Color DEBUG_COLOR = new GColor("color.bg.logviwer.table.debug");
	private static final Color INFO_COLOR = new GColor("color.bg.logviwer.table.info");
	private static final Color WARN_COLOR = new GColor("color.bg.logviwer.table.warn");
	private static final Color ERROR_COLOR = new GColor("color.bg.logviwer.table.error");
	private static final Color FATAL_COLOR = new GColor("color.bg.logviwer.table.fatal");
	private static final Color FG = new GColor("color.fg.logviewer.table");
	private static final Color FG_SELECTED = new GColor("color.fg.logviewer.table.selected");

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		setForeground(data.isSelected() ? FG_SELECTED : FG);

		if (value.toString().equalsIgnoreCase(Level.DEBUG.toString())) {
			setBackground(DEBUG_COLOR);
		}
		else if (value.toString().equalsIgnoreCase(Level.TRACE.toString())) {
			setBackground(TRACE_COLOR);
		}
		else if (value.toString().equalsIgnoreCase(Level.WARN.toString())) {
			setBackground(WARN_COLOR);
		}
		else if (value.toString().equalsIgnoreCase(Level.INFO.toString())) {
			setBackground(INFO_COLOR);
		}
		else if (value.toString().equalsIgnoreCase(Level.ERROR.toString())) {
			setBackground(ERROR_COLOR);
		}
		else if (value.toString().equalsIgnoreCase(Level.FATAL.toString())) {
			setBackground(FATAL_COLOR);
		}

		return this;
	}

}
