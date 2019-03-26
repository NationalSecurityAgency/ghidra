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

/**
 * Renderer for the {@link FVTable} that will set the background color based on
 * the text contents. This is intended to be used only for the log level 
 * column.
 */
public class LogLevelTableCellRenderer extends GTableCellRenderer {

	private static final Color TRACE_COLOR = Color.WHITE;
	private static final Color DEBUG_COLOR = new Color(135, 191, 212);
	private static final Color INFO_COLOR = new Color(225, 225, 225);
	private static final Color WARN_COLOR = new Color(255, 236, 50);
	private static final Color ERROR_COLOR = Color.RED;
	private static final Color FATAL_COLOR = Color.RED.darker();

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		setForeground(Color.black);

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
