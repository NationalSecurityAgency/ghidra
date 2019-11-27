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
package docking.widgets;

import java.awt.Component;
import java.util.Date;

import javax.swing.JComponent;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.util.DateUtils;

/**
 * The JDK-provided DateRenderer does not inherit the backgrounds and such properly.
 * For LAFs having tables with alternating backgrounds, e.g., Aqua and Nimbus, the date
 * column does not have the correct background. This fixes that.
 */
public class GenericDateCellRenderer extends GTableCellRenderer {

	private String toolTip;

	public GenericDateCellRenderer() {
		this(null);
	}

	public GenericDateCellRenderer(String toolTip) {
		this.toolTip = toolTip;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Date value = (Date) data.getValue();

		GTableCellRenderingData newData =
			data.copyWithNewValue(DateUtils.formatDateTimestamp(value));

		JComponent c = (JComponent) super.getTableCellRendererComponent(newData);
		if (toolTip != null) {
			c.setToolTipText(toolTip);
		}
		return c;
	}
}
