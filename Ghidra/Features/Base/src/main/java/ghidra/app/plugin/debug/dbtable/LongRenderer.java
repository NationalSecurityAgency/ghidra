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
package ghidra.app.plugin.debug.dbtable;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.SwingConstants;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;

public class LongRenderer extends GTableCellRenderer {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		renderer.setHorizontalAlignment(SwingConstants.LEADING);

		return renderer;
	}

	@Override
	protected String getText(Object value) {
		return value == null ? "" : "0x" + Long.toHexString((Long) value);
	}

	@Override
	protected String formatNumber(Number value, Settings settings) {
		return getText(value);
	}
}
