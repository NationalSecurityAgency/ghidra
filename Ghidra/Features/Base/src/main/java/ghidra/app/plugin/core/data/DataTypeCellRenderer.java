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
package ghidra.app.plugin.core.data;

import java.awt.Color;
import java.awt.Component;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeInstance;

public class DataTypeCellRenderer extends GTableCellRenderer {
	private static final long serialVersionUID = 1L;

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();

		String dtString = "";
		boolean useRed = false;
		if (value instanceof DataTypeInstance) {
			DataType dt = ((DataTypeInstance) value).getDataType();
			dtString = dt.getDisplayName();
			if (dt.isNotYetDefined()) {
				useRed = true;
			}
		}

		GTableCellRenderingData renderData = data.copyWithNewValue(dtString);

		Component c =
			super.getTableCellRendererComponent(renderData);

		if (useRed) {
			c.setForeground(Color.RED);
		}

		return c;
	}
}
