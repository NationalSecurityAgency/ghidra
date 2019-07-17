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
package ghidra.app.plugin.core.function.editor;

import java.awt.Component;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.program.model.address.Address;
import ghidra.util.NumericUtilities;

class VarnodeLocationTableCellRenderer extends GTableCellRenderer {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel label =
			(JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		if (value instanceof Address) {
			Address address = (Address) value;
			if (address.isStackAddress()) {
				label.setText(NumericUtilities.toSignedHexString(address.getOffset()));
			}
		}

		return label;
	}

}
