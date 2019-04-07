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
package docking.widgets.filechooser;

import java.awt.Component;
import java.io.File;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.util.filechooser.GhidraFileChooserModel;

class FileTableCellRenderer extends GTableCellRenderer {

	private GhidraFileChooserModel model;
	private GhidraFileChooser chooser;

	public FileTableCellRenderer(GhidraFileChooser chooser) {
		this.model = chooser.getModel();
		this.chooser = chooser;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		File file = (File) data.getValue();
		data.setCellData(chooser.getDisplayName(file), data.getColumnViewIndex(), data.isSelected(),
			data.hasFocus());
		Component c = super.getTableCellRendererComponent(data);

		if (c instanceof JLabel) {
			((JLabel) c).setIcon(model.getIcon(file));
		}
		return c;

	}

}
