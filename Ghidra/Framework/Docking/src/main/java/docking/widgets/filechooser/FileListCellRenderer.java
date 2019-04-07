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

import javax.swing.*;

import ghidra.util.filechooser.GhidraFileChooserModel;

class FileListCellRenderer extends DefaultListCellRenderer {

	private GhidraFileChooser chooser;
	private GhidraFileChooserModel model;

	public FileListCellRenderer(GhidraFileChooser chooser) {
		this.chooser = chooser;
		this.model = chooser.getModel();
	}

	@Override
	public Component getListCellRendererComponent(JList<?> list, Object value, int index,
			boolean isSelected, boolean cellHasFocus) {

		File file = (File) value;

		Component c = super.getListCellRendererComponent(list, chooser.getDisplayName(file), index,
			isSelected, cellHasFocus);
		if (c instanceof JLabel) {
			((JLabel) c).setIcon(model.getIcon(file));
		}
		return c;

	}

}
