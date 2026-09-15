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
import java.awt.Dimension;
import java.io.File;

import javax.swing.JList;

import docking.widgets.list.GListCellRenderer;
import ghidra.util.filechooser.GhidraFileChooserModel;

class FileListCellRenderer extends GListCellRenderer<File> {

	private GhidraFileChooser chooser;
	private GhidraFileChooserModel model;

	public FileListCellRenderer(GhidraFileChooser chooser) {
		this.chooser = chooser;
		this.model = chooser.getModel();
		setShouldAlternateRowBackgroundColors(false);
	}

	@Override
	protected String getItemText(File file) {
		return chooser.getDisplayName(file);
	}

	@Override
	public Dimension getPreferredSize() {
		/*
		 	The preferred size is used by the UI to pre-calculate the list's cell width to use while
		 	rendering. The default preferred size does not account for the border insets. Some LaFs
		 	appreciably change border size when focused. If the size of the cell is pre-calculated 
		 	using the smaller border size, then when the cell is focused text may be clipped, as the
		 	cell size does not get updated when the border is changed. Start with the biggest known 
		 	border size to prevent clipping.
		 */
		Dimension d = super.getPreferredSize();
		int borderWidth = getMaxBorderWidth();
		d.width += borderWidth;
		return d;
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends File> list, File file, int index,
			boolean isSelected, boolean cellHasFocus) {

		super.getListCellRendererComponent(list, file, index, isSelected, cellHasFocus);

		setIcon(model.getIcon(file));

		setToolTipText(null); // clear out previous cell's tool tip

		// As a performance tweak, the file chooser's list will get set to a fixed width when the 
		// number of directory items is large. (Clients may also choose to set a fixed width value.)
		// Setting a fixed width may cause a cell's text to get clipped.  When we get clipped text,
		// add a tooltip to show the full text.
		int fixedWidth = list.getFixedCellWidth();
		if (fixedWidth > 0) {
			Dimension d = getPreferredSize();
			if (d.getWidth() > fixedWidth) {
				setToolTipText(getText());
			}
		}
		return this;
	}

}
