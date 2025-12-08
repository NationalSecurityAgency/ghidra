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

import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;

import docking.widgets.list.GListCellRenderer;
import ghidra.util.Msg;
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
	public Component getListCellRendererComponent(JList<? extends File> list, File file, int index,
			boolean isSelected, boolean cellHasFocus) {

		super.getListCellRendererComponent(list, file, index, isSelected, cellHasFocus);
		setIcon(model.getIcon(file));

		// The file chooser's list will sometimes set a fixed width.  When that happens, the text
		// may get clipped.  When we get clipped text, add a tooltip to show the full text.
		int fixedWidth = list.getFixedCellWidth();
		if (fixedWidth > 0) {
			Dimension d = getPreferredSize();
			if (d.getWidth() > fixedWidth) {
				setToolTipText(getText());
			}	
			else {
				setToolTipText(null);
			}
		}

		return this;
	}

}
