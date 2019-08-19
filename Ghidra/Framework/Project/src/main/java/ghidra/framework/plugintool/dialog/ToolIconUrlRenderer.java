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
package ghidra.framework.plugintool.dialog;

import java.awt.Color;
import java.awt.Component;

import javax.swing.BorderFactory;
import javax.swing.JList;
import javax.swing.border.Border;

import docking.util.image.ToolIconURL;
import docking.widgets.list.GListCellRenderer;

class ToolIconUrlRenderer extends GListCellRenderer<ToolIconURL> {
	private Border emptyBorder = BorderFactory.createEmptyBorder(5, 5, 5, 5);
	private Border blueLineBorder = BorderFactory.createLineBorder(Color.BLUE, 2);
	private Border emptyBlueBorder = BorderFactory.createEmptyBorder(3, 3, 3, 3);
	private Border blueCompoundBorder =
		BorderFactory.createCompoundBorder(emptyBlueBorder, blueLineBorder);

	ToolIconUrlRenderer() {
		setBorder(emptyBorder);
		setShouldAlternateRowBackgroundColors(false);
	}

	@Override
	protected String getItemText(ToolIconURL value) {
		return "";
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends ToolIconURL> list,
			ToolIconURL toolIconUrl, int index, boolean isSelected, boolean cellHasFocus) {

		// lie to our parent about the selected status to disable the background selection color
		super.getListCellRendererComponent(list, toolIconUrl, index, false, cellHasFocus);
		setIcon(toolIconUrl.getIcon());
		setBorder(isSelected ? blueCompoundBorder : emptyBorder);
		return this;
	}

}
