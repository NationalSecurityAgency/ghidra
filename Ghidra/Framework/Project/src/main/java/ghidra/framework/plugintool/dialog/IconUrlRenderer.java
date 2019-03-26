/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.project.tool.ToolIconURL;

import java.awt.Color;
import java.awt.Component;

import javax.swing.*;
import javax.swing.border.Border;

class IconUrlRenderer extends JLabel implements ListCellRenderer {
	private Border        emptyBorder = BorderFactory.createEmptyBorder(5,5,5,5);
	private Border     blueLineBorder = BorderFactory.createLineBorder(Color.BLUE,2);
	private Border    emptyBlueBorder = BorderFactory.createEmptyBorder(3,3,3,3);
	private Border blueCompoundBorder = BorderFactory.createCompoundBorder(emptyBlueBorder, blueLineBorder);

	IconUrlRenderer() {
		super();
		setBorder(emptyBorder);
	}

	public Component getListCellRendererComponent(JList list, 
												Object value, 
												int index, 
												boolean isSelected, 
												boolean cellHasFocus) {
		if ((value instanceof ToolIconURL)) {
			ToolIconURL url = (ToolIconURL)value;

			setIcon(url.getIcon());
			setText(null);//setText(url.getLocation());
		}
		if (isSelected) {
			setBorder(blueCompoundBorder);
		}
		else {
			setBorder(emptyBorder);
		}
		return this;
	}
}
