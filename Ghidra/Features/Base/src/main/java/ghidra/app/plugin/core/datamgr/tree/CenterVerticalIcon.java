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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.Component;
import java.awt.Graphics;

import javax.swing.Icon;

public class CenterVerticalIcon implements Icon {
	private Icon icon;
	private int verticalOffset;
	private int height;

	public CenterVerticalIcon(Icon icon, int height) {
		this.icon = icon;
		this.height = height;
		verticalOffset = (height - icon.getIconHeight()) / 2;
	}

	public int getIconHeight() {
		return height;
	}

	public int getIconWidth() {
		return icon.getIconWidth();
	}

	public void paintIcon(Component c, Graphics g, int x, int y) {
		icon.paintIcon(c, g, x, y + verticalOffset);
	}

}
