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
package resources.icons;

import java.awt.Component;
import java.awt.Graphics;

import javax.swing.Icon;

import resources.ResourceManager;

public class TranslateIcon implements Icon {
	Icon icon;
	int translateX;
	int translateY;

	/** Where the translate values are offset from the icon's upper corner */
	public TranslateIcon(Icon icon, int translateX, int translateY) {
		this.icon = icon;
		this.translateX = translateX;
		this.translateY = translateY;
	}

	/**
	 * @see javax.swing.Icon#paintIcon(java.awt.Component, java.awt.Graphics, int, int)
	 */
	public void paintIcon(Component c, Graphics g, int x, int y) {
		icon.paintIcon(c, g, x + translateX, y + translateY);
	}

	public int getIconHeight() {
		return icon.getIconHeight();
	}

	public int getIconWidth() {
		return icon.getIconWidth();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[" + ResourceManager.getIconName(icon) + "]";
	}
}
