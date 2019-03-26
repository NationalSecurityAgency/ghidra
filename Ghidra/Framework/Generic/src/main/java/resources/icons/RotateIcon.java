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
package resources.icons;

import java.awt.*;

import javax.swing.Icon;

public class RotateIcon implements Icon {

	private final Icon icon;
	private final int degrees;
	private String description;

	public RotateIcon(Icon icon, int degrees) {
		this.icon = icon;
		this.degrees = degrees;
	}

	@Override
	public int getIconHeight() {
		return icon.getIconHeight();
	}

	@Override
	public int getIconWidth() {
		return icon.getIconWidth();
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		Graphics2D g2 = (Graphics2D) g;
		int height = getIconHeight();
		int width = getIconWidth();
		int rotX = x + (width >> 1);
		int rotY = y + (height >> 1);

		g2.rotate(Math.toRadians(degrees), rotX, rotY);
		icon.paintIcon(c, g, x, y);
		g2.rotate(-Math.toRadians(degrees), rotX, rotY);
	}

	@Override
	public String toString() {
		if (description == null) {
			description = icon.toString();
		}
		return description;
	}
}
