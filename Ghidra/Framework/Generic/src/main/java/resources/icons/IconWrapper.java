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

/**
 * <code>IconWrapper</code> provides a simple icon wrapper which 
 * delays icon construction until its first use.
 */
public abstract class IconWrapper implements Icon {

	private Icon icon;

	/**
	 * Creates the icon upon first use.
	 * @return icon
	 */
	protected abstract Icon createIcon();

	private void init() {
		if (icon == null) {
			icon = createIcon();
		}
	}

	@Override
	public int getIconHeight() {
		init();
		return icon.getIconHeight();
	}

	@Override
	public int getIconWidth() {
		init();
		return icon.getIconWidth();
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		init();
		icon.paintIcon(c, g, x, y);
	}

}
