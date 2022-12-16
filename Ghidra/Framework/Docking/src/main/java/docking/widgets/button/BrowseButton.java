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
package docking.widgets.button;

import java.awt.Component;
import java.awt.Graphics;

import javax.swing.Icon;
import javax.swing.JButton;

import generic.theme.GThemeDefaults.Colors;

/**
 * A button meant to be used to show a chooser dialog.
 */
public class BrowseButton extends JButton {

	public static final String NAME = "BrowseButton";
	public static final String TOOLTIP_TEXT = "Browse";

	private static final Icon ICON = new Icon() {
		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(Colors.FOREGROUND);
			g.fillRect(x, y + 5, 2, 2);
			g.fillRect(x + 4, y + 5, 2, 2);
			g.fillRect(x + 8, y + 5, 2, 2);
		}

		@Override
		public int getIconWidth() {
			return 10;
		}

		@Override
		public int getIconHeight() {
			return 10;
		}
	};

	public BrowseButton() {
		setIcon(ICON);
		setName(NAME);
		setToolTipText(TOOLTIP_TEXT);
	}
}
