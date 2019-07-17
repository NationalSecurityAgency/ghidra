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
package ghidra.app.plugin.core.overview.entropy;

import java.awt.*;

import javax.swing.JPanel;

public class PalettePanel extends JPanel {

	private Palette palette;
	private final int topBottomMargin;

	PalettePanel(int topBottomMargin) {
		this.topBottomMargin = topBottomMargin;
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(20, 10);
	}

	public void setPalette(Palette palette) {
		this.palette = palette;
	}

	@Override
	public void paintComponent(Graphics g) {
		super.paintComponent(g);
		int height = getHeight() - 2 * topBottomMargin;
		int width = getWidth();

		g.setColor(getBackground());
		g.fillRect(0, 0, getWidth(), getHeight());
		g.setColor(Color.BLACK);
		if (palette == null) {
			g.setColor(Color.BLACK);
			g.drawRect(0, 0, width - 1, height - 1);
			return;
		}
		int palsize = palette.getSize();
		//Draw the rectangles for each pixel
		for (int i = 0; i < height; i++) {
			int index = i * palsize / height;
			if (index >= palsize) {
				index = palsize - 1;
			}
			Color c = palette.getColor(index);
			g.setColor(c);
			g.fillRect(0, topBottomMargin + i, width, 1);
		}
		g.setColor(Color.BLACK);
		g.drawRect(0, topBottomMargin, width - 1, height);
	}

}
