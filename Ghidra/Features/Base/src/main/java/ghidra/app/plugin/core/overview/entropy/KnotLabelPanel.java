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
import java.util.ArrayList;

import javax.swing.JPanel;

public class KnotLabelPanel extends JPanel {
	private static final Font FONT = new Font("Times New Roman", Font.BOLD, 16);
	private int topBottomMargin = 10;
	private Palette palette;

	public KnotLabelPanel(int topBottomMargin) {
		this.topBottomMargin = topBottomMargin;
	}

	public void setPalette(Palette palette) {
		this.palette = palette;
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);

		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		int height = getHeight() - 2 * topBottomMargin;
		int width = getWidth();
		g.setColor(getBackground());
		g.fillRect(0, 0, width, height);
		int paletteSize = palette.getSize();
		g.setFont(FONT);
		FontMetrics fontMetrics = g.getFontMetrics();
		int ascent = fontMetrics.getAscent();
		int descent = fontMetrics.getDescent();
		int fontOffset = ascent / 3;  // this looks about right
		ArrayList<KnotRecord> knots = palette.getKnots();

		g.setColor(Color.BLACK);
		g.drawLine(5, topBottomMargin - 6, 10, topBottomMargin - ascent + 2);
		g.drawString("min entropy (0.0)", 20, topBottomMargin - ascent - descent);

		g.drawLine(5, topBottomMargin + 2, 10, topBottomMargin + 2);
		g.drawString("uniform byte values", 20, topBottomMargin + ascent / 2);

		for (KnotRecord record : knots) {
			int start = (record.start * height) / paletteSize;
			int end = (record.end * height) / paletteSize;
			int y = topBottomMargin + (start + end) / 2;
			g.drawString(getLabel(record), 20, y + fontOffset);
			g.drawLine(5, y, 10, y);
		}

		g.setColor(Color.BLACK);
		g.drawLine(5, height + topBottomMargin + 4, 10, height + topBottomMargin + 8);
		g.drawString("max entropy (8.0)", 20, topBottomMargin + height + ascent + descent);

	}

	private String getLabel(KnotRecord record) {
		StringBuffer buf = new StringBuffer();
		buf.append(record.name);
		return buf.toString();
	}
}
