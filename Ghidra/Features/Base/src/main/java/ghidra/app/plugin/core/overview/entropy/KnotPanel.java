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
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.util.ArrayList;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.util.GraphicsUtils;
import docking.widgets.label.GLabel;

/**
 * Class used by the entropy legend panel to show known entropy ranges.
 */
public class KnotPanel extends JPanel implements ComponentListener {
	private static final long serialVersionUID = 1L;
	private static final int SPACING = 5;
	private static final Font FONT = new Font("SansSerif", Font.PLAIN, 10);
	private Palette palette = null;
	private FontMetrics metrics;

	private ChangeListener paletteListener = new ChangeListener() {
		@Override
		public void stateChanged(ChangeEvent e) {
			buildLabels();
		}
	};

	public KnotPanel() {
		super();
		addComponentListener(this);
		metrics = getFontMetrics(FONT);
		setPreferredSize(
			new Dimension(100, SPACING + metrics.getMaxAscent() + metrics.getMaxDescent()));
	}

	public void oldPaintComponent(Graphics g) {
		super.paintComponent(g);
		g.setColor(getBackground());
		Rectangle clip = g.getClipBounds();
		g.fillRect(clip.x, clip.y, clip.width, clip.height);

		if (palette == null) {
			return;
		}

		g.setColor(Color.BLACK);
		g.setFont(FONT);
		int height = getHeight();
		int width = getWidth();
		int palsize = palette.getSize();
		int fontHeight = metrics.getMaxAscent() + metrics.getMaxDescent();
		int baseline = (height - fontHeight - 1) / 2 + metrics.getMaxAscent();

		ArrayList<KnotRecord> knots = palette.getKnots();
		for (int i = 0; i < knots.size(); i++) {
			KnotRecord rec = knots.get(i);
			int start = (rec.start * width) / palsize;
			int end = (rec.end * width) / palsize;
			g.drawLine(start, 0, start, height - 1);
			g.drawLine(end, 0, end, height - 1);
			g.drawLine(start, height - 1, end, height - 1);

			FontMetrics currentMetrics = metrics;
			int w = currentMetrics.stringWidth(rec.name);
			int knotwidth = end - start;
			while (w > knotwidth) {
				currentMetrics = getSmallerFontMetrics(currentMetrics);
				w = currentMetrics.stringWidth(rec.name);

				if (currentMetrics.getFont().getSize() <= 4) {
					break; // can't go any smaller
				}
			}

			if (w < knotwidth) { // we found a suitable font
				g.setFont(currentMetrics.getFont());
				GraphicsUtils.drawString(this, g, rec.name, start + (knotwidth - 1) / 2 - w / 2,
					baseline);
				g.setFont(FONT);
			}
			else { // must be no room to paint the string, even with a small font
				String ellipsis = "...";
				w = metrics.stringWidth(ellipsis);
				GraphicsUtils.drawString(this, g, ellipsis, start + (knotwidth - 1) / 2 - w / 2,
					baseline);
			}

			// reset the font
			currentMetrics = metrics;
		}

	}

	private FontMetrics getSmallerFontMetrics(FontMetrics fontMetrics) {
		Font currentFont = fontMetrics.getFont();
		int size = currentFont.getSize();
		Font newFont = currentFont.deriveFont((float) --size);
		return getFontMetrics(newFont);
	}

	public void setPalette(Palette pal) {
		palette = pal;
		palette.addPaletteListener(paletteListener);
		buildLabels();
		repaint();
	}

	private void buildLabels() {
		removeAll();
		setLayout(null);

		int paletteSize = palette.getSize();
		Container parent = getParent();

		ArrayList<KnotRecord> knots = palette.getKnots();
		for (KnotRecord record : knots) {
			JLabel label = new GLabel(record.name);
			label.setFont(FONT);
			label.setBorder(new ToplessLineBorder(Color.BLACK));
			label.setHorizontalAlignment(SwingConstants.CENTER);
			label.setToolTipText(record.name);

			int height = getHeight();
			int width = getWidth();
			int start = (record.start * width) / paletteSize;
			int end = (record.end * width) / paletteSize;

			int labelWidth = end - start;
			int labelHeight = height - 1;
			int x = start + ((end - start >> 1) - (labelWidth >> 1));
			int y = 0;

			label.setBounds(x, y, labelWidth, labelHeight);
			add(label);
		}
		invalidate();
		if (parent != null) {
			parent.validate();
		}
	}

	public void refresh() {
		buildLabels();
		repaint();
	}

	@Override
	public void componentResized(ComponentEvent e) {
		refresh();
	}

	@Override
	public void componentHidden(ComponentEvent e) {
	}

	@Override
	public void componentMoved(ComponentEvent e) {
	}

	@Override
	public void componentShown(ComponentEvent e) {
	}

	private class ToplessLineBorder extends LineBorder {

		public ToplessLineBorder(Color color) {
			super(color);
		}

		@Override
		public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
			super.paintBorder(c, g, x, y - 1, width, height + 1);
		}
	}
}
