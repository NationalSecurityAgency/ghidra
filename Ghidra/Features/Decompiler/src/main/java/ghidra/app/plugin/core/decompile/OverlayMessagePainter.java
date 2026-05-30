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
package ghidra.app.plugin.core.decompile;

import java.awt.*;

import org.apache.commons.lang3.StringUtils;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.Gui;

/**
 * Class to overlay a message on the decompiler panel to indicate the display is stale and
 * needs to be refreshed manually.
 */
class OverlayMessagePainter {
	private static final int MARGIN = 10;
	private static final String FONT_ID = "font.graph.component.message";
	private final Color gradientColor = new GColor("color.bg.visualgraph.message");
	private String message;

	void setMessage(String message) {
		this.message = message;
	}

	boolean isActive() {
		return !StringUtils.isBlank(message);
	}

	void paintOverlay(Graphics g, Rectangle bounds) {
		if (!isActive()) {
			return;
		}

		Graphics2D g2 = (Graphics2D) g;

		// this composite softens the text and color of the message
		Composite originalComposite = g2.getComposite();
		g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), .60f));

		// set up font
		Font font = Gui.getFont(FONT_ID);
		g.setFont(font);
		Rectangle textBounds = font.getStringBounds(message, g2.getFontRenderContext()).getBounds();

		int gh = textBounds.height * 3;
		int gy = bounds.height - gh;
		paintGradient(g2, 0, gy, bounds.width, gh);

		// paint message
		g2.setPaint(Palette.BLACK);
		int textX = bounds.width - textBounds.width - MARGIN;
		int textY = bounds.height - textBounds.height / 2; //text at bottom; account for baseline
		g2.drawString(message, textX, textY);

		g2.setComposite(originalComposite);
	}

	private void paintGradient(Graphics2D g2, int x, int y, int w, int h) {
		Color[] colors = new Color[] { Color.WHITE, gradientColor };
		float[] fractions = new float[] { 0.0f, .95f };
		LinearGradientPaint gradiantPaint =
			new LinearGradientPaint(new Point(x, y), new Point(x, y + h), fractions, colors);
		g2.setPaint(gradiantPaint);
		g2.fillRect(x, y, w, h);
	}

}
