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
package docking.util;

import java.awt.*;

import javax.swing.JComponent;
import javax.swing.plaf.LayerUI;

import generic.theme.GColor;
import generic.theme.Gui;

public class MessageOverlay extends LayerUI<JComponent> {
	private final String FONT_ID = "font.messageoverlay";
	private final Color backgroundColor = new GColor("color.bg.messageoverlay");
	private final Color textColor = new GColor("color.fg.messageoverlay");

	private String message = null;

	@Override
	public void paint(Graphics g, JComponent c) {
		super.paint(g, c);
		if (message == null) {
			return;
		}

		final Graphics2D g2 = (Graphics2D) g.create();

		g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, .60f));

		final Font font = Gui.getFont(FONT_ID);
		g2.setFont(font);

		FontMetrics fm = g2.getFontMetrics(font);

		final int bottomY = (int) (c.getY() + c.getHeight());

		final int startX = 0;
		final int startY = bottomY - 5;
		final Color[] colors = { backgroundColor, new Color(0, 0, 0, 0) };

		final int backgroundHeight = (fm.getHeight() * 3);
		final int backgroundWidth = c.getWidth();
		final int backgroundY = bottomY - backgroundHeight;

		final float[] fractions = { 0.0f, .95f };
		final int upperY = backgroundY;

		g2.setPaint(new LinearGradientPaint(new Point(startX, startY), new Point(startX, upperY),
			fractions, colors));
		g2.fillRect(startX, backgroundY, backgroundWidth, backgroundHeight);

		g2.setPaint(textColor);

		final int centerX = (c.getWidth() - fm.stringWidth(message)) / 2;
		g2.drawString(message, centerX, startY);
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
