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
package help.screenshot;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 
 * Each line is sized based on the font height and line padding on the top and bottom of the line.
 * The y coordinate tracks the top of the line, so a lines baseline (position to draw the text) 
 * is y + line padding + font accent.  
 */

public class TextFormatter {
	private static final Pattern PATTERN = Pattern.compile("\\|(.+?)\\|");

	private BufferedImage image;
	private Font font;
	private FontMetrics metrics;
	private int lineHeight;
	private int x;
	private int y;
	private int leftMargin;
	private int baselineOffset;
	private TextFormatterContext defaultContext = new TextFormatterContext(Color.BLACK);

	private int width;

	private int linePadding;

	private int topMargin;

	public TextFormatter(int lineCount, int width, int topMargin, int leftMargin, int linePadding) {
		this(null, lineCount, width, topMargin, leftMargin, linePadding);
	}

	public TextFormatter(Font f, int lineCount, int width, int topMargin, int leftMargin,
			int linePadding) {
		this.width = width;
		this.topMargin = topMargin;
		this.leftMargin = leftMargin;
		this.linePadding = linePadding;
		initializeSizes(f);
		createEmptyImage(lineCount);
		x = leftMargin;
		y = topMargin;
	}

	private void createEmptyImage(int lineCount) {
		int height = lineCount * (lineHeight) + topMargin * 2;
		image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = image.createGraphics();
		g.setColor(Color.WHITE);
		g.fillRect(0, 0, width, height);
		g.setColor(Color.black);
		g.drawRect(0, 0, width - 1, height - 1);
		g.dispose();
	}

	private void initializeSizes(Font f) {
		// dummy image to get font sizes.
		image = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = image.createGraphics();
		if (f == null) {
			f = new Font("Monospaced", Font.PLAIN, 14);
		}
		font = f;
		metrics = g.getFontMetrics(font);
		lineHeight = metrics.getHeight() + 2 * linePadding;
		baselineOffset = metrics.getAscent() + linePadding;
		g.dispose();

	}

	public void write(String text, TextFormatterContext... context) {
		int contextIndex = 0;
		int last = 0;
		Matcher matcher = PATTERN.matcher(text);
		while (matcher.find()) {
			int start = matcher.start();
			int end = matcher.end();

			print(text, last, start, defaultContext);
			print(text, start + 1, end - 1, context[contextIndex++]);
			last = end;
		}
		print(text, last, text.length(), defaultContext);
	}

	public void writeln(String text, TextFormatterContext... context) {
		write(text, context);
		newLine();
	}

	private void print(String text, int start, int end, TextFormatterContext context) {
		if (start >= text.length()) {
			return;
		}
		if (start == end) {
			return;			// empty text
		}
		String s = text.substring(start, end);
		out(s, context.fg, context.bg, context.cursor);
	}

	private TextFormatter out(String text, Color fg, Color bg, Color cursor) {
		Graphics2D g = image.createGraphics();
		g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
			RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		g.setFont(font);
		metrics = g.getFontMetrics(font);
		int stringWidth = metrics.stringWidth(text);
		if (bg != null) {
			g.setColor(bg);
			g.fillRect(x, y + linePadding, stringWidth, lineHeight - 2 * linePadding);
		}

		g.setColor(fg);
		g.drawString(text, x, y + baselineOffset);

		if (cursor != null) {
			g.setColor(cursor);
			g.setStroke(new BasicStroke(2f));
			g.drawLine(x, y + linePadding, x, y + baselineOffset);
		}
		g.dispose();
		x += stringWidth;
		return this;
	}

	public void colorLines(Color c, int line, int nLines) {
		Graphics2D g = image.createGraphics();
		g.setColor(c);
		int yPos = topMargin + line * lineHeight;
		int h = nLines * lineHeight;
		g.fillRect(0, yPos, width, h);
		g.dispose();
	}

	public TextFormatter newLine() {
		x = leftMargin;
		y += lineHeight;
		return this;
	}

	public Image getImage() {
		return image;
	}

}
