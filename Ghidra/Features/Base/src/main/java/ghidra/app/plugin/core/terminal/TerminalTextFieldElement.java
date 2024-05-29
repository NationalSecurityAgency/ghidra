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
package ghidra.app.plugin.core.terminal;

import java.awt.*;
import java.awt.geom.AffineTransform;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.plugin.core.terminal.vt.*;
import ghidra.app.plugin.core.terminal.vt.VtHandler.Intensity;

/**
 * A text field element for rendering a full line of terminal text
 * 
 * <p>
 * {@link TerminalTextFields} are populated by a single element. The typical pattern seems to be to
 * create a separate element for each bit of text having common attributes. This pattern would
 * generate quite a bit of garbage, since the terminal contents change frequently. Every time a line
 * content changed, we'd have to re-construct the elements. Instead, we use a single re-usable
 * element that renders the {@link VtLine} directly, including the variety of attributes. When the
 * line changes, we merely have to re-paint.
 */
public class TerminalTextFieldElement implements FieldElement {
	public static final int UNDERLINE_HEIGHT = 1;

	protected final VtLine line;
	protected final FontMetrics metrics;
	protected final AnsiColorResolver colors;

	protected final int em;

	/**
	 * Create a text field element
	 * 
	 * @param line the line of text from the {@link VtBuffer}
	 * @param metrics the font metrics
	 * @param colors the color resolver
	 */
	public TerminalTextFieldElement(VtLine line, FontMetrics metrics, AnsiColorResolver colors) {
		this.line = line;
		this.metrics = metrics;
		this.colors = colors;

		this.em = metrics.charWidth('M');
	}

	@Override
	public String getText() {
		StringBuilder sb = new StringBuilder();
		line.gatherText(sb, 0, line.length());
		return sb.toString();
	}

	@Override
	public int length() {
		return line.length();
	}

	/**
	 * Get the number of columns (total width, not just the used by the line)
	 * 
	 * @return the column count
	 */
	public int getNumCols() {
		return line.cols();
	}

	@Override
	public int getStringWidth() {
		// Assumes monospaced.
		return em * length();
	}

	@Override
	public int getHeightAbove() {
		return metrics.getMaxAscent() + metrics.getLeading();
	}

	@Override
	public int getHeightBelow() {
		return metrics.getMaxDescent();
	}

	@Override
	public char charAt(int index) {
		return line.getChar(index);
	}

	@Override
	public Color getColor(int charIndex) {
		return line.getCellAttrs(charIndex).resolveForeground(colors);
	}

	@Override
	public FieldElement substring(int start) {
		return this; // Used for clipping and wrapping. I don't care.
	}

	@Override
	public FieldElement substring(int start, int end) {
		return this; // Used for clipping and wrapping. I don't care.
	}

	@Override
	public FieldElement replaceAll(char[] targets, char replacement) {
		throw new UnsupportedOperationException("No wrapping");
	}

	@Override
	public int getMaxCharactersForWidth(int width) {
		// Assumes monospaced.
		return width / em;
	}

	@Override
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		return new RowColLocation(0, characterIndex);
	}

	@Override
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		if (dataRow == 0 && dataColumn >= 0 && dataColumn < length()) {
			return dataColumn;
		}
		return -1;
	}

	protected static class SaveTransform implements AutoCloseable {
		private final Graphics2D g;
		private final AffineTransform saved;

		public SaveTransform(Graphics g) {
			this.g = (Graphics2D) g;
			this.saved = this.g.getTransform();
		}

		@Override
		public void close() {
			this.g.setTransform(saved);
		}
	}

	protected void paintChars(JComponent c, Graphics g, int x, int y, VtAttributes attrs, int start,
			int end) {
		char[] ch = line.getCharBuffer();
		int descent = metrics.getDescent();
		int height = metrics.getHeight();
		int left = x + start * em;
		int width = em * (end - start);
		Font font = metrics.getFont();
		Color bg = attrs.resolveBackground(colors);
		if (bg != null) {
			g.setColor(bg);
			g.fillRect(left, descent - height, width, height);
		}
		g.setColor(attrs.resolveForeground(colors));
		// NB. I don't really intend to implement blinking.
		// TODO: AnsiFont mapping?
		if (attrs.intensity() == Intensity.DIM) {
			g.setFont(font.deriveFont(Font.PLAIN));
		}
		else {
			// Normal will use bold font, but standard color
			g.setFont(font.deriveFont(Font.BOLD));
		}
		if (!attrs.hidden()) {
			switch (attrs.underline()) {
				case DOUBLE:
					g.fillRect(left, descent - UNDERLINE_HEIGHT * 3, width, UNDERLINE_HEIGHT);
					// Yes, fall through
				case SINGLE:
					g.fillRect(left, descent - UNDERLINE_HEIGHT, width, UNDERLINE_HEIGHT);
				case NONE:
			}

			for (int i = start; i < end; i++) {
				/**
				 * HACK: The default monospaced font selected by Java may not have glyphs for the
				 * box-drawing characters, so it may choose glyphs from a different font.
				 * Alternatively, the default monospaced font's box-drawing glyphs are not, in fact,
				 * monospaced. This is not acceptable. To deal with that, when we find a glyph whose
				 * width does not match, we'll scale it horizontally so that it does.
				 */
				int chW = metrics.charWidth(ch[i]);
				if (chW != em) {
					try (SaveTransform st = new SaveTransform(g)) {
						st.g.translate(x + em * i, 0);
						st.g.scale((double) em / chW, 1.0);
						st.g.drawChars(ch, i, 1, 0, 0);
					}
				}
				else {
					g.drawChars(ch, i, 1, x + em * i, 0);
				}
			}
			if (attrs.strikeThrough()) {
				g.fillRect(left, height * 2 / 3, width, UNDERLINE_HEIGHT);
			}
		}
		// TODO: What is proportionalSpacing?
	}

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		if (!(g instanceof Graphics2D g2)) {
			line.forEachRun(
				(attrs, start, end) -> paintChars(c, g, x, y, attrs, start, end));
			return;
		}
		Object aaHint = c.getClientProperty(RenderingHints.KEY_TEXT_ANTIALIASING);
		Object lcdHint = c.getClientProperty(RenderingHints.KEY_TEXT_LCD_CONTRAST);
		Object aaOld =
			aaHint == null ? null : g2.getRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING);
		Object lcdOld =
			lcdHint == null ? null : g2.getRenderingHint(RenderingHints.KEY_TEXT_LCD_CONTRAST);
		if (aaOld == aaHint) {
			aaHint = null;
		}
		if (lcdOld == lcdHint) {
			lcdHint = null;
		}
		try {
			if (aaHint != null) {
				g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, aaHint);
			}
			if (lcdHint != null) {
				g2.setRenderingHint(RenderingHints.KEY_TEXT_LCD_CONTRAST, lcdHint);
			}
			line.forEachRun(
				(attrs, start, end) -> paintChars(c, g, x, y, attrs, start, end));
		}
		finally {
			if (aaHint != null) {
				g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, aaOld);
			}
			if (lcdHint != null) {
				g2.setRenderingHint(RenderingHints.KEY_TEXT_LCD_CONTRAST, lcdOld);
			}
		}
	}

	@Override
	public FieldElement getFieldElement(int column) {
		return this;
	}
}
