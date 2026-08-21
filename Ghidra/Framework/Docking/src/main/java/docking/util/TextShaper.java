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
import java.awt.font.*;
import java.text.AttributedCharacterIterator;
import java.text.AttributedString;
import java.util.*;
import java.util.List;

/**
 * A class that will layout text into lines based on the given display size.   This class requires
 * the graphics context in order to correctly size the text.
 */
public class TextShaper {

	private List<TextShaperLine> lines = new ArrayList<>();
	private Dimension textSize = new Dimension(0, 0);

	private String originalText;
	private String clippedText;
	private Dimension displaySize = new Dimension(0, 0);
	private Graphics2D g2d;

	/**
	 * Creates a text shaper with the given text, display size and graphics context.
	 * @param text the text
	 * @param displaySize the size
	 * @param g2d the graphics
	 */
	public TextShaper(String text, Dimension displaySize, Graphics2D g2d) {
		this.originalText = text;
		this.clippedText = text;
		this.displaySize = displaySize;
		this.g2d = g2d;

		// Trim blank lines we don't want
		// Drop all blank lines before and after the non-blank lines.  It seems pointless to paint
		// these blank lines.   We can change this if there is a valid reason to do so.
		text = removeNewlinesAroundText(text);
		text = text.replaceAll("\t", "    ");

		init(text);
	}

	private String removeNewlinesAroundText(String s) {
		int first = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c != '\n') {
				first = i;
				break;
			}
		}

		s = s.substring(first);

		int last = s.length() - 1;
		for (int i = last; i >= 0; i--) {
			char c = s.charAt(i);
			if (c != '\n') {
				last = i;
				break;
			}
		}
		return s.substring(0, last + 1);
	}

	private void init(String currentText) {

		if (displaySize.width <= 0) {
			return;
		}

		// create the attributed string needed by the LineBreakMeasurer, setting the font over all
		// of the text
		AttributedString as = new AttributedString(currentText);
		int length = currentText.length();
		Font font = g2d.getFont();
		as.addAttribute(TextAttribute.FONT, font, 0, length);

		// create the LineBreakMeasuerer we will use to split the text at the given width, using the
		// rendering environment to get accurate size information
		AttributedCharacterIterator paragraph = as.getIterator();
		FontRenderContext frc = g2d.getFontRenderContext();
		LineBreakMeasurer measurer = new LineBreakMeasurer(paragraph, frc);
		measurer.setPosition(paragraph.getBeginIndex());

		int totalHeight = 0;
		int largestWidth = 0;
		int position = 0;
		while ((position = measurer.getPosition()) < paragraph.getEndIndex()) {

			TextShaperLine line = createLine(currentText, measurer);

			// Look ahead to see if the new row we created will fit within the height restrictions.
			// If not, we must clip the text and do this work again.
			float rowHeight = line.getHeight();
			totalHeight += rowHeight;
			if (totalHeight > displaySize.height) {

				// Truncate the original text and try again with the smaller text that we now know 
				// will fit, adding an ellipsis.
				int lineCount = lines.size();
				lines.clear();

				if (lineCount == 0) {
					return; // no room for a single line of text
				}

				// clip the text of the and recalculate
				int end = position;
				int newEnd = end - 3; // 3 for '...' 
				clippedText = currentText.substring(0, newEnd) + "...";

				init(clippedText);
				return;
			}

			lines.add(line);

			largestWidth = Math.max(largestWidth, (int) line.getWidth());

		}

		textSize = new Dimension(largestWidth, totalHeight);
	}

	private TextShaperLine createLine(String currentText, LineBreakMeasurer measurer) {

		// nextOffset() finds the end of the text that fits into the max width
		int position = measurer.getPosition();
		int wrappingWidth = displaySize.width;
		int nextEnd = measurer.nextOffset(wrappingWidth);

		// special case: look for newlines in the current line and split the text on that 
		// newline instead so that user-requested newlines are painted
		int limit = updateLimitForNewline(currentText, position, nextEnd);

		TextShaperLine line = null;
		if (limit == 0) {
			// A limit of 0 implies the first character of the text is a newline.  Add a full blank
			// line to handle that case.  This can happen with consecutive newlines or if a line
			// happened to break with a leading newline.
			Font font = g2d.getFont();
			FontRenderContext frc = g2d.getFontRenderContext();
			LineMetrics lm = font.getLineMetrics("W", frc);
			line = new BlankLine(lm.getHeight());

			// advance the measurer to move past the single newline
			measurer.nextLayout(wrappingWidth, position + 1, false);
		}
		else {
			// create a layout with the given limit (either restricted by width or by a newline)
			TextLayout layout = measurer.nextLayout(wrappingWidth, position + limit, false);
			int nextPosition = measurer.getPosition();
			String lineText = currentText.substring(position, nextPosition);
			line = new TextLayoutLine(lineText, layout);
		}

		// If we limited the current line to break on the newline, then move past that newline so it
		// is not in the next line we process.  Since we have broken the line already, we do not 
		// need that newline character.
		movePastTrailingNewline(currentText, measurer);

		return line;
	}

	private int updateLimitForNewline(String text, int position, int limit) {
		int newline = text.indexOf('\n', position);
		if (newline != -1) {
			if (newline >= position && newline < limit) {
				// newline will be in the current line; break on the newline
				return newline - position;
			}
		}
		return limit;
	}

	private void movePastTrailingNewline(String text, LineBreakMeasurer measurer) {
		int newPosition = measurer.getPosition();
		if (newPosition < text.length()) {
			char nextChar = text.charAt(newPosition);
			if (nextChar == '\n') {
				measurer.setPosition(newPosition + 1);
			}
		}
	}

	/**
	 * Returns the bounds of the wrapped text of this class
	 * @return the bounds of the wrapped text of this class
	 */
	public Dimension getTextSize() {
		return textSize;
	}

	/**
	 * Returns true if the text is too large to fit in the original display size
	 * @return true if the text is too large to fit in the original display size
	 */
	public boolean isClipped() {
		return !Objects.equals(originalText, clippedText);
	}

	public List<TextShaperLine> getLines() {
		return Collections.unmodifiableList(lines);
	}

	/**
	 * Renders the wrapped text into the graphics used to create this class.
	 * @param g the graphics into which the text should be painted.
	 */
	public void drawText(Graphics2D g) {
		float dy = 0;
		for (TextShaperLine line : lines) {
			float y = dy + line.getAscent(); // move the drawing down to the start of the next line
			line.draw(g, 0, y);
			dy += line.getHeight();
		}
	}

	abstract class TextShaperLine {
		abstract float getHeight();

		abstract float getWidth();

		abstract float getAscent();

		abstract String getText();

		abstract boolean isBlank();

		abstract void draw(Graphics2D g, float x, float y);
	}

	private class TextLayoutLine extends TextShaperLine {
		private String lineText;
		private TextLayout layout;

		TextLayoutLine(String text, TextLayout layout) {
			this.lineText = text;
			this.layout = layout;
		}

		@Override
		float getAscent() {
			return layout.getAscent();
		}

		@Override
		float getHeight() {
			return (int) (layout.getAscent() + layout.getDescent() + layout.getLeading());
		}

		@Override
		float getWidth() {
			return (float) layout.getBounds().getWidth();
		}

		@Override
		String getText() {
			return lineText;
		}

		@Override
		void draw(Graphics2D g, float x, float y) {
			layout.draw(g, x, y);
		}

		@Override
		boolean isBlank() {
			return false;
		}

		@Override
		public String toString() {
			return lineText;
		}
	}

	private class BlankLine extends TextShaperLine {

		private float lineHeight;

		BlankLine(float lineHeight) {
			this.lineHeight = lineHeight;
		}

		@Override
		float getAscent() {
			return 0; // the value shouldn't matter, since we don't actually draw anything
		}

		@Override
		float getHeight() {
			return lineHeight;
		}

		@Override
		float getWidth() {
			return 0;
		}

		@Override
		boolean isBlank() {
			return true;
		}

		@Override
		String getText() {
			return "\n";
		}

		@Override
		void draw(Graphics2D g, float x, float y) {
			// nothing to draw
		}

		@Override
		public String toString() {
			return "Blank Line";
		}
	}

}
