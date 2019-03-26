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
package docking.widgets.fieldpanel.field;

import java.awt.*;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.util.GraphicsUtils;

/**
 * An object that wraps a string and provides data that describes how to render
 * that string.  
 * <p>
 * This class was created as a place to house attributes of rendering that 
 * are not described by Java's Font object, like underlining.
 * 
 * 
 */
public class AttributedString {

	private static final int UNDERLINE_HEIGHT = 1;

	private boolean isUnderlined;
	private Color underlineColor;

	private String text;
	private Icon icon;
	private FontMetrics fontMetrics;
	private Color textColor;

	int textWidth = -1;

	AttributedString() {
		// for the factory methods of this class
	}

	/**
	 * Creates an attributed string with the given text, color and metrics with
	 * no other attributes, like highlighting or underlining.
	 * 
	 * @param text The text that this class describes.
	 * @param textColor The color to paint the text.
	 * @param fontMetrics The font metrics used to draw the text.
	 */
	public AttributedString(String text, Color textColor, FontMetrics fontMetrics) {
		this(text, textColor, fontMetrics, false, null);
	}

	/**
	 * Creates an attributed string with the given text, color and metrics with
	 * other attributes, like highlighting and underlining.
	 * 
	 * @param text The text that this class describes.
	 * @param textColor The color to paint the text.
	 * @param fontMetrics The font metrics used to draw the text.
	 * @param underline True if <code>text</code> should be underlined.
	 * @param underlineColor the color to use for underlining.
	 */
	public AttributedString(String text, Color textColor, FontMetrics fontMetrics,
			boolean underline, Color underlineColor) {
		this(null, text, textColor, fontMetrics, underline, underlineColor);
	}

	/**
	 * Creates an attributed string with the given text, color, icon and metrics with
	 * other attributes, like highlighting and underlining.
	 * 
	 * @param icon icon image to be displayed to the left of the text
	 * @param text The text that this class describes.
	 * @param textColor The color to paint the text.
	 * @param fontMetrics The font metrics used to draw the text.
	 * @param underline True if <code>text</code> should be underlined.
	 * @param underlineColor the color to use for underlining.
	 */
	public AttributedString(Icon icon, String text, Color textColor, FontMetrics fontMetrics,
			boolean underline, Color underlineColor) {

		if (underline && underlineColor == null) {
			throw new NullPointerException("underline color cannot be null when underlining.");
		}
		this.icon = icon;
		this.text = text;
		this.fontMetrics = fontMetrics;
		this.textColor = textColor;
		this.isUnderlined = underline;
		this.underlineColor = underlineColor;
	}

	public String getText() {
		return text;
	}

	public Icon getIcon() {
		return icon;
	}

	public int length() {
		return getText().length();
	}

	private int getIconWidth() {
		return (icon == null) ? 0 : icon.getIconWidth();
	}

//==================================================================================================
// font metrics methods
//==================================================================================================

	public int getStringWidth() {
		if (textWidth == -1) {
			textWidth = getIconWidth() + fontMetrics.stringWidth(text);
		}
		return textWidth;
	}

	public int getHeightAbove() {
		return fontMetrics.getMaxAscent() + fontMetrics.getLeading();
	}

	public int getHeightBelow() {
		return fontMetrics.getMaxDescent() + UNDERLINE_HEIGHT;
	}

	public int getColumnPosition(int width) {
		int subWidth = getIconWidth();
		for (int i = 0; i < text.length(); i++) {
			subWidth += fontMetrics.charWidth(text.charAt(i));
			if (subWidth > width) {
				return i;
			}
		}
		return text.length();
	}

	public FontMetrics getFontMetrics(int charIndex) {
		return fontMetrics;
	}

	public Color getColor(int charIndex) {
		return textColor;
	}

	public AttributedString substring(int start) {
		AttributedString newString = deriveAttributedString(text.substring(start));
		if (start == 0) {
			// keep the icon on the string if it is at the beginning
			newString.icon = icon;
		}
		return newString;
	}

	public AttributedString substring(int start, int end) {
		if (start == 0 && end == text.length()) {
			return this;
		}

		AttributedString newString = deriveAttributedString(text.substring(start, end));
		if (start == 0) {
			// keep the icon on the string if it is at the beginning
			newString.icon = icon;
		}
		return newString;
	}

	public AttributedString replaceAll(char[] targets, char repacement) {
		StringBuffer buffer = new StringBuffer();
		int n = text.length();
		for (int i = 0; i < n; i++) {
			char c = text.charAt(i);
			if (contains(targets, c)) {
				buffer.append(repacement);
			}
			else {
				buffer.append(c);
			}
		}
		return deriveAttributedString(buffer.toString());
	}

	private boolean contains(char[] targets, char candidate) {
		for (char target : targets) {
			if (target == candidate) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String toString() {
		return getText();
	}

//==================================================================================================
// paint methods
//==================================================================================================

	public void paint(JComponent c, Graphics g, int x, int y) {
		if (icon != null) {
			icon.paintIcon(null, g, x, -fontMetrics.getHeight());
			x += icon.getIconWidth();
		}

		g.setFont(fontMetrics.getFont());
		if (isUnderlined) {
			g.setColor(underlineColor);

			int descent = fontMetrics.getDescent();
			g.fillRect(x, descent - UNDERLINE_HEIGHT, getStringWidth(), UNDERLINE_HEIGHT);
		}

		g.setColor(textColor);
		GraphicsUtils.drawString(c, g, text, x, 0);
	}

//==================================================================================================
// factory methods
//==================================================================================================

	public AttributedString deriveAttributedString(String newText) {
		AttributedString newString = new AttributedString();

		newString.text = newText;
		newString.fontMetrics = fontMetrics;
		newString.textColor = textColor;
		newString.isUnderlined = isUnderlined;
		newString.underlineColor = underlineColor;

		return newString;
	}
}
