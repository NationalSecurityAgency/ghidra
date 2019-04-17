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
package ghidra.framework.plugintool.dialog;

import java.awt.*;
import java.util.StringTokenizer;

import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import org.apache.commons.lang3.StringUtils;

/**
 * Abstract class that defines a panel for displaying name/value pairs with html-formatting. 
 * <p>
 * This is used with the {@link ExtensionDetailsPanel} and the {@link PluginDetailsPanel}
 */
public abstract class AbstractDetailsPanel extends JPanel {

	protected static final int LEFT_COLUMN_WIDTH = 150;
	protected static final int RIGHT_MARGIN = 30;

	// Font attributes for the title of each row.
	protected static SimpleAttributeSet titleAttrSet;

	protected JLabel textLabel;
	protected Font defaultFont;
	protected JScrollPane sp;

	/**
	 * Sets attributes for the different pieces of information being displayed in this 
	 * panel.
	 */
	protected abstract void createFieldAttributes();

	/**
	 * Returns a new {@link SimpleAttributeSet} with all attributes set by the caller. 
	 * 
	 * @param fontFamily the font to use 
	 * @param fontSize the font size
	 * @param bold if true, render text bold
	 * @param color the foreground text color
	 * @return a new attribute set
	 */
	protected SimpleAttributeSet createAttributeSet(String fontFamily, int fontSize, boolean bold,
			Color color) {

		SimpleAttributeSet attrSet = new SimpleAttributeSet();
		attrSet.addAttribute(StyleConstants.FontFamily, fontFamily);
		attrSet.addAttribute(StyleConstants.FontSize, new Integer(fontSize));
		attrSet.addAttribute(StyleConstants.Bold, bold);
		attrSet.addAttribute(StyleConstants.Foreground, color);

		return attrSet;
	}

	/**
	 * Returns a new {@link SimpleAttributeSet} with the following default attributes set:
	 * <ul>
	 * <li>FontFamily: "Tahoma"</li>
	 * <li>FontSize: 11</li>
	 * <li>Bold: True</li>
	 * </ul>
	 * 
	 * @param color the foreground text color
	 * @return a new attribute set
	 */
	protected SimpleAttributeSet createAttributeSet(Color color) {

		SimpleAttributeSet attrSet = new SimpleAttributeSet();
		attrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		attrSet.addAttribute(StyleConstants.FontSize, new Integer(11));
		attrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		attrSet.addAttribute(StyleConstants.Foreground, color);

		return attrSet;
	}

	/**
	 * Clears the text in the details pane.
	 */
	protected void clear() {
		textLabel.setText("");
	}

	/**
	 * Creates the main dialog components.
	 */
	protected void createMainPanel() {
		setLayout(new BorderLayout());
		textLabel = new JLabel("");
		textLabel.setVerticalAlignment(SwingConstants.TOP);
		textLabel.setOpaque(true);
		textLabel.setBackground(Color.WHITE);
		sp = new JScrollPane(textLabel);
		sp.getVerticalScrollBar().setUnitIncrement(10);
		sp.setPreferredSize(new Dimension(700, 200));
		add(sp, BorderLayout.CENTER);
		defaultFont = new Font("Tahoma", Font.BOLD, 12);
	}

	/**
	 * Inserts an html-formatted string into the given buffer. This is meant to be used
	 * for inserting the name of each row in the description text.
	 * 
	 * @param buffer the string buffer to add to
	 * @param rowName the name of the row to add
	 */
	protected void insertRowTitle(StringBuilder buffer, String rowName) {
		buffer.append("<TR>");
		buffer.append("<TD VALIGN=\"TOP\">");
		insertHTMLLine(rowName + ":", titleAttrSet, buffer);
		buffer.append("</TD>");
	}

	/**
	 * Inserts an html-formatted string into the given buffer. This is meant to be used
	 * for inserting the value of each row in the description text.
	 * 
	 * @param buffer the string buffer to add to
	 * @param value the text to add
	 * @param attrSet the structure containing formatting information 
	 */
	protected void insertRowValue(StringBuilder buffer, String value, SimpleAttributeSet attrSet) {
		buffer.append("<TD VALIGN=\"TOP\">");
		insertHTMLLine(value, attrSet, buffer);
		buffer.append("</TD>");
		buffer.append("</TR>");
	}

	/**
	 * Adds text to a string buffer as an html-formatted string, adding formatting information
	 * as specified.
	 * 
	 * @param string the string to add
	 * @param attributeSet the formatting instructions
	 * @param buffer the string buffer to add to
	 */
	protected void insertHTMLString(String string, SimpleAttributeSet attributeSet,
			StringBuilder buffer) {
		if (string == null) {
			return;
		}
		buffer.append("<FONT COLOR=\"#");

		Color foregroundColor = (Color) attributeSet.getAttribute(StyleConstants.Foreground);
		buffer.append(createColorString(foregroundColor));

		buffer.append("\" FACE=\"");

		buffer.append(attributeSet.getAttribute(StyleConstants.FontFamily).toString());

		buffer.append("\">");

		Boolean isBold = (Boolean) attributeSet.getAttribute(StyleConstants.Bold);
		isBold = (isBold == null) ? Boolean.FALSE : isBold;
		if (isBold) {
			buffer.append("<B>");
		}

		buffer.append(string);

		if (isBold) {
			buffer.append("</B>");
		}

		buffer.append("</FONT>");
	}

	/**
	 * Inserts a single line of html into a {@link StringBuffer}, with the given attributes.
	 * 
	 * @param string the string to insert
	 * @param attributeSet the attributes to apply
	 * @param buffer the string buffer
	 */
	protected void insertHTMLLine(String string, SimpleAttributeSet attributeSet,
			StringBuilder buffer) {
		if (string == null) {
			return;
		}

		insertHTMLString(string, attributeSet, buffer);

		// row padding - newline space
		buffer.append("<BR>");
	}

	/**
	 * Returns a stringified version of the {@link Color} provided; eg: "8c0000"
	 * 
	 * @param color the color to parse
	 * @return string version of the color
	 */
	protected String createColorString(Color color) {

		int red = color.getRed();
		int green = color.getGreen();
		int blue = color.getBlue();

		return StringUtils.leftPad(Integer.toHexString(red), 2, "0") +
			StringUtils.leftPad(Integer.toHexString(green), 2, "0") +
			StringUtils.leftPad(Integer.toHexString(blue), 2, "0");
	}

	/**
	 * Returns a string with line breaks at the boundary of the window it's being displayed in. 
	 * Without this the description would just run on in one long line.
	 * 
	 * @param descr the string to format
	 * @return the formatted string
	 */
	protected String formatDescription(String descr) {
		if (descr == null) {
			return "";
		}
		int maxWidth = getMaxStringWidth();
		int remainingWidth = maxWidth;
		FontMetrics fm = textLabel.getFontMetrics(defaultFont);
		int spaceSize = fm.charWidth(' ');
		StringBuffer sb = new StringBuffer();
		StringTokenizer st = new StringTokenizer(descr, " ");
		while (st.hasMoreTokens()) {
			String str = st.nextToken();
			if (str.endsWith(".")) {
				str = str + "  ";
			}
			int strWidth = fm.stringWidth(str);
			if (strWidth + spaceSize <= remainingWidth) {
				sb.append(" ");
				sb.append(str);
				remainingWidth -= strWidth + spaceSize;
			}
			else {
				sb.append("<BR>");
				sb.append(str + " ");
				remainingWidth = maxWidth - strWidth;
			}
		}
		return sb.toString();
	}

	/**
	 * Returns the maximum size that one line of text can be when formatting the description.
	 * 
	 * @return the number of characters in the string
	 */
	protected int getMaxStringWidth() {

		int width = textLabel.getWidth();
		if (width == 0) {
			width = 700;
		}
		width -= LEFT_COLUMN_WIDTH + RIGHT_MARGIN; // allow for tabs and right margin
		return width;
	}
}
