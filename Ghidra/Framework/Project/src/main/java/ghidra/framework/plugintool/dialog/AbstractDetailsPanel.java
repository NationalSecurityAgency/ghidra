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

import static ghidra.util.HTMLUtilities.*;

import java.awt.*;

import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import docking.widgets.label.GDHtmlLabel;
import ghidra.util.HTMLUtilities;

/**
 * Abstract class that defines a panel for displaying name/value pairs with html-formatting. 
 * <p>
 * This is used with the {@link ExtensionDetailsPanel} and the {@link PluginDetailsPanel}
 */
public abstract class AbstractDetailsPanel extends JPanel {

	private static final int MIN_WIDTH = 700;
	protected static final int LEFT_COLUMN_WIDTH = 150;
	protected static final int RIGHT_MARGIN = 30;

	// Font attributes for the title of each row.
	protected static SimpleAttributeSet titleAttrSet;

	protected JLabel textLabel;
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
		attrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(fontSize));
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
		attrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
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
		textLabel = new GDHtmlLabel() {
			@Override
			public Dimension getPreferredSize() {

				// overridden to force word-wrapping by limiting the preferred size of the label
				Dimension mySize = super.getPreferredSize();
				int rightColumnWidth = AbstractDetailsPanel.this.getWidth() - LEFT_COLUMN_WIDTH;
				mySize.width = Math.max(MIN_WIDTH, rightColumnWidth);
				return mySize;
			}
		};

		textLabel.setVerticalAlignment(SwingConstants.TOP);
		textLabel.setOpaque(true);
		textLabel.setBackground(Color.WHITE);
		sp = new JScrollPane(textLabel);
		sp.getVerticalScrollBar().setUnitIncrement(10);
		sp.setPreferredSize(new Dimension(MIN_WIDTH, 200));
		add(sp, BorderLayout.CENTER);
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
		insertHTMLLine(buffer, rowName + ":", titleAttrSet);
		buffer.append("</TD>");
	}

	/**
	 * Inserts an html-formatted string into the given buffer. This is meant to be used
	 * for inserting the value of each row in the description text.
	 * 
	 * @param buffer the string buffer to add to
	 * @param value the text to add
	 * @param attributes the structure containing formatting information 
	 */
	protected void insertRowValue(StringBuilder buffer, String value,
			SimpleAttributeSet attributes) {
		buffer.append("<TD VALIGN=\"TOP\" WIDTH=\"80%\">");
		insertHTMLLine(buffer, value, attributes);
		buffer.append("</TD>");
		buffer.append("</TR>");
	}

	/**
	 * Adds text to a string buffer as an html-formatted string, adding formatting information
	 * as specified.
	 * @param buffer the string buffer to add to
	 * @param string the string to add
	 * @param attributes the formatting instructions
	 */
	protected void insertHTMLString(StringBuilder buffer, String string,
			SimpleAttributeSet attributes) {

		if (string == null) {
			return;
		}

		buffer.append("<FONT COLOR=\"");

		Color foregroundColor = (Color) attributes.getAttribute(StyleConstants.Foreground);
		buffer.append(HTMLUtilities.toHexString(foregroundColor));

		buffer.append("\" FACE=\"");
		buffer.append(attributes.getAttribute(StyleConstants.FontFamily).toString());

		buffer.append("\">");

		Boolean isBold = (Boolean) attributes.getAttribute(StyleConstants.Bold);
		isBold = (isBold == null) ? Boolean.FALSE : isBold;
		String text = HTMLUtilities.escapeHTML(string);
		if (isBold) {
			text = HTMLUtilities.bold(text);
		}

		buffer.append(text);

		buffer.append("</FONT>");
	}

	/**
	 * Inserts a single line of html into a {@link StringBuffer}, with the given attributes.
	 * @param buffer the string buffer
	 * @param string the string to insert
	 * @param attributes the attributes to apply
	 */
	protected void insertHTMLLine(StringBuilder buffer, String string,
			SimpleAttributeSet attributes) {
		if (string == null) {
			return;
		}

		insertHTMLString(buffer, string, attributes);

		// row padding - newline space
		buffer.append(BR);
	}
}
