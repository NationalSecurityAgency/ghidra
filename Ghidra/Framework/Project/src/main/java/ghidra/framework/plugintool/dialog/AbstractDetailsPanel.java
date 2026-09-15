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
import javax.swing.text.View;

import docking.widgets.label.GDHtmlLabel;
import generic.theme.*;

/**
 * Abstract class that defines a panel for displaying name/value pairs with html-formatting.
 */
public abstract class AbstractDetailsPanel extends JPanel {

	protected static final String FONT_DEFAULT = "font.plugin.details.panel.default";
	protected static final String FONT_MONOSPACED = "font.plugin.details.panel.monospaced";

	// based on the default font size
	private static final int PREFERRED_WIDTH = 900;
	private static final int LEFT_COLUMN_WIDTH = 150;
	private static final int MIN_WIDTH = 700;

	// Font attributes for the title of each row.
	protected static GAttributes titleAttrs;

	protected JLabel textLabel;
	protected JScrollPane sp;

	private ThemeListener themeListener = e -> {
		updateFieldAttributes();
	};

	protected AbstractDetailsPanel() {
		createFieldAttributes();
		Gui.addThemeListener(themeListener);
	}

	private void updateFieldAttributes() {
		createFieldAttributes();
		refresh();
		repaint();
	}

	/**
	 * Sets attributes for the different pieces of information being displayed in this
	 * panel.
	 */
	protected abstract void createFieldAttributes();

	protected abstract void refresh();

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

				// Overridden to force word-wrapping by limiting the preferred size of the label.
				// Specifically, long descriptions will get word-wrapped by the html document when
				// the text is longer than the preferred width.
				Dimension size = super.getPreferredSize();
				int availableRightWidth = AbstractDetailsPanel.this.getWidth() - LEFT_COLUMN_WIDTH;
				size.width = Math.max(MIN_WIDTH, availableRightWidth);

				View v = (View) getClientProperty("html");
				if (v == null) {
					return size;
				}

				// We may have html wider than the chosen width that cannot wrap due to not having
				// any whitespace (e.g., a file path).  In that case, the display will run past the
				// right edge of the screen without showing a horizontal scrollbar.  We can force 
				// the scroll bar to appear by making the chosen width be the html minimum width
				// (which is the width needed to render an unbreakable line of text).
				Insets i = getInsets();
				int availableWidth = size.width - (i.left + i.right);
				int htmlw = (int) v.getMinimumSpan(View.X_AXIS);
				boolean isClipped = htmlw > availableWidth;
				if (isClipped) {
					// the minimum html is wider than the current preferred width
					size.width = htmlw;
				}

				return size;
			}
		};

		textLabel.setVerticalAlignment(SwingConstants.TOP);
		textLabel.setOpaque(true);
		textLabel.setBackground(new GColor("color.bg.panel.details"));
		sp = new JScrollPane(textLabel);
		sp.getVerticalScrollBar().setUnitIncrement(10);
		sp.setPreferredSize(new Dimension(PREFERRED_WIDTH, 300));
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
		insertRowTitle(buffer, rowName, titleAttrs);
	}

	protected void insertRowTitle(StringBuilder buffer, String rowName, GAttributes attributes) {
		buffer.append("<TR>");
		buffer.append("<TD VALIGN=\"TOP\" NOWRAP>");
		insertHTMLLine(buffer, rowName + ":", attributes);
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
	protected void insertRowValue(StringBuilder buffer, String value, GAttributes attributes) {
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
	protected void insertHTMLString(StringBuilder buffer, String string, GAttributes attributes) {

		if (string == null) {
			return;
		}

		buffer.append(attributes.toStyledHtml(string));
	}

	/**
	 * Inserts a single line of html into a {@link StringBuffer}, with the given attributes.
	 * @param buffer the string buffer
	 * @param string the string to insert
	 * @param attributes the attributes to apply
	 */
	protected void insertHTMLLine(StringBuilder buffer, String string, GAttributes attributes) {
		if (string == null) {
			return;
		}

		insertHTMLString(buffer, string, attributes);

		// row padding - newline space
		buffer.append(BR);
	}
}
