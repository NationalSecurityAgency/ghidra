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
package docking.widgets;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkEvent.EventType;
import javax.swing.event.HyperlinkListener;
import javax.swing.text.DefaultCaret;

import org.apache.commons.lang3.StringUtils;

import docking.DockingUtils;
import docking.actions.KeyBindingUtils;
import generic.theme.GColor;
import ghidra.docking.util.LookAndFeelUtils;
import utility.function.Callback;

/**
 * A component that acts like a label, but adds the ability to render HTML links with a client
 * callback for when the link is activated.  Links can be activated by mouse clicking or or by 
 * focusing the link and then pressing Enter or Space.
 * <p>
 * Users can make one simple text link by calling {@link #addLink(String, Callback)}.  
 * Alternatively, users can mix plain text and links by using both {@link #addText(String)} and 
 * {@link #addLink(String, Callback)}.
 */
public class GHyperlinkComponent extends JPanel {

	public GHyperlinkComponent() {
		setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));
	}

	/**
	 * Adds text to this widget that will be displayed as plain text.
	 * @param text the text
	 */
	public void addText(String text) {
		JTextPane textPane = new FixedSizeTextPane(text, Callback.dummy());
		textPane.setFocusable(false);
		add(textPane);
		String updated = text;

		// the text pane will trim leading spaces; keep the client spaces
		int leadingSpaces = text.indexOf(text.trim());
		if (leadingSpaces != 0) {
			updated = StringUtils.repeat("&nbsp;", leadingSpaces) + text.substring(leadingSpaces);
		}

		setText(textPane, updated);

		// clear the description to avoid excess text reading
		textPane.getAccessibleContext().setAccessibleDescription("");
	}

	/**
	 * Uses the given text to create a link the user can click.
	 * @param text the text
	 * @param linkActivatedCallback the callback that will be called when the link is activated
	 */
	public void addLink(String text, Callback linkActivatedCallback) {
		JTextPane textPane = new FixedSizeTextPane(text, linkActivatedCallback);
		add(textPane);
		setText(textPane, "<a href=\"stub\">" + text + "</a>");
		textPane.getAccessibleContext().setAccessibleDescription("Clickable link");
	}

	private void setText(JTextPane textPane, String text) {

		String html = "<html><nobr>" + text;
		textPane.setText(html);

		//
		// Hack Alert!: We've run into scenarios where changing the text of this component 
		//              causes the entire component to paint no text.  For some reason, the 
		//              component will work correctly if it has a non-zero size border installed.
		//              Also, if we call getPreferredSize(), then it will work.
		//
		textPane.getPreferredSize();
		getPreferredSize();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A text pane that can render links.
	 */
	private class FixedSizeTextPane extends JTextPane {

		private String rawText;

		FixedSizeTextPane(String rawText, Callback linkActivatedCallback) {
			this.rawText = rawText;

			setContentType("text/html");
			setEditable(false);
			setCaret(new NonScrollingCaret());
			DockingUtils.setTransparent(this);

			// Create a border the same dimensions as the one we will later switch to when focused.
			// This keeps the UI from moving.
			Border defaultBorder = BorderFactory.createEmptyBorder(1, 1, 1, 1);
			setBorder(defaultBorder);

			// change the border of the link so users can see when it is focused
			Color FOCUS_COLOR = new GColor("color.border.button.focused");
			Border FOCUSED_BORDER = BorderFactory.createLineBorder(FOCUS_COLOR);
			addFocusListener(new FocusListener() {

				@Override
				public void focusLost(FocusEvent e) {
					setBorder(defaultBorder);
				}

				@Override
				public void focusGained(FocusEvent e) {
					setBorder(FOCUSED_BORDER);
				}
			});

			addHyperlinkListener(new HyperlinkListener() {
				@Override
				public void hyperlinkUpdate(HyperlinkEvent e) {
					EventType type = e.getEventType();
					if (type == EventType.ACTIVATED) {
						linkActivatedCallback.call();
					}
				}
			});

			addActivationKeyBinding(linkActivatedCallback);
		}

		private void addActivationKeyBinding(Callback linkActivatedCallback) {
			// Space and Enter typically activate buttons
			KeyStroke enterKs = KeyBindingUtils.parseKeyStroke("Enter");
			KeyStroke spaceKs = KeyBindingUtils.parseKeyStroke("Space");
			Action action = new AbstractAction("Activate Link") {
				@Override
				public void actionPerformed(ActionEvent e) {
					linkActivatedCallback.call();
				}
			};
			KeyBindingUtils.registerAction(this, enterKs, action, JComponent.WHEN_FOCUSED);
			KeyBindingUtils.registerAction(this, spaceKs, action, JComponent.WHEN_FOCUSED);
		}

		@Override
		public Dimension getMaximumSize() {
			return getBestSize();
		}

		@Override
		public Dimension getMinimumSize() {
			return getBestSize();
		}

		@Override
		public Dimension getPreferredSize() {
			return getBestSize();
		}

		private Dimension getBestSize() {
			int width = getBestWidth();
			Dimension d = super.getPreferredSize();
			d.width = Math.min(width, d.width);
			return d;
		}

		private int getBestWidth() {
			Font font = getFont();
			FontMetrics fm = getFontMetrics(font);
			int stringWidth = fm.stringWidth(rawText);

			// 
			// Make a width that is at least as big as the width of the text.  Use the preferred
			// width, as that is more accurate.  Do not do this for the FlatLaf UIs because their
			// preferred width includes a minimum width which will be too large for a small number
			// of characters.
			//
			Dimension preferred = super.getPreferredSize();
			int width = stringWidth;
			if (!LookAndFeelUtils.isUsingFlatUI()) {
				width = Math.max(stringWidth, preferred.width);
			}

			// a fudge factor to compensate for text calculation rounding, based on a 12pt font size
			Insets insets = getInsets();
			width += insets.left + insets.right;
			return width;
		}
	}

	private class NonScrollingCaret extends DefaultCaret {

		private NonScrollingCaret() {
			setVisible(false);
		}

		@Override
		protected void adjustVisibility(Rectangle nloc) {
			// we don't want to adjust any visibility (no scrolling for this comp)
		}
	}
}
