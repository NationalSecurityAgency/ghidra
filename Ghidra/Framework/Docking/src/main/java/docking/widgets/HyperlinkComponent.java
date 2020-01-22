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

import java.awt.BorderLayout;
import java.awt.Rectangle;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.util.*;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.text.DefaultCaret;

import docking.DockingUtils;

/**
 * A component that acts like a label, but adds the ability to render HTML anchors and the 
 * ability for clients to add anchor handlers.
 * <p>
 * When given HTML content (a String that 
 * starts with &lt;HTML&gt;) and anchor tags (&lt;a href="callback_name"&gt;a hyper link&lt;a&gt;),
 * this component will display the hyperlinks properly and will notify any registered 
 * listeners ({@link #addHyperlinkListener(String, HyperlinkListener)} that the user has clicked the link
 * by the given name. 
 */
public class HyperlinkComponent extends JPanel {

	private JTextPane textPane;
	private HashMap<String, List<HyperlinkListener>> hyperlinkListeners;

	public HyperlinkComponent(String htmlTextWithHyperlinks) {
		setLayout(new BorderLayout());

		textPane = new JTextPane();
		textPane.setContentType("text/html");
		textPane.setEditable(false);

		DockingUtils.setTransparent(textPane);

		textPane.setCaret(new NonScrollingCaret());

		textPane.addHyperlinkListener(new HyperlinkListener() {
			@Override
			public void hyperlinkUpdate(HyperlinkEvent e) {
				String anchorText = e.getDescription();
				List<HyperlinkListener> list = hyperlinkListeners.get(anchorText);
				if (list == null) {
					return;
				}
				for (HyperlinkListener hyperlinkListener : list) {
					hyperlinkListener.hyperlinkUpdate(e);
				}
			}
		});

		textPane.setBorder(BorderFactory.createEmptyBorder());
		textPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);

		setText(htmlTextWithHyperlinks);

		add(textPane, BorderLayout.NORTH);

		// Hack alert! For some reason this text pane will sometimes be 
		// initialized with a height of zero. This prevents anything from 
		// being rendered. To avoid this, just set the preferred size to 
		// the value of the parent.
		// Note: This is related to the comment in setText() regarding the
		// getPreferredSize() calls.
		textPane.setPreferredSize(getPreferredSize());

		hyperlinkListeners = new HashMap<String, List<HyperlinkListener>>();
	}

	/**
	 * Add a listener that will be called whenever hyperlink updates happen (hover, activate, etc).
	 * 
	 * @param anchorName The value in the <code>href</code> attribute of the anchor tag.
	 * @param listener The listener to be called when the anchor(s) with a matching <code>href</code> is
	 *        manipulated by the user.
	 */
	public void addHyperlinkListener(String anchorName, HyperlinkListener listener) {
		List<HyperlinkListener> list = hyperlinkListeners.get(anchorName);
		if (list == null) {
			list = new ArrayList<HyperlinkListener>();
			hyperlinkListeners.put(anchorName, list);
		}

		list.add(listener);
	}

	public void removeHyperlinkListener(String anchorName, HyperlinkListener listener) {
		List<HyperlinkListener> list = hyperlinkListeners.get(anchorName);
		if (list == null) {
			return;
		}

		list.remove(listener);
	}

	public void setText(final String text) {
		textPane.setText(text);

		//
		// Hack Alert!: I've run into scenarios where changing the text of this component 
		//              causes the entire component to paint no text.  For some reason, the 
		//              component will work correctly if it has a non-zero size border installed.
		//              Also, if we call getPreferredSize(), then it will work.
		//
		textPane.getPreferredSize();
		getPreferredSize();
	}

	public String getText() {
		return textPane.getText();
	}

	@Override
	public synchronized void addMouseListener(MouseListener l) {
		textPane.addMouseListener(l);
	}

	@Override
	public synchronized void removeMouseListener(MouseListener l) {
		textPane.removeMouseListener(l);
	}

	@Override
	public synchronized void addMouseMotionListener(MouseMotionListener l) {
		textPane.addMouseMotionListener(l);
	}

	@Override
	public synchronized void removeMouseMotionListener(MouseMotionListener l) {
		textPane.removeMouseMotionListener(l);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

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
