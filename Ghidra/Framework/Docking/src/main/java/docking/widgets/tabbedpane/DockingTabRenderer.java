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
package docking.widgets.tabbedpane;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import resources.ResourceManager;

/**
 * A widget that can be used to render an icon, title and close button for JTabbedPane.  You would 
 * use this class with the tabbed pane by calling {@link JTabbedPane#setTabComponentAt(int, Component)}
 */
public class DockingTabRenderer extends JPanel {

	private static final int MAX_TITLE_LENGTH = 25;
	private Icon EMPTY_ICON =
		ResourceManager.getScaledIcon(ResourceManager.loadImage("images/close16.gif"), 8, 8);
	private Icon CLOSE_ICON =
		ResourceManager.getScaledIcon(ResourceManager.loadImage("images/close16.gif"), 8, 8);

	private JLabel titleLabel;
	private JLabel iconLabel;
	private JButton closeButton;

	private HierarchyListener hierarchyListener;
	private TabContainerForwardingMouseListener forwardingListener;
	private MouseListener renameListener;

	public DockingTabRenderer(final JTabbedPane tabbedPane, String fullTitle, String tabTitle,
			ActionListener closeListener) {

		final ForwardingMouseListener eventForwardingListener =
			new ForwardingMouseListener(tabbedPane);

		titleLabel = new GDLabel();
		iconLabel = new GDLabel();
		closeButton = new EmptyBorderButton();

		setTitle(tabTitle, fullTitle);
		closeButton.setToolTipText("Close " + tabTitle);
		closeButton.setIcon(EMPTY_ICON); // no icon until we rollover the tab
		closeButton.setFocusable(false);
		closeButton.addActionListener(closeListener);
		closeButton.setRolloverIcon(CLOSE_ICON);

		JPanel container = new JPanel();
		container.setLayout(new BoxLayout(container, BoxLayout.X_AXIS));
		container.add(iconLabel);
		container.add(Box.createHorizontalStrut(5));
		container.add(titleLabel);
		container.add(Box.createHorizontalStrut(5));
		container.add(Box.createHorizontalGlue());
		container.add(closeButton);

		setLayout(new BorderLayout());
		add(container, BorderLayout.CENTER);

		// proper background coloring--let the tab's color shine through
		setOpaque(false);
		container.setOpaque(false);
		closeButton.setOpaque(false);

		// we need to forward events so that the tabbed pane will properly switch tabs
		iconLabel.addMouseListener(eventForwardingListener);
		iconLabel.addMouseMotionListener(eventForwardingListener);
		titleLabel.addMouseListener(eventForwardingListener);
		titleLabel.addMouseMotionListener(eventForwardingListener);

		// listeners to know when to hide our close button (from the tabbed pane)
		final ButtonIconSwapperMouseListener iconListener =
			new ButtonIconSwapperMouseListener(tabbedPane);
		installIconListener(container, tabbedPane, iconListener);

		// listeners to know when to hide our close button (from this panel)
		addMouseListener(iconListener);
		addMouseMotionListener(iconListener);

		installMouseForwardingListenerWorkaround(tabbedPane, iconListener);
	}

	private void installMouseForwardingListenerWorkaround(final JTabbedPane tabbedPane,
			final ButtonIconSwapperMouseListener iconListener) {

		forwardingListener = new TabContainerForwardingMouseListener(tabbedPane);

		addHierarchyListener(new HierarchyListener() {
			@Override
			public void hierarchyChanged(HierarchyEvent e) {
				long changeFlags = e.getChangeFlags();
				if (HierarchyEvent.DISPLAYABILITY_CHANGED == (changeFlags &
					HierarchyEvent.DISPLAYABILITY_CHANGED)) {

					Container myParent = getParent(); // should be a TabContainer

					// check for the first time we are put together
					boolean isDisplayable = isDisplayable();
					if (isDisplayable) {
						// remove and add in order to prevent duplicate adding
						myParent.removeMouseListener(iconListener);
						myParent.removeMouseMotionListener(iconListener);
						myParent.removeMouseListener(forwardingListener);
						myParent.removeMouseMotionListener(forwardingListener);
						myParent.addMouseListener(iconListener);
						myParent.addMouseMotionListener(iconListener);
						myParent.addMouseListener(forwardingListener);
						myParent.addMouseMotionListener(forwardingListener);

						hierarchyListener = this;
					}
					else if (hierarchyListener != null) {
						myParent.removeMouseListener(iconListener);
						myParent.removeMouseMotionListener(iconListener);
						myParent.removeMouseListener(forwardingListener);
						myParent.removeMouseMotionListener(forwardingListener);

						removeHierarchyListener(hierarchyListener);
					}
				}
			}
		});
	}

	private String getShortenedTitle(String title) {
		if (title.length() > MAX_TITLE_LENGTH) {
			title = title.substring(0, MAX_TITLE_LENGTH - 3) + "...";
		}
		return title;
	}

	// add listeners to the tabbed pane so that the icon for closing appears (and disappears) as
	// needed
	private void installIconListener(Container container, JTabbedPane tabbedPane,
			ButtonIconSwapperMouseListener iconListener) {
		Component[] components = container.getComponents();
		for (Component component : components) {
			component.addMouseListener(iconListener);
		}

		tabbedPane.addMouseListener(iconListener);
		// we need this due to the gaps between the renderer and the tabbed pane
		tabbedPane.addMouseMotionListener(iconListener);
	}

	public void installRenameAction(MouseListener listener) {
		this.renameListener = listener;
	}

	public void setIcon(Icon icon) {
		iconLabel.setIcon(icon);
	}

	public void setTitle(String tabTitle, String fullTitle) {
		titleLabel.setText(getShortenedTitle(tabTitle));
		String trimmedTabText = tabTitle.trim();
		String trimmedTitleText = fullTitle.trim();
		if (trimmedTabText.equals(trimmedTitleText)) {
			// don't include the same text on twice
			titleLabel.setToolTipText(tabTitle);
		}
		else if (trimmedTitleText.contains(trimmedTabText)) {
			// don't include both when the tab text is a subset of the title
			titleLabel.setToolTipText(fullTitle);
		}
		else {
			// both are different, include both			
			titleLabel.setToolTipText("<html><b>" + tabTitle + "</b> - [" + fullTitle + "]");
		}
	}

	public String getTabText() {
		return titleLabel.getText();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A class to hide/show the close button's icon to make it appear that the button is hidden
	 * and removed.
	 */
	private class ButtonIconSwapperMouseListener extends MouseAdapter {

		private final JTabbedPane tabbedPane;

		ButtonIconSwapperMouseListener(JTabbedPane tabbedPane) {
			this.tabbedPane = tabbedPane;
		}

		private void updateButton(MouseEvent e) {
			Point point = e.getPoint();
			Point tabbedPaneRelativePoint =
				SwingUtilities.convertPoint(e.getComponent(), point, tabbedPane);
			int x = tabbedPaneRelativePoint.x;
			int y = tabbedPaneRelativePoint.y;
			int tabIndex = tabbedPane.indexAtLocation(x, y);
			if (tabIndex < 0) {
				// no tab for the given point (can happen when over the tabbed pane, but not
				// over any tab)
				closeButton.setIcon(EMPTY_ICON);
				return;
			}

			Component tabComponent = tabbedPane.getTabComponentAt(tabIndex);
			if (SwingUtilities.isDescendingFrom(closeButton, tabComponent)) {
				closeButton.setIcon(CLOSE_ICON);
			}
			else {
				closeButton.setIcon(EMPTY_ICON);
			}
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			updateButton(e);
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			updateButton(e);
		}

		@Override
		public void mouseExited(MouseEvent e) {
			closeButton.setIcon(EMPTY_ICON);
		}
	}

	/**
	 * A class designed to listen for mouse events on this renderer component which it will then
	 * forward on to the given component.
	 */
	private class ForwardingMouseListener implements MouseListener, MouseMotionListener {

		private final Component handler;

		ForwardingMouseListener(Component handler) {
			this.handler = handler;
		}

		private void forwardEvent(MouseEvent e) {
			MouseEvent newEvent = SwingUtilities.convertMouseEvent(e.getComponent(), e, handler);
			handler.dispatchEvent(newEvent);
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			if (consumePopup(e)) {
				return;
			}
			forwardEvent(e);
		}

		@Override
		public void mousePressed(MouseEvent e) {
			if (consumePopup(e)) {
				return;
			}
			forwardEvent(e);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (consumePopup(e)) {
				return;
			}
			forwardEvent(e);
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			forwardEvent(e);
		}

		@Override
		public void mouseExited(MouseEvent e) {
			forwardEvent(e);
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			forwardEvent(e);
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			forwardEvent(e);
		}

		private boolean consumePopup(MouseEvent e) {
			if (renameListener == null) {
				return false;
			}

			if (!e.isPopupTrigger()) {
				return false;
			}

			renameListener.mouseClicked(e);

			return true;
		}
	}

	/**
	 * A class to handle mouse events specifically for BasicTabbedPaneUI$TabContainer, which does
	 * not forward mouse events on to the tabbed pane.  When using custom tab renderers, which 
	 * we are, tabbed panes that are larger than the the renderer will not get mouse events that
	 * are over the tab, but not the renderer.
	 */
	private class TabContainerForwardingMouseListener extends MouseAdapter {

		private final JTabbedPane tabbedPane;

		TabContainerForwardingMouseListener(JTabbedPane tabbedPane) {
			this.tabbedPane = tabbedPane;
		}

		/**
		 * This lets clicks on the TabContainer trigger tab selection.
		 */
		private void maybeForwardMousePressedEvent(MouseEvent e) {
			MouseEvent tabbedPaneRelativeMouseEvent =
				SwingUtilities.convertMouseEvent(e.getComponent(), e, tabbedPane);
			tabbedPane.dispatchEvent(tabbedPaneRelativeMouseEvent);
		}

		/**
		 * This lets rollover highlighting happen when over the TabContainer.
		 */
		private void forwardMouseMotionEvent(MouseEvent e) {
			e.consume();
			MouseEvent newEvent = SwingUtilities.convertMouseEvent(e.getComponent(), e, tabbedPane);
			tabbedPane.dispatchEvent(newEvent);
		}

		@Override
		public void mousePressed(MouseEvent e) {
			if (e.isConsumed()) {
				return;
			}
			maybeForwardMousePressedEvent(e);
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			if (e.isConsumed()) {
				return;
			}
			maybeForwardMousePressedEvent(e);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (e.isConsumed()) {
				return;
			}
			maybeForwardMousePressedEvent(e);
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			if (e.isConsumed()) {
				return;
			}
			forwardMouseMotionEvent(e);
		}
	}
}
