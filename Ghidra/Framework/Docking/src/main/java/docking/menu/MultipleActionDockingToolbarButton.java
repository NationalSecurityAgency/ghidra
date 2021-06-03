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
package docking.menu;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.*;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.action.*;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDHtmlLabel;
import ghidra.util.Swing;
import resources.ResourceManager;

public class MultipleActionDockingToolbarButton extends EmptyBorderButton {

	private Icon primaryIcon;
	private Icon disabledIcon;

	private static int ARROW_WIDTH = 4;
	private static int ARROW_HEIGHT = 2;
	private static int ARROW_PADDING = 4;

	private PopupMouseListener popupListener;
	private Shape popupContext;

	private final MultiActionDockingActionIf multipleAction;
	private boolean iconBorderEnabled = true;
	private boolean entireButtonShowsPopupMenu;

	public MultipleActionDockingToolbarButton(MultiActionDockingActionIf action) {
		multipleAction = action;
		installMouseListeners();
		setIcon(ResourceManager.loadImage("images/core.png"));
	}

	@Override
	public void setBorder(Border border) {
		super.setBorder(border);
		if (primaryIcon != null) { // happens during init
			initIcons();
		}
	}

	@Override
	public void setIcon(Icon icon) {
		primaryIcon = Objects.requireNonNull(icon);
		initIcons();
	}

	@Override
	public Icon getDisabledIcon() {
		return disabledIcon;
	}

	/**
	 * By default a click on this button will trigger <code>actionPerformed()</code> to be called.
	 * You can call this method to disable that feature.  When called with <code>false</code>, this
	 * method will effectively let the user click anywhere on the button or its drop-down arrow
	 * to show the popup menu.  During normal operation, the user can only show the popup by
	 * clicking the drop-down arrow.
	 * 
	 * @param performActionOnButtonClick true to perform the action when the button is clicked
	 */
	public void setPerformActionOnButtonClick(boolean performActionOnButtonClick) {
		entireButtonShowsPopupMenu = !performActionOnButtonClick;
		iconBorderEnabled = performActionOnButtonClick;
		popupContext = createPopupContext();
	}

	@Override
	protected void paintBorder(Graphics g) {
		Border buttonBorder = getBorder();
		if (buttonBorder == null) {
			return;
		}

		Insets borderInsets = buttonBorder.getBorderInsets(this);
		int leftIconWidth = primaryIcon.getIconWidth() + (borderInsets.left + borderInsets.right);
		if (iconBorderEnabled) {
			buttonBorder.paintBorder(this, g, 0, 0, leftIconWidth, getHeight());
		}

		int rightButtonWidth =
			ARROW_WIDTH + ARROW_PADDING + (borderInsets.left + borderInsets.right);
		buttonBorder.paintBorder(this, g, leftIconWidth, 0, rightButtonWidth, getHeight());
	}

	private void initIcons() {
		Icon newIcon = createImageIcon();
		disabledIcon = ResourceManager.getDisabledIcon(newIcon);
		super.setIcon(newIcon);
		popupContext = createPopupContext();
	}

	private void installMouseListeners() {
		MouseListener[] mouseListeners = getMouseListeners();
		for (MouseListener mouseListener : mouseListeners) {
			removeMouseListener(mouseListener);
		}

		popupListener = new PopupMouseListener(mouseListeners);
		addMouseListener(popupListener);
	}

	private Icon createImageIcon() {
		Insets insets = getInsets();
		return new IconWithDropDownArrow(primaryIcon,
			primaryIcon.getIconWidth() + ARROW_WIDTH + ARROW_PADDING + (insets.right + insets.left),
			primaryIcon.getIconHeight(), insets);
	}

	private Shape createPopupContext() {
		if (entireButtonShowsPopupMenu) {
			return new Rectangle(0, 0, getWidth(), getHeight());
		}

		Border buttonBorder = getBorder();
		Insets borderInsets =
			buttonBorder == null ? new Insets(0, 0, 0, 0) : buttonBorder.getBorderInsets(this);
		int leftIconWidth = primaryIcon.getIconWidth() + (borderInsets.left + borderInsets.right);
		int rightButtonWidth =
			ARROW_WIDTH + ARROW_PADDING + (borderInsets.left + borderInsets.right);
		int height = getIcon().getIconHeight() + borderInsets.top + borderInsets.bottom;
		return new Rectangle(leftIconWidth, 0, rightButtonWidth, height);
	}

	private ActionContext getActionContext() {
		ComponentProvider provider = getComponentProvider();
		ActionContext context = provider == null ? null : provider.getActionContext(null);
		final ActionContext actionContext = context == null ? new ActionContext() : context;
		return actionContext;
	}

	private ComponentProvider getComponentProvider() {
		DockingWindowManager manager = DockingWindowManager.getActiveInstance();
		if (manager == null) {
			return null;
		}
		return manager.getActiveComponentProvider();
	}

	/** 
	 * Show a popup containing all the actions below the button
	 * @param listener for the created popup menu
	 * @return the popup menu that was shown
	 */
	JPopupMenu showPopup(PopupMenuListener listener) {
		JPopupMenu menu = new JPopupMenu();
		List<DockingActionIf> actionList = multipleAction.getActionList(getActionContext());
		for (DockingActionIf dockingAction : actionList) {

			String[] menuPath = dockingAction.getMenuBarData().getMenuPath();
			String name = menuPath[menuPath.length - 1];

			// this is a special signal to say we should insert a separator and not a real menu item
			if (!dockingAction.isEnabled()) {
				String description = dockingAction.getDescription();
				JSeparator separator = new ProgramNameSeparator(name, description);
				menu.add(separator);
				continue;
			}

			JMenuItem item = dockingAction.createMenuItem(false);

			// a custom Ghidra UI that handles alignment issues and allows for tabulating presentation
			item.setUI((DockingMenuItemUI) DockingMenuItemUI.createUI(item));
			final DockingActionIf delegateAction = dockingAction;
			item.addActionListener(e -> {
				ActionContext context = getActionContext();
				context.setSourceObject(e.getSource());
				if (delegateAction instanceof ToggleDockingAction) {
					ToggleDockingAction toggleAction = (ToggleDockingAction) delegateAction;
					toggleAction.setSelected(!toggleAction.isSelected());
				}
				delegateAction.actionPerformed(context);
			});
			ButtonModel itemButtonModel = item.getModel();
			itemButtonModel.addChangeListener(new HoverChangeListener(delegateAction));

			menu.add(item);
		}

		if (listener != null) {
			menu.addPopupMenuListener(listener);
		}
		Point p = getPopupPoint();
		menu.show(this, p.x, p.y);
		return menu;
	}

	public Point getPopupPoint() {
		Rectangle bounds = getBounds();
		return new Point(0, bounds.y + bounds.height);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class IconWithDropDownArrow implements Icon {

		private int width;
		private int height;
		private Insets insets;
		private Icon baseIcon;

		IconWithDropDownArrow(Icon baseIcon, int width, int height, Insets insets) {
			this.baseIcon = baseIcon;
			this.width = width;
			this.height = height;
			this.insets = insets;
		}

		@Override
		public int getIconHeight() {
			return height;
		}

		@Override
		public int getIconWidth() {
			return width;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			baseIcon.paintIcon(c, g, x, y);

			if (!(g instanceof Graphics2D)) {
				return; // shouldn't happen
			}

			g.setColor(Color.BLACK);
			int iconWidth = baseIcon.getIconWidth();
			int iconHeight = baseIcon.getIconHeight();
			int insetsPadding = insets.left + insets.right; // the insets of the left icon and the arrow (between the two)
			int leftSidePadding = ARROW_PADDING / 2; // half of the padding for the left
			int oddSizeOffset = 0; // we may have an odd number length for the arrow
			if (ARROW_WIDTH % 2 == 0) {
				// a starting even width will end up giving us an odd number of pixels, which
				// throws off the padding around the arrow (different number of pixels in padding
				// on each side of the arrow)...so handle it
				oddSizeOffset = 1;
			}
			leftSidePadding = leftSidePadding - oddSizeOffset;
			int paintArrowXOffset = x + iconWidth + insetsPadding + leftSidePadding;
			int paintArrowYOffset = y + (iconHeight / 2) - ARROW_HEIGHT;

			int arrowStartX = paintArrowXOffset;
			int arrowEndX = paintArrowXOffset + ARROW_WIDTH;
			int arrowMiddleX = paintArrowXOffset + (ARROW_WIDTH / 2);

			int arrowStartY = paintArrowYOffset;
			int arrowEndY = arrowStartY;
			int arrowMiddleY = arrowStartY + ARROW_HEIGHT;

			int[] xPoints = { arrowStartX, arrowEndX, arrowMiddleX };
			int[] yPoints = { arrowStartY, arrowEndY, arrowMiddleY };

			Graphics2D graphics2D = (Graphics2D) g;
			graphics2D.drawPolygon(xPoints, yPoints, 3);
			graphics2D.fillPolygon(xPoints, yPoints, 3);
		}
	}

	private class PopupMouseListener extends MouseAdapter implements PopupMenuListener {
		private final MouseListener[] parentListeners;
		private JPopupMenu popupMenu;
		private long actionID = 0; // used to determine when the popup was closed by clicking the button 

		public PopupMouseListener(MouseListener[] parentListeners) {
			this.parentListeners = parentListeners;
		}

		@Override
		public void mousePressed(MouseEvent e) {
			// close the popup if the user clicks the button while the popup is visible
			if (popupIsShowing() && e.getClickCount() == 1) { // ignore double-click when the menu is up
				popupMenu.setVisible(false);
				return;
			}

			long eventTime = System.currentTimeMillis();
			if (actionID == eventTime) {
				return;
			}

			Point clickPoint = e.getPoint();
			if (isEnabled() && popupContext.contains(clickPoint)) {

				// Unusual Code Alert: we need to put this call in an invoke later, since Java
				// will update the focused window after we click.  We need the focus to be
				// correct before we show, since our menu is built with actions based upon the
				// focused dude.
				Swing.runLater(() -> popupMenu = showPopup(PopupMouseListener.this));

				e.consume();
				model.setPressed(false);
				model.setArmed(false);
				model.setRollover(false);
				clearBorder();
				return;
			}

			for (MouseListener listener : parentListeners) {
				listener.mousePressed(e);
			}
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			if (popupIsShowing()) {
				e.consume();
				return;
			}

			for (MouseListener listener : parentListeners) {
				listener.mouseClicked(e);
			}
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (popupIsShowing()) {
				e.consume();
				return;
			}

			for (MouseListener listener : parentListeners) {
				listener.mouseReleased(e);
			}
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			if (popupIsShowing()) {
				return;
			}

			for (MouseListener listener : parentListeners) {
				listener.mouseEntered(e);
			}
		}

		@Override
		public void mouseExited(MouseEvent e) {
			if (popupIsShowing()) {
				return;
			}
			for (MouseListener listener : parentListeners) {
				listener.mouseExited(e);
			}
		}

		private boolean popupIsShowing() {
			return (popupMenu != null) && popupMenu.isVisible();
		}

		@Override
		public void popupMenuCanceled(PopupMenuEvent e) {
			// no-op
		}

		@Override
		public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
			actionID = System.currentTimeMillis(); // hacktastic!
		}

		@Override
		public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
			// no-op
		}
	}

	private class HoverChangeListener implements ChangeListener {
		private final DockingActionIf delegateAction;

		public HoverChangeListener(DockingActionIf delegateAction) {
			this.delegateAction = delegateAction;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			Object source = e.getSource();
			if (!(source instanceof ButtonModel)) {
				return;
			}

			ButtonModel buttonModel = (ButtonModel) source;
			if (buttonModel.isArmed()) {
				// item entered
				DockingWindowManager.setMouseOverAction(delegateAction);
			}
			else {
				// item exited
				DockingWindowManager.setMouseOverAction(null);
			}
		}

	}

	private static class ProgramNameSeparator extends JSeparator {

		private final int EMTPY_SEPARATOR_HEIGHT = 10;
		private final int TEXT_SEPARATOR_HEIGHT = 32;
		private JLabel renderer = new GDHtmlLabel();

		private int separatorHeight = EMTPY_SEPARATOR_HEIGHT;

		private ProgramNameSeparator(String name, String description) {
			setBorder(BorderFactory.createEmptyBorder(20, 0, 20, 0));
			renderer.setText(name);
			DockingUtils.setTransparent(renderer);
			renderer.setHorizontalAlignment(SwingConstants.CENTER);
			renderer.setVisible(true);

			if (!StringUtils.isBlank(name)) {
				separatorHeight = TEXT_SEPARATOR_HEIGHT;
			}

// IF WE CHOOSE TO SHOW TOOLTIPS (and below too)...
//            setToolTipText( description );
		}

		@Override
		protected void paintComponent(Graphics g) {
			Dimension d = getSize();

			// some edge padding, for classiness
			int pad = 10;
			int center = separatorHeight >> 1;
			int x = 0 + pad;
			int y = center;
			int w = d.width - pad;
			g.setColor(getForeground());
			g.drawLine(x, y, w, y);

			// drop-shadow
			g.setColor(getBackground());
			g.drawLine(x, (y + 1), w, (y + 1));

			// now add our custom text
			renderer.setSize(getSize());
			renderer.paint(g);
		}

		@Override
		public Dimension getPreferredSize() {
			// assume horizontal
			return new Dimension(0, separatorHeight);
		}

		@Override
		public Dimension getMinimumSize() {
			return new Dimension(0, separatorHeight);
		}

//
// USE THE CODE BELOW IF WE WANT TOOLTIPS
//
//          @Override
//        public String getToolTipText( MouseEvent event ) {
//            // We only want to show the tooltip when the user is over the label.  Since the label
//            // is not on the screen, we cannot ask it if the mouse location is within its bounds.
//            Dimension labelSize = renderer.getPreferredSize();
//            if ( labelSize.height == 0 && labelSize.width == 0 ) {
//                return null;
//            }
//
//            Dimension mySize = getSize();
//            int centerX = mySize.width >> 1;
//
//            int labelMidPoint = labelSize.width >> 1;
//            int labelStartX = centerX - labelMidPoint;
//            int labelEndX = centerX + labelMidPoint;
//
//            Point mousePoint = event.getPoint();
//            boolean insideLabel = (mousePoint.x >= labelStartX) && (mousePoint.x <= labelEndX);
//            if ( !insideLabel ) {
//                return null;
//            }
//            return getToolTipText();
//        }
//
//        @Override
//        public Point getToolTipLocation( MouseEvent event ) {
//            Rectangle bounds = getBounds();
//            bounds.x += bounds.width;
//            bounds.y = 0;
//            return bounds.getLocation();
//        }
	}
}
