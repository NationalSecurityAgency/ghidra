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

import docking.*;
import docking.action.*;
import docking.widgets.EmptyBorderButton;
import generic.theme.GThemeDefaults.Colors;
import ghidra.util.Swing;
import resources.ResourceManager;

public class MultipleActionDockingToolbarButton extends EmptyBorderButton {

	private Icon primaryIcon;
	private Icon disabledIcon;

	private static int ARROW_WIDTH = 4;
	private static int ARROW_HEIGHT = 2;
	private static int ARROW_PADDING = 4;

	private PopupMouseListener popupListener;
	private JPopupMenu popupMenu;
	private Shape popupContext;
	private long popupLastClosedTime;

	private final MultiActionDockingActionIf multipleAction;

	public MultipleActionDockingToolbarButton(MultiActionDockingActionIf action) {
		multipleAction = action;
		installMouseListeners();
		setIcon(ResourceManager.getDefaultIcon());
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

	@Override
	protected void paintBorder(Graphics g) {
		Border buttonBorder = getBorder();
		if (buttonBorder == null) {
			return;
		}

		Insets borderInsets = buttonBorder.getBorderInsets(this);
		int leftIconWidth = primaryIcon.getIconWidth() + (borderInsets.left + borderInsets.right);
		buttonBorder.paintBorder(this, g, 0, 0, leftIconWidth, getHeight());
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

	@Override
	public void updateUI() {

		removeMouseListener(popupListener);

		super.updateUI();

		installMouseListeners();
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
		final ActionContext actionContext = context == null ? new DefaultActionContext() : context;
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
	 * 
	 * @return the popup menu that was shown
	 */
	JPopupMenu showPopup() {

		if (popupIsShowing()) {
			popupMenu.setVisible(false);
			return null;
		}

		//
		// showPopup() will handled 2 cases when this action's button is clicked:
		// 1) show a popup if it was not showing
		// 2) hide the popup if it was showing
		//
		// Case 2 requires timestamps.  Java will close the popup as the button is clicked. This 
		// means that when we are told to show the popup as the result of a click, the popup will 
		// never be showing.  To work around this, we track the elapsed time since last click.  If 
		// the period is too short, then we assume Java closed the popup when the click happened 
		//and thus we should ignore it.
		//
		long elapsedTime = System.currentTimeMillis() - popupLastClosedTime;
		if (elapsedTime < 500) { // somewhat arbitrary time window
			return null;
		}

		JPopupMenu menu = new JPopupMenu();
		List<DockingActionIf> actionList = multipleAction.getActionList(getActionContext());
		for (DockingActionIf dockingAction : actionList) {

			Component component = dockingAction.createMenuComponent(false);
			if (!(component instanceof JMenuItem item)) {
				// not an actual item, e.g., a separator as in HorizontalRuleAction
				menu.add(component);
				continue;
			}

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

		menu.addPopupMenuListener(popupListener);
		Point p = getPopupPoint();
		menu.show(this, p.x, p.y);
		return menu;
	}

	public Point getPopupPoint() {
		Rectangle bounds = getBounds();
		return new Point(0, bounds.y + bounds.height);
	}

	private boolean popupIsShowing() {
		return (popupMenu != null) && popupMenu.isVisible();
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

			g.setColor(Colors.FOREGROUND);
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

		public PopupMouseListener(MouseListener[] parentListeners) {
			this.parentListeners = parentListeners;
		}

		@Override
		public void mousePressed(MouseEvent e) {

			Point clickPoint = e.getPoint();
			if (isEnabled() && popupContext.contains(clickPoint)) {

				// Unusual Code Alert: we need to put this call in an invoke later, since Java
				// will update the focused window after we click.  We need the focus to be
				// correct before we show, since our menu is built with actions based upon the
				// focused component.
				Swing.runLater(() -> popupMenu = showPopup());

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

		@Override
		public void popupMenuCanceled(PopupMenuEvent e) {
			// no-op
		}

		@Override
		public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
			popupLastClosedTime = System.currentTimeMillis();
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

}
