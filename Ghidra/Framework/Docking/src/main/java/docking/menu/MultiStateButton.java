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
import java.util.function.Consumer;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

import docking.*;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.util.Swing;
import resources.Icons;
import resources.ResourceManager;
import utility.function.Dummy;

/**
 * A button that has a drop-down list of choosable {@link ButtonState}s. When a state is selected,
 * it changes the behavior of the action associated with the button. This code is based on code 
 * for the {@link MultipleActionDockingToolbarButton}.
 *
 * @param <T> The type of the user data associated with the {@link ButtonState}s
 */
public class MultiStateButton<T> extends JButton {

	private Icon arrowIcon;
	private Icon disabledArrowIcon;

	private static int ARROW_WIDTH = 6;
	private static int ARROW_HEIGHT = 3;
	private static int ARROW_ICON_WIDTH = 20;
	private static int ARROW_ICON_HEIGHT = 15;

	private PopupMouseListener popupListener;
	private JPopupMenu popupMenu;
	private Rectangle arrowButtonRegion;
	private long popupLastClosedTime;
	private List<ButtonState<T>> buttonStates;
	private ButtonState<T> currentButtonState;

	private Consumer<ButtonState<T>> stateChangedConsumer = Dummy.consumer();

	public MultiStateButton(List<ButtonState<T>> buttonStates) {
		setButtonStates(buttonStates);
		installMouseListeners();

		arrowButtonRegion = createArrowRegion();
		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				super.componentResized(e);
				arrowButtonRegion = createArrowRegion();
				repaint();
			}
		});
		addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_DOWN) {
					Swing.runLater(() -> popupMenu = showPopup());
					e.consume();
				}
			}
		});
	}

	public void setButtonStates(List<ButtonState<T>> buttonStates) {
		this.buttonStates = buttonStates;
		if (buttonStates.size() == 1) {
			arrowIcon = Icons.EMPTY_ICON;
			disabledArrowIcon = Icons.EMPTY_ICON;
			setHorizontalAlignment(SwingConstants.CENTER); // center text if no drop-down menu
		}
		else {
			arrowIcon = new ArrowIcon();
			disabledArrowIcon = ResourceManager.getDisabledIcon(arrowIcon);
			setHorizontalAlignment(SwingConstants.LEFT); // align left if we have drop-down menu
		}
		setCurrentButtonState(buttonStates.get(0));
		arrowButtonRegion = createArrowRegion();
	}

	/**
	 * Sets a consumer to be called when the user changes the active {@link ButtonState}.
	 * @param consumer the consumer to be called when the button state changes
	 */
	public void setStateChangedListener(Consumer<ButtonState<T>> consumer) {
		this.stateChangedConsumer = consumer;
	}

	/**
	 * Sets the active button state for this button.
	 * @param buttonState the button state to be made active
	 */
	public void setCurrentButtonState(ButtonState<T> buttonState) {
		if (!buttonStates.contains(buttonState)) {
			throw new IllegalArgumentException("Attempted to set button state to unknown state");
		}
		this.currentButtonState = buttonState;
		setText(buttonState.getButtonText());
		String tooltip = buttonState.getDescription();

		setToolTipText(tooltip);
		getAccessibleContext().setAccessibleDescription(tooltip);
		stateChangedConsumer.accept(buttonState);
	}

	/**
	 * Sets the active button state to the state that is associated with the given client data.
	 * @param clientData the client data to make its associated button state the active state
	 */
	public void setSelectedStateByClientData(T clientData) {
		for (ButtonState<T> buttonState : buttonStates) {
			if (Objects.equals(clientData, buttonState.getClientData())) {
				setCurrentButtonState(buttonState);
			}
		}
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		int y = (getHeight() - arrowIcon.getIconHeight()) / 2;
		Icon icon = isEnabled() ? arrowIcon : disabledArrowIcon;
		icon.paintIcon(this, g, arrowButtonRegion.x, y);
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension d = super.getPreferredSize();
		d.width = d.width + arrowIcon.getIconWidth();
		d.height = Math.max(d.height, arrowIcon.getIconHeight());
		return d;
	}

	private Rectangle createArrowRegion() {
		if (buttonStates.size() == 1) {
			return new Rectangle(0, 0, 0, 0);
		}
		Dimension size = getSize();
		Border border = getBorder();

		// Depending on the theme, the button may have thick borders to compensate for the extra
		// space we requested in the preferred size method. Some themes do this via a compound
		// border and using the outside border's right inset works very well to move the icon
		// inside the border.
		// Otherwise, we just use 3 as a decent compromise. Nimbus looks best with 3, but flat 
		// themes look best with 2 as they have a thinner "outside" border
		int rightMargin = 3;
		if (border instanceof CompoundBorder compoundBorder) {
			Border outsideBorder = compoundBorder.getOutsideBorder();
			Insets borderInsets = outsideBorder.getBorderInsets(this);
			rightMargin = borderInsets.right;
		}
		int w = arrowIcon.getIconWidth() + rightMargin;
		int h = size.height;
		return new Rectangle(size.width - w, 0, w, h);
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

	protected ActionContext getActionContext() {
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
	protected JPopupMenu showPopup() {

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
		// and thus we should ignore it.
		//
		long elapsedTime = System.currentTimeMillis() - popupLastClosedTime;
		if (elapsedTime < 500) { // somewhat arbitrary time window
			return null;
		}

		JPopupMenu menu = doCreateMenu();

		menu.addPopupMenuListener(popupListener);
		Point p = getPopupPoint();
		menu.show(this, p.x, p.y);
		return menu;
	}

	protected JPopupMenu doCreateMenu() {

		JPopupMenu menu = new JPopupMenu();
		ButtonGroup buttonGroup = new ButtonGroup();
		for (ButtonState<T> state : buttonStates) {

			JCheckBoxMenuItem item = new JCheckBoxMenuItem(state.getMenuText());
			item.setToolTipText(state.getDescription());
			item.getAccessibleContext().setAccessibleDescription(state.getDescription());
			item.setSelected(state == currentButtonState);
			buttonGroup.add(item);

			// a UI that handles alignment issues and allows for tabulating presentation
			item.setUI(DockingMenuItemUI.createUI(item));
			item.addActionListener(e -> {
				setCurrentButtonState(state);
			});

			menu.add(item);
		}
		return menu;
	}

	public Point getPopupPoint() {
		Rectangle bounds = getBounds();
		return new Point(bounds.width - arrowIcon.getIconWidth(), bounds.y + bounds.height);
	}

	private boolean popupIsShowing() {
		return (popupMenu != null) && popupMenu.isVisible();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class ArrowIcon implements Icon {

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(Messages.HINT);
			g.drawLine(x, y, x, y + ARROW_ICON_HEIGHT);
			g.setColor(Colors.FOREGROUND);

			int arrowMiddleX = x + ARROW_ICON_WIDTH / 2;
			int arrowStartX = arrowMiddleX - ARROW_WIDTH / 2;
			int arrowEndX = arrowStartX + ARROW_WIDTH;

			int arrowStartY = y + ARROW_ICON_HEIGHT / 2 - ARROW_HEIGHT / 2;
			int arrowEndY = arrowStartY;
			int arrowMiddleY = arrowStartY + ARROW_HEIGHT;

			int[] xPoints = { arrowStartX, arrowEndX, arrowMiddleX };
			int[] yPoints = { arrowStartY, arrowEndY, arrowMiddleY };

			Graphics2D graphics2D = (Graphics2D) g;
			graphics2D.drawPolygon(xPoints, yPoints, 3);
			graphics2D.fillPolygon(xPoints, yPoints, 3);
		}

		@Override
		public int getIconWidth() {
			return ARROW_ICON_WIDTH;
		}

		@Override
		public int getIconHeight() {
			return ARROW_ICON_HEIGHT;
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
			if (isEnabled() && arrowButtonRegion.contains(clickPoint)) {

				// Unusual Code Alert: we need to put this call in an invoke later, since Java
				// will update the focused window after we click.  We need the focus to be
				// correct before we show, since our menu is built with actions based upon the
				// focused component.
				Swing.runLater(() -> popupMenu = showPopup());

				e.consume();
				model.setPressed(false);
				model.setArmed(false);
				model.setRollover(false);
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

}
