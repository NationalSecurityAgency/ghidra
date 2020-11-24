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
package docking;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.Animator.RepeatBehavior;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import docking.action.DockingActionIf;
import docking.util.AnimationUtils;
import docking.widgets.VariableHeightPanel;
import docking.widgets.label.GDLabel;

// TODO: should this be put into generic?
public class GenericHeader extends JPanel {

	private static final Color NON_FOCUS_START_COLOR = new Color(150, 150, 150);
	private static final Color FOCUS_START_COLOR = new Color(30, 30, 150);
	private static final int MINIMUM_TITLE_SIZE = 80;

	private Color nonFocusColor = NON_FOCUS_START_COLOR;
	private Color focusColor = FOCUS_START_COLOR;

	protected Component component;
	protected DockableToolBarManager toolBarMgr;
	private VariableHeightPanel toolbar;
	private JComponent menuCloseToolbar;
	private int numLines = 0;

	protected TitlePanel titlePanel;
	private boolean useSingleLineLayoutOverride;

	private MouseListener mouseListener = new MouseAdapter() {
		@Override
		public void mousePressed(MouseEvent e) {
			setSelected(true);
			requestFocus();
		}
	};

	public GenericHeader() {
		this(NON_FOCUS_START_COLOR, FOCUS_START_COLOR);
	}

	public GenericHeader(Color nonFocusColor, Color focusColor) {
		this.nonFocusColor = nonFocusColor;
		this.focusColor = focusColor;

		BorderLayout layout = new BorderLayout();
		layout.setVgap(1);
		setLayout(layout);
		setBorder(BorderFactory.createLineBorder(Color.GRAY));
		setFocusable(false);

		titlePanel = new TitlePanel();

		toolBarMgr = new DockableToolBarManager(this);

		resetComponents();

		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateLayout();
			}
		});
	}

	public void dispose() {
		toolBarMgr.dispose();
	}

	@Override
	public Dimension getPreferredSize() {
		if (getComponentCount() == 0) {
			// give some height (for layout calculations) when we are not yet built
			return new Dimension(100, 20);
		}
		return super.getPreferredSize();
	}

	/**
	 * Signals whether or not to break the toolbar actions into multiple rows.  The default is
	 * to wrap as necessary.  
	 * @param noWrap true signals not to break the actions into multiple rows
	 */
	public void setNoWrapToolbar(boolean noWrap) {
		useSingleLineLayoutOverride = noWrap;
		updateLayout();
	}

	@Override
	public void requestFocus() {
		if (component == null) {
			return;
		}
		component.requestFocus();
	}

	private void installMouseListener(Component comp) {
		if (comp instanceof Container) {
			Container c = (Container) comp;
			Component comps[] = c.getComponents();
			for (Component element : comps) {
				installMouseListener(element);
			}
		}

		comp.removeMouseListener(mouseListener);
		comp.addMouseListener(mouseListener);
	}

	protected void resetComponents() {
		if (toolBarMgr == null) {
			return; // initializing
		}

		toolbar = (VariableHeightPanel) toolBarMgr.getToolBar();
		menuCloseToolbar = toolBarMgr.getMenuCloseToolBar();
		numLines = 0;
	}

	public void update() {
		if (toolBarMgr == null) {
			return; // initializing
		}

		resetComponents();
		updateLayout();
		installMouseListener(this);
	}

	void updateLayout() {

		if (toolbar == null) {
			if (numLines != 1) {
				constructOneLinePanel();
			}
			return;
		}

		Dimension mySize = getSize();
		Dimension toolBarSize = toolbar.getPreferredLayoutSize();
		Dimension d = menuCloseToolbar.getPreferredSize();
		if (mySize.width == 0 || toolBarSize.width + d.width + MINIMUM_TITLE_SIZE < mySize.width ||
			useSingleLineLayoutOverride) {
			if (numLines != 1) {
				constructOneLinePanel();
			}
		}
		else if (numLines != 2) {
			constructMultiLinePanel();
		}

	}

	private void constructOneLinePanel() {
		removeAll();
		if (toolbar == null) {
			add(menuCloseToolbar, BorderLayout.EAST);
		}
		else {
			JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
			toolbar.setBorder(BorderFactory.createEmptyBorder());
			panel.add(toolbar);
			panel.add(menuCloseToolbar);
			add(panel, BorderLayout.EAST);
			toolbar.setUseSingleLineLayout(true);
			toolbar.invalidate();
		}
		add(titlePanel, BorderLayout.CENTER);
		numLines = 1;
		validateInvalidate();
	}

	protected void validateInvalidate() {
		toolbar.invalidate();
		invalidate();
		Component parent = getParent();
		if (parent != null) {
			parent.validate();
		}
		else {
			validate();
		}
	}

	private void constructMultiLinePanel() {
		removeAll();
		toolbar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.BLACK));
		add(toolbar, BorderLayout.SOUTH);
		add(titlePanel, BorderLayout.CENTER);
		add(menuCloseToolbar, BorderLayout.EAST);

		numLines = 2;
		if (useSingleLineLayoutOverride) {
			toolbar.setUseSingleLineLayout(true);
		}
		else {
			toolbar.setUseSingleLineLayout(false);
		}

		validateInvalidate();
	}

	/**
	 * updates the toolbar to include the new action.
	 * @param action the action that was added.
	 */
	public void actionAdded(DockingActionIf action) {
		toolBarMgr.addAction(action);
	}

	/**
	 * updates the toolbar to remove the given action.
	 * @param action the action that was removed.
	 */
	public void actionRemoved(DockingActionIf action) {
		toolBarMgr.removeAction(action);
	}

	public DockingActionIf getAction(String name) {
		return toolBarMgr.getAction(name);
	}

	public int getToolBarWidth() {
		JComponent toolBarComponent = toolBarMgr.getToolBar();
		return toolBarComponent.getMinimumSize().width;
	}

	/**
	 * Sets the focus state of the component so that a visual clue can be displayed.
	 * @param hasFocus true if the this component has focus, false otherwise.
	 */
	public void setSelected(boolean hasFocus) {
		titlePanel.setSelected(hasFocus);
	}

	protected Animator createEmphasizingAnimator() {
		if (!AnimationUtils.isAnimationEnabled()) {
			return null;
		}

		TitleFlasher titleFlasher = new TitleFlasher();
		return titleFlasher.animator;
	}

	public boolean isSelected() {
		return titlePanel.isSelected();
	}

	public void setTitle(String title) {
		titlePanel.setTitle(title);
	}

	public void setIcon(Icon icon) {
		titlePanel.setIcon(icon);
	}

	public void setColor(Color color) {
		focusColor = color;
	}

	public void setComponent(Component component) {
		this.component = component;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	public class TitleFlasher {

		Animator animator;

		TitleFlasher() {
			animator = PropertySetter.createAnimator(1000, this, "color", NON_FOCUS_START_COLOR,
				NON_FOCUS_START_COLOR, Color.YELLOW, FOCUS_START_COLOR);

//			animator =
//				PropertySetter.createAnimator(1000, this, "color", NON_FOCUS_START_COLOR,
//					NON_FOCUS_START_COLOR, Color.YELLOW, FOCUS_START_COLOR);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);
//			animator.setRepeatCount(5); // non-focus->focus; focus->non-focus (*2)

			// color-to-color, reversing colors each time it is run
			animator.setRepeatBehavior(RepeatBehavior.REVERSE);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			animator.start();

			titlePanel.setSelected(true);
		}

		public void setColor(Color updatedColor) {
			focusColor = updatedColor;
			titlePanel.repaint();
		}

		private void done() {
			focusColor = FOCUS_START_COLOR;
			titlePanel.repaint();
		}
	}

	/**
	 * Overridden pane to draw a title using a gradient colored background
	 */
	protected class TitlePanel extends JPanel {

		private PopupMouseListener popupMouseListener;
		private JLabel titleLabel;
		private boolean isSelected = false;

		/**
		 * Constructs a new titlePanel.
		 */
		TitlePanel() {
			super(new BorderLayout());
			setFocusable(false);
			titleLabel = new GDLabel();
			titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 0));
			titleLabel.setForeground(Color.BLACK);
			titleLabel.setFocusable(false);
			add(titleLabel, BorderLayout.CENTER);
		}

		void installRenameAction(MouseListener listener) {
			if (popupMouseListener != null) {
				titleLabel.removeMouseListener(popupMouseListener);
			}

			popupMouseListener = new PopupMouseListener(listener);
			titleLabel.addMouseListener(popupMouseListener);
		}

		@Override
		public void paintComponent(Graphics g) {

			super.paintComponent(g);

			Graphics2D g2d = (Graphics2D) g;
			Rectangle r = getBounds();

			GradientPaint gp;
			if (isSelected) {
				gp = new GradientPaint(r.x, r.y, focusColor, r.x + r.width, r.y, getBackground());
			}
			else {
				gp = new GradientPaint(r.x, r.y, nonFocusColor, r.x + r.width, r.y,
					getBackground());
			}

			g2d.setPaint(gp);
			g2d.fill(r);
		}

		/**
		 * Sets the title to be displayed.
		 * @param s the title to be displayed.
		 */
		void setTitle(String s) {
			titleLabel.setText(s);
			titleLabel.setToolTipText(s);
		}

		void setIcon(Icon icon) {

			icon = DockingUtils.scaleIconAsNeeded(icon);
			if (icon != null) {
				titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 0));
			}
			else {
				titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 0));
			}
			titleLabel.setIcon(icon);

		}

		boolean isSelected() {
			return isSelected;
		}

		JComponent getDragComponent() {
			return titleLabel;
		}

		/**
		 * Sets the focus state.  If in focus use color in the gradient and white lettering.
		 * Otherwise use gray gradient and black lettering.
		 * @param state the focus state.
		 */
		void setSelected(boolean state) {
			isSelected = state;
			titleLabel.setForeground(state ? Color.WHITE : Color.BLACK);
			repaint();
		}

		private class PopupMouseListener extends MouseAdapter {

			private MouseListener popupListenerDelegate;

			PopupMouseListener(MouseListener popupListenerDelegage) {
				this.popupListenerDelegate = popupListenerDelegage;
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				maybePopup(e);
			}

			@Override
			public void mousePressed(MouseEvent e) {
				maybePopup(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybePopup(e);
			}

			private void maybePopup(MouseEvent e) {
				if (!e.isPopupTrigger()) {
					return;
				}

				popupListenerDelegate.mouseClicked(e);
			}
		}
	}
}
