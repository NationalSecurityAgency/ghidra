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

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.docking.util.DockingWindowsLookAndFeelUtils;
import resources.ResourceManager;

/**
 * Class that is a JButton that has an empty border and adds a mouse listener
 * so that the button looks raised when the mouse pointer enters the button,
 * and looks lowered when the mouse pointer exits the button.e
 */
public class EmptyBorderButton extends JButton {

	private ButtonStateListener emptyBorderButtonChangeListener;

	/**
	 * A raised beveled border.
	 */
	public static final Border RAISED_BUTTON_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createRaisedBevelBorder(), BorderFactory.createEmptyBorder(1, 1, 1, 1));

	/**
	 * An empty border.
	 */
	public static final Border NO_BUTTON_BORDER = new EmptyBorder(
		RAISED_BUTTON_BORDER.getBorderInsets(new JButton()));

	/**
	 * A lowered border beveled border.
	 */
	public static final Border LOWERED_BUTTON_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createLoweredBevelBorder(), BorderFactory.createEmptyBorder(1, 1, 1, 1));

	/**
	 * Construct a new EmptyBorderButton.
	 *
	 */
	public EmptyBorderButton() {
		super();
		init();
	}

	/**
	 * Construct a new EmptyBorderButton that has the given button text.
	 * @param text text of the button
	 */
	public EmptyBorderButton(String text) {
		super(text);
		init();
	}

	/**
	 * Construct a new EmptyBorderButton that has an associated action.
	 * @param a action for the button
	 */
	public EmptyBorderButton(Action a) {
		super(a);
		init();
	}

	/**
	 * Construct a new EmptyBorderButton that has an icon.
	 * @param icon icon for the button
	 */
	public EmptyBorderButton(Icon icon) {
		super(icon);
		init();
	}

	/**
	 * Construct a new EmptyBorderButton that has text and an icon.
	 * @param text button text
	 * @param icon icon for the button
	 */
	public EmptyBorderButton(String text, Icon icon) {
		super(text, icon);
		init();
	}

	private void init() {
		ToolTipManager.sharedInstance().registerComponent(this);
		installLookAndFeelFix();
		clearBorder();
		emptyBorderButtonChangeListener = new ButtonStateListener();
		addChangeListener(emptyBorderButtonChangeListener);
	}

	@Override
	public void setIcon(Icon newIcon) {
		Icon disabledIcon = ResourceManager.getDisabledIcon(newIcon);
		setDisabledIcon(disabledIcon);
		super.setIcon(newIcon);
	}

	private void installLookAndFeelFix() {
		// We want our custom buttons to paint themselves blended with the background.  Several 
		// LookAndFeels do not do this (WinXP and Metal), so we override that behavior here.
		setContentAreaFilled(false);
		setOpaque(true);

		// Mac OSX LNF doesn't give us rollover callbacks, so we have to add a mouse listener to
		// do the work
		if (DockingWindowsLookAndFeelUtils.isUsingAquaUI(getUI())) {
			addMouseListener(new MouseAdapter() {
				@Override
				public void mouseEntered(MouseEvent e) {
					if (e.getButton() == MouseEvent.NOBUTTON) {
						raiseBorder();
					}
				}

				@Override
				public void mouseExited(MouseEvent e) {
					clearBorder();
				}
			});
		}
	}

	public void raiseBorder() {
		setBorder(getRaisedBorder());
	}

	public void clearBorder() {
		setBorder(NO_BUTTON_BORDER);
	}

	protected void updateBorderBasedOnState() {
		if (!isEnabled()) {
			return;
		}

		ButtonModel buttonModel = getModel();
		boolean pressed = buttonModel.isPressed();
		boolean rollover = buttonModel.isRollover();
		boolean armed = buttonModel.isArmed();

		if (pressed && (rollover || armed)) {
			setBorder(getLoweredBorder());
		}
		else if (rollover) {
			setBorder(getRaisedBorder());
		}
		else {
			setBorder(NO_BUTTON_BORDER);
		}
	}

	protected Border getRaisedBorder() {
		return RAISED_BUTTON_BORDER;
	}

	protected Border getLoweredBorder() {
		return LOWERED_BUTTON_BORDER;
	}

	public void removeListeners() {
		removeChangeListener(emptyBorderButtonChangeListener);
	}

	private class ButtonStateListener implements ChangeListener {
		@Override
		public void stateChanged(ChangeEvent e) {
			updateBorderBasedOnState();
		}
	}
}
