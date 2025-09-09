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
package docking.widgets.filechooser;

import java.awt.Color;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.io.File;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;

public class FileChooserToggleButton extends JToggleButton {

	//
	// All border sizes are based on trial-and-error, adjusted to prevent the UI from moving as the 
	// user hovers and moves around with the keyboard.
	//
	private static final Border RAISED_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createRaisedBevelBorder(), BorderFactory.createEmptyBorder(2, 2, 2, 2));

	private static final Border LOWERED_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createLoweredBevelBorder(), BorderFactory.createEmptyBorder(2, 2, 2, 2));

	// The focused border is a blue line with some padding on the outside so it is easy to see when
	// the button has focus.  This is similar to other buttons in the system.
	private static final Color FOCUS_COLOR = new GColor("color.border.button.focused");
	private static final Border FOCUSED_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createEmptyBorder(1, 1, 1, 1), BorderFactory.createLineBorder(FOCUS_COLOR));
	private static final Border UNFOCUSED_BORDER = BorderFactory.createEmptyBorder(2, 2, 2, 2);

	private static final Border NO_BORDER = new EmptyBorder(4, 4, 4, 4);

	private GhidraFileChooser fileChooser;

	public FileChooserToggleButton(String text, GhidraFileChooser fileChooser) {
		super(text);
		this.fileChooser = fileChooser;
		initBorder();
	}

	private void initBorder() {
		setForeground(Colors.BACKGROUND);
		setOpaque(true);
		setHorizontalTextPosition(SwingConstants.CENTER);
		setVerticalTextPosition(SwingConstants.BOTTOM);
		clearBorder();

		// prevents the WinXP LNF from painting its awkward borders
		setContentAreaFilled(false);

		// changes the border on hover and click
		addChangeListener(new ButtonStateListener());

		// works in conjunction with the mouse listener to properly set the border
		addChangeListener(e -> updateBorderBasedOnState());

		addFocusListener(new ButtonFocusListener());

		updateBorderBasedOnState();
	}

	@Override
	public void setBorder(Border border) {
		// To keep UI from installing an incorrect border (such as when switching themes),
		// only allow borders created by this class to be set.
		if (border == RAISED_BORDER || border == LOWERED_BORDER || border == NO_BORDER ||
			border instanceof FocusedBorder) {
			super.setBorder(border);
		}
	}

	private void clearBorder() {
		setBorder(NO_BORDER);
	}

	/** {@return Returns the directory with which this button is associated.} */
	File getFile() {
		return null;
	}

	private void updateBorderBasedOnState() {
		if (!isEnabled()) {
			return;
		}

		ButtonModel buttonModel = getModel();
		boolean pressed = buttonModel.isPressed();
		boolean rollover = buttonModel.isRollover();
		boolean armed = buttonModel.isArmed();
		boolean selected = buttonModel.isSelected();

		Border border = NO_BORDER;

		if (selected) {
			border = LOWERED_BORDER;
		}
		else if (pressed && (rollover || armed)) {
			border = LOWERED_BORDER;
		}
		else if (rollover) {
			border = RAISED_BORDER;
		}

		border = createFocusedBorder(border, isFocusOwner());

		setBorder(border);
	}

	private Border createFocusedBorder(Border outside, boolean isFocused) {
		Border inside = isFocused ? FOCUSED_BORDER : UNFOCUSED_BORDER;
		return new FocusedBorder(outside, inside);
	}

	private class ButtonStateListener implements ChangeListener {
		@Override
		public void stateChanged(ChangeEvent e) {
			updateBorderBasedOnState();
		}
	}

	private class ButtonFocusListener implements FocusListener {

		@Override
		public void focusGained(FocusEvent e) {
			updateBorderBasedOnState();
		}

		@Override
		public void focusLost(FocusEvent e) {
			updateBorderBasedOnState();
			fileChooser.updateShortcutPanel();
		}
	}

	private class FocusedBorder extends CompoundBorder {
		FocusedBorder(Border outsideBorder, Border insideBorder) {
			super(outsideBorder, insideBorder);
		}
	}
}
