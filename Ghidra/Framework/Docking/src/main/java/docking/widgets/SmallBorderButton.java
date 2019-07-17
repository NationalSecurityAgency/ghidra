/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * Class that is a JButton that has an empty border and adds a mouse listener
 * so that the button looks raised when the mouse pointer enters the button,
 * and looks lowered when the mouse pointer exits the button. 
 *
 */ 
public class SmallBorderButton extends JButton {
	
	/**
	 * A raised beveled border.
	 */
    public static final Border RAISED_BORDER = BorderFactory.createCompoundBorder(
				BorderFactory.createRaisedBevelBorder(),
				BorderFactory.createEmptyBorder(1,1,1,1));
    /**
     * An empty border.
     */
//    public static final Border NO_BORDER = new EmptyBorder(RAISED_BORDER.getBorderInsets(new JButton()));
    public static final Border NO_BORDER = RAISED_BORDER;
    
    /**
     * A lowered border beveled border.
     */
    public static final Border LOWERED_BORDER = BorderFactory.createCompoundBorder(
				BorderFactory.createLoweredBevelBorder(),
				BorderFactory.createEmptyBorder(1,1,1,1));

	private Border overrideBorder;

	/**
	 * Construct a new EmptyBorderButton.
	 *
	 */
	public SmallBorderButton() {
		super();
		initBorder();
	}

	/**
	 * Construct a new EmptyBorderButton that has the given button text.
	 * @param text text of the button
	 */
	public SmallBorderButton(String text) {
		super(text);
		initBorder();
	}

	/**
	 * Construct a new EmptyBorderButton that has an associated action.
	 * @param a action for the button
	 */
	public SmallBorderButton(Action a) {
		super(a);
		initBorder();
	}

	/**
	 * Construct a new EmptyBorderButton that has an icon.
	 * @param icon icon for the button
	 */
	public SmallBorderButton(Icon icon) {
		super(icon);
		initBorder();
	}

	/**
	 * Construct a new EmptyBorderButton that has text and an icon.
	 * @param text button text
	 * @param icon icon for the button
	 */
	public SmallBorderButton(String text, Icon icon) {
		super(text, icon);
		initBorder();
	}

	private void initBorder() {
		clearBorder();
		addMouseListener(new ButtonMouseListener());
	}

	/**
	 * Clear the border on this button and set it to NO_BORDER.
	 *
	 */
	public void clearBorder() {
		setBorder(NO_BORDER);
	}

	/**
	 * Override the default border created by this button.
	 * @param overrideBorder new border to use
	 */
	public void setOverrideBorder(Border overrideBorder) {
	    this.overrideBorder = overrideBorder;
	}

	/**
	 * Mouse listener on the button to render it appropriately.
	 */
	private class ButtonMouseListener extends MouseAdapter {
		private boolean inside = false;

		@Override
        public void mouseEntered(MouseEvent me)  {
			if (isEnabled()) {
				setBorder(RAISED_BORDER);
				inside = true;
			}
		}

		@Override
        public void mouseExited(MouseEvent me)  {
			inside = false;
			setBorder(NO_BORDER);
			if (overrideBorder != null) {
			    setBorder(overrideBorder);
			}
		}

		@Override
        public void mousePressed(MouseEvent e) {
			if (isEnabled()) {
				setBorder(LOWERED_BORDER);
			}
		}

		@Override
        public void mouseReleased(MouseEvent e) {
			if (inside) {
				setBorder(RAISED_BORDER);
			}
			else {
				setBorder(NO_BORDER);
			}
			if (overrideBorder != null) {
			    setBorder(overrideBorder);
			}
		}
	}
	
}
