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

import java.awt.*;
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
     * An empty border.
     */
    public static final Border NO_BORDER = BorderFactory.createEmptyBorder(1,1,1,1);


	/**
	 * Construct a new EmptyBorderButton.
	 *
	 */
	public SmallBorderButton() {
		super();
		initBackground();
	}

	/**
	 * Construct a new EmptyBorderButton that has the given button text.
	 * @param text text of the button
	 */
	public SmallBorderButton(String text) {
		super(text);
		initBackground();
	}

	/**
	 * Construct a new EmptyBorderButton that has an associated action.
	 * @param a action for the button
	 */
	public SmallBorderButton(Action a) {
		super(a);
		initBackground();
	}

	/**
	 * Construct a new EmptyBorderButton that has an icon.
	 * @param icon icon for the button
	 */
	public SmallBorderButton(Icon icon) {
		super(icon);
		initBackground();
	}

	/**
	 * Construct a new EmptyBorderButton that has text and an icon.
	 * @param text button text
	 * @param icon icon for the button
	 */
	public SmallBorderButton(String text, Icon icon) {
		super(text, icon);
		initBackground();
	}

	private void initBackground() {
		clearBackground();
		addMouseListener(new ButtonMouseListener());
	}

	/**
	 * Clear the border on this button and set it to NO_BORDER.
	 *
	 */
	public void clearBorder() {
		setBorder(NO_BORDER);
	}

	public void setFocusBackground(){
		setBackground(Color.lightGray);
	}

	public void setPressBackground(){
		setBackground(Color.GRAY);
	}

	public void clearBackground() {
		setBackground(Color.DARK_GRAY);
	}

	/**
	 * Mouse listener on the button to render it appropriately.
	 */
	private class ButtonMouseListener extends MouseAdapter {
		private boolean inside = false;

		@Override
        public void mouseEntered(MouseEvent me)  {
			if (isEnabled()) {
				setFocusBackground();
				inside = true;
			}
		}

		@Override
        public void mouseExited(MouseEvent me)  {
			inside = false;
			setBorder(NO_BORDER);
			clearBackground();
		}

		@Override
        public void mousePressed(MouseEvent e) {
			if (isEnabled()) {
				setPressBackground();
			}
		}

		@Override
        public void mouseReleased(MouseEvent e) {
			if (inside) {
				setFocusBackground();
			}
			else {
				setBorder(NO_BORDER);
				clearBackground();
			}
		}
	}
	
}
