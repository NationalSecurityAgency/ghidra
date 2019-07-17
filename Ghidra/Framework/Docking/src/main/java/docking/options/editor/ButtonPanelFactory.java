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
package docking.options.editor;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.Border;

import resources.ResourceManager;

/**
 * Class with static methods to create a JButton with a raised bevel border,
 * and to create a JPanel with buttons created by calling the 
 * createButton() method.
 */
public class ButtonPanelFactory {

	private ButtonPanelFactory() {
	}

	/**
	 * layout the buttons on the panel created with createButtonPanel()
	 * horizontally along the X-axis
	 */
	public final static char X_AXIS = '0';
	/**
	 * layout the buttons on the panel created with createButtonPanel()
	 * vertically along the Y-axis
	 */
	public final static char Y_AXIS = '1';

	/*
	 * types of buttons you can request from the factory that have
	 * been pre-configured using our convention
	 */
	/**
	 * Button that has an up arrow.
	 */
	public final static int ARROW_UP_TYPE = 0;
	/**
	 * Button that has a down arrow.
	 */
	public final static int ARROW_DOWN_TYPE = 1;
	/**
	 * Button that indicates a file chooser to browse.
	 */
	public final static int BROWSE_TYPE = 2;
	/**
	 * Button for cancel.
	 */
	public final static int CANCEL_TYPE = 3;
	/**
	 * Button that indicates an edit operation.
	 */
	public final static int EDIT_TYPE = 4;
	/**
	 * Button for OK.
	 */
	public final static int OK_TYPE = 5;
	/** 
	 * Button that has a left arrow.
	 */
	public final static int ARROW_LEFT_TYPE = 6;
	/**
	 * Button that has a right arrow.
	 */
	public final static int ARROW_RIGHT_TYPE = 7;

	/*
	 * values used to construct various button types, as defined
	 * above.  These constants may be useful outside the factory when
	 * the factory can't be used (e.g., when using StringInputPanel).
	 */
	/**
	 * Dimension for the arrow button.
	 */
	public final static Dimension ARROW_SIZE = new Dimension(32, 32);
	/**
	 * Dimension for the browse button.
	 */
	public final static Dimension BROWSE_SIZE = new Dimension(30, 25);
	/**
	 * Text for the browse button.
	 */
	public final static Icon BROWSE_ICON = new Icon() {
		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(Color.BLACK);
			g.fillRect(x, y + 5, 2, 2);
			g.fillRect(x + 4, y + 5, 2, 2);
			g.fillRect(x + 8, y + 5, 2, 2);
		}

		@Override
		public int getIconWidth() {
			return 10;
		}

		@Override
		public int getIconHeight() {
			return 10;
		}
	};
	/**
	 * Font for the browse button label.
	 */
	public final static Font BROWSE_FONT = new Font("Dialog", Font.BOLD, 12);

	/**
	 * internal values used when creating the panels and buttons
	 */
	private final static int TOP_MARGIN = 8;
	private final static int BOTTOM_MARGIN = 8;
	private final static int SIDE_MARGIN = 20;
//    private final static int BUTTON_MARGIN      = 4;
	private final static int BUTTON_GAP = 10;
	private final static String CANCEL_LABEL = "Cancel";
	private final static String OK_LABEL = "Ok";
	private final static String UNTITLED = "Untitled Button";
	private static final String BROWSE_TOOLTIP_TEXT = "Browse";

	/**
	 * Create a button with specified type.
	 * @param buttonType the type of button to create.
	 */
	public static JButton createButton(int buttonType) {
		switch (buttonType) {
			case ARROW_DOWN_TYPE:
				return createImageButton("images/down.png", "DOWN", ARROW_SIZE);
			case ARROW_UP_TYPE:
				return createImageButton("images/up.png", "UP", ARROW_SIZE);
			case ARROW_LEFT_TYPE:
				return createImageButton("images/left.png", "LEFT", ARROW_SIZE);
			case ARROW_RIGHT_TYPE:
				return createImageButton("images/right.png", "RIGHT", ARROW_SIZE);
			case BROWSE_TYPE:
				return createBrowseButton();
			case CANCEL_TYPE:
				return createButton(CANCEL_LABEL);
			case EDIT_TYPE:
				return createImageButton("images/accessories-text-editor.png", "Edit", BROWSE_SIZE);
			case OK_TYPE:
				return createButton(OK_LABEL);
			default:
				return createButton(UNTITLED);
		}
	}

	/**
	 * Create a button with the given text.
	 * @param text the text to use in the button.
	 */
	public static JButton createButton(String text) {
		return new JButton(text);
	}

	/**
	 * Create the panel for the buttons; the button are aligned vertically;
	 * the side margins on the panel has a default value of 20.
	 * @param buttons the array of buttons to put in the panel.
	 */
	public static JPanel createButtonPanel(JButton[] buttons) {
		return createButtonPanel(buttons, SIDE_MARGIN, Y_AXIS);
	}

	/**
	 * Create the panel for the buttons; the button are aligned as specified;
	 * the side margins on the panel has a default value of 20.
	 * @param buttons the array buttons to put in the panel.
	 * @param alignment either X_AXIS or Y_AXIS
	 */
	public static JPanel createButtonPanel(JButton[] buttons, char alignment) {
		return createButtonPanel(buttons, SIDE_MARGIN, alignment);
	}

	/**
	 * Create the panel for the buttons; the button are aligned vertically;
	 * use sideMargin value for side margins on the panel.
	 * @param buttons the array buttons to put in the panel.
	 * @param sideMargin the amount of margin space to use on the sides.
	 */
	public static JPanel createButtonPanel(JButton[] buttons, int sideMargin) {
		return createButtonPanel(buttons, sideMargin, Y_AXIS);
	}

	/**
	 * Create the panel for the buttons; the button are aligned as specified;
	 * use sideMargin value for side margins on the panel, and use either
	 * X_AXIS or Y_AXIS as the alignment specification.
	 * @param buttons the array buttons to put in the panel.
	 * @param alignment either X_AXIS or Y_AXIS
	 */
	public static JPanel createButtonPanel(JButton[] buttons, int sideMargin, char alignment) {
		JPanel panel = new JPanel();
		JPanel subPanel = new JPanel();
		panel.add(subPanel);

		subPanel.setLayout((alignment == Y_AXIS ? new GridLayout(0, 1, 0, BUTTON_GAP)
				: new GridLayout(1, 0, BUTTON_GAP, 0)));

		Border inside =
			BorderFactory.createEmptyBorder(TOP_MARGIN, sideMargin, BOTTOM_MARGIN, sideMargin);
		subPanel.setBorder(inside);

		for (JButton button : buttons) {
			subPanel.add(button);
		}
		return panel;
	}

	/**
	 * Create an button that has an icon created from the given imageFile.
	 * @param imageFile icon filename
	 * @param alternateText text to use if the icon could not be loaded 
	 * @param preferredSize size that the button would like to be
	 * @return JButton new button
	 */
	public static JButton createImageButton(String imageFile, String alternateText,
			Dimension preferredSize) {

		ImageIcon buttonIcon = ResourceManager.loadImage(imageFile);
		return createImageButton(buttonIcon, alternateText, preferredSize);
	}

	/**
	 * Create a button with the given icon.
	 * @param buttonIcon icon for the button
	 * @param alternateText text to use if the icon could not be loaded
	 * @param preferredSize size that the button would like to be
	 * @return JButton new button
	 */
	public static JButton createImageButton(ImageIcon buttonIcon, String alternateText,
			Dimension preferredSize) {

		JButton button = ButtonPanelFactory.createButton("");
		if (buttonIcon != null) {
			button.setIcon(buttonIcon);
		}
		else {
			button.setText(alternateText);
		}
		button.setPreferredSize(preferredSize);

		return button;
	}

	private static JButton createBrowseButton() {

		JButton button = new JButton(BROWSE_ICON);
		button.setName("BrowseButton");

		button.setToolTipText(BROWSE_TOOLTIP_TEXT);

		return button;
	}
}
