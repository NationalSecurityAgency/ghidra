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
package docking.widgets.textfield;

import java.awt.*;
import java.awt.event.*;
import java.util.function.Consumer;

import javax.swing.JTextField;
import javax.swing.ToolTipManager;

import docking.DockingUtils;
import docking.util.GraphicsUtils;
import generic.theme.GThemeDefaults.Colors.Messages;
import generic.theme.Gui;

/**
 * Overrides the JTextField mainly to allow hint painting for the current radix mode.
 */
public class HexDecimalModeTextField extends JTextField {

	private static final String FONT_ID = "font.input.hint";
	private int hintWidth;
	private boolean isHexMode;
	private boolean showNumbericDecoration = true;

	public HexDecimalModeTextField(int columns, Consumer<Boolean> modeConsumer) {
		super(columns);

		FontMetrics fontMetrics = getFontMetrics(Gui.getFont(FONT_ID));
		String mode = isHexMode ? "Hex" : "Dec";
		hintWidth = fontMetrics.stringWidth(mode);

		addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_M && DockingUtils.isControlModifier(e)) {
					isHexMode = !isHexMode;
					modeConsumer.accept(isHexMode);
					repaint();
				}
			}
		});

		// make sure tooltips will be activated
		ToolTipManager.sharedInstance().registerComponent(this);
	}

	@Override
	public String getToolTipText(MouseEvent event) {

		int hintStart = getBounds().width - hintWidth;
		if (event.getX() > hintStart) {
			String key = DockingUtils.CONTROL_KEY_NAME;
			return "Press '" + key + "-M' to toggle Hex or Decimal Mode";
		}

		return null;
	}

	public void setHexMode(boolean hexMode) {
		this.isHexMode = hexMode;
	}

	/**
	 * Turns on or off the faded text that displays the field's radix mode (hex or decimal).
	 *
	 * @param show true to show the radix mode.
	 */
	public void setShowNumberMode(boolean show) {
		this.showNumbericDecoration = show;
		repaint();
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		if (!showNumbericDecoration) {
			return;
		}

		Font savedFont = g.getFont();
		g.setFont(Gui.getFont(FONT_ID));
		g.setColor(Messages.HINT);

		Dimension size = getSize();
		Insets insets = getInsets();
		int x;
		if (getHorizontalAlignment() == RIGHT) {
			x = insets.left;
		}
		else {
			x = size.width - insets.right - hintWidth;
		}
		int y = size.height - insets.bottom - 1;
		String mode = isHexMode ? "Hex" : "Dec";
		GraphicsUtils.drawString(this, g, mode, x, y);
		g.setFont(savedFont);
	}

}
