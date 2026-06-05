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
package docking.widgets.textfield.integer;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.JTextField;
import javax.swing.ToolTipManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import docking.DockingUtils;
import docking.util.GraphicsUtils;
import generic.theme.GThemeDefaults.Colors.Messages;
import generic.theme.Gui;
import utility.function.Callback;

/**
 * Overrides the JTextField mainly to allow hint painting for the current input format. It also
 * handles processing control-M to switch modes.
 */
public class MultiFormatTextField extends JTextField {

	private static final String FONT_ID = "font.input.hint";
	private int hintWidth;
	private boolean showFormatHint = true;
	private List<IntegerFormat> formats;
	private int currentFormatIndex;

	public MultiFormatTextField(int columns, List<IntegerFormat> formats,
			Consumer<IntegerFormat> formatChangeConsumer) {
		super(columns);

		this.formats = formats;
		updateFormatNameWidth();

		addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_M && DockingUtils.isControlModifier(e)) {
					if (++currentFormatIndex >= formats.size()) {
						currentFormatIndex = 0;
					}
					updateFormatNameWidth();
					formatChangeConsumer.accept(formats.get(currentFormatIndex));
					repaint();
				}
			}
		});

		// make sure tooltips will be activated
		ToolTipManager.sharedInstance().registerComponent(this);

	}

	/**
	 * Uses the given callback to notify the client when the text has changed in this text field.
	 * @param c the callback to be notified when the text changes in this field
	 */
	public void addTextChangedCallback(Callback c) {
		Document document = getDocument();

		document.addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				c.call();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				c.call();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				c.call();
			}
		});
	}

	private void updateFormatNameWidth() {
		FontMetrics fontMetrics = getFontMetrics(Gui.getFont(FONT_ID));
		hintWidth = fontMetrics.stringWidth(formats.get(currentFormatIndex).getName());

	}

	@Override
	public String getToolTipText(MouseEvent event) {

		int hintStart = getBounds().width - hintWidth;

		if (event.getX() > hintStart && formats.size() > 1) {
			String key = DockingUtils.CONTROL_KEY_NAME;
			IntegerFormat format = formats.get(currentFormatIndex);
			return "Enter value in %s format. Press %s-M to cycle input formats."
					.formatted(format.getDescription(), key);
		}

		return super.getToolTipText(event);
	}

	/**
	 * Sets the {@link IntegerFormat} that will be used to format and parse the text in this
	 * field.
	 * @param format the number format that will be used to format and parse the text in this field
	 */
	public void setFormat(IntegerFormat format) {
		int indexOf = formats.indexOf(format);
		if (indexOf >= 0) {
			currentFormatIndex = indexOf;
		}
		updateFormatNameWidth();
		repaint();
	}

	/**
	 * Turns on or off the faded hint text that displays the field's current format (i.e., hex,
	 * decimal).
	 *
	 * @param show true to show the input format.
	 */
	public void setShowInputFormatHint(boolean show) {
		this.showFormatHint = show;
		repaint();
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		if (!showFormatHint) {
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
		IntegerFormat format = formats.get(currentFormatIndex);
		GraphicsUtils.drawString(this, g, format.getName(), x, y);
		g.setFont(savedFont);
	}

}
