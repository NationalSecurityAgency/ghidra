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
/**
 *
 */
package docking.widgets.textfield;

import java.awt.*;
import java.awt.event.ActionListener;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JTextField;
import javax.swing.event.*;

import docking.util.GraphicsUtils;
import ghidra.util.SystemUtilities;

/**
 * Text field for entering dates. Optionally, a minimum and maximum date value can be set on this
 * text field.
 */
public class LocalDateTextField {

	private JTextField textField;

	private LocalDate minimum;
	private LocalDate maximum;

	private DateTimeFormatter dateFormat = null;

	private List<ChangeListener> listeners = new ArrayList<>();

	private static final String MONTH_LABEL = "Month";
	private static final String DAY_LABEL = "Day";

	private boolean isMonthMode = false;

	private boolean showFieldDecoration = true;

	public LocalDateTextField(String dateFormatPattern) {

		textField = new MyTextField();

		dateFormat = DateTimeFormatter.ofPattern(dateFormatPattern);

		setDayMode();

		textField.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				update();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				update();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				update();
			}
		});
	}

	private void update() {
		// We are in the DocumentListener so the document is locked and cant' be modified.
		// Use invokeLater so that listeners can make updates.
		SystemUtilities.runSwingLater(() -> notifyListeners());
	}

	private void notifyListeners() {
		for (ChangeListener changeListener : listeners) {
			changeListener.stateChanged(null);
		}
	}

	/**
	 * Sets the minimum allowed date. Can be null.
	 * @param minimum the minimum allowed date.
	 */
	public void setMinimum(LocalDate minimum) {
		this.minimum = minimum;
	}

	/**
	 * Sets the maximum allowed date. Can be null.
	 * @param maximum the minimum allowed date.
	 */
	public void setMaximum(LocalDate maximum) {
		this.maximum = maximum;
	}

	public void setValue(LocalDate newDate) {

		if (newDate == null) {
			return;
		}

		if (minimum != null && minimum.compareTo(newDate) > 0) {
			throw new IllegalArgumentException("value is before the minimum allowed date!");
		}
		if (maximum != null && maximum.compareTo(newDate) < 0) {
			throw new IllegalArgumentException("value is after the maximum allowed date!");
		}

		if (!newDate.equals(getValue())) {
			setText(dateFormat.format(newDate));
		}

	}

	public LocalDate getValue() {
		String str = textField.getText();
		try {
			return LocalDate.parse(str, dateFormat);
		}
		catch (DateTimeParseException pe) {
			return null;
		}
	}

	public LocalDate getMinimum() {
		return minimum;
	}

	public LocalDate getMaximum() {
		return maximum;
	}

	/**
	 * Turns on or off the faded text that indicates if the field is in month or day mode
	 * @param show true to show the mode.
	 */
	public void setShowFieldMode(boolean show) {
		this.showFieldDecoration = show;
		textField.repaint();
	}

	public boolean isShowingFieldMode() {
		return showFieldDecoration;
	}

	/**
	 * Sets the mode to Month.
	 */
	public void setMonthMode() {
		isMonthMode = true;
		textField.repaint();
	}

	/**
	 * Sets the mode to Day.
	 */
	public void setDayMode() {
		isMonthMode = false;
		textField.repaint();
	}

	private void setText(String str) {
		textField.setText(str);
	}

	public JTextField getTextField() {
		return textField;
	}

	public JComponent getComponent() {
		return textField;
	}

	public void setEnabled(boolean enabled) {
		textField.setEnabled(enabled);
	}

	public void requestFocus() {
		textField.requestFocus();
	}

	public void selectAll() {
		textField.selectAll();
	}

	public void addActionListener(ActionListener listener) {
		textField.addActionListener(listener);
	}

	public void removeActionListener(ActionListener listener) {
		textField.removeActionListener(listener);
	}

	/**
	 * Adds a change listener that will be notified whenever the value changes.
	 * @param listener the change listener to add.
	 */
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes the changes listener.
	 * @param listener the listener to be removed.
	 */
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private class MyTextField extends JTextField {

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);

			if (showFieldDecoration) {
				Font font = new Font("Monospaced", Font.PLAIN, 10);
				Font savedFont = g.getFont();
				g.setFont(font);
				g.setColor(Color.LIGHT_GRAY);
				FontMetrics fontMetrics = getFontMetrics(font);
				String label = isMonthMode ? MONTH_LABEL : DAY_LABEL;
				int stringWidth = fontMetrics.stringWidth(label);
				Dimension size = getSize();
				Insets insets = getInsets();
				int x = size.width - insets.right - stringWidth;
				int y = size.height - insets.bottom;
				GraphicsUtils.drawString(this, g, label, x, y);
				g.setFont(savedFont);
			}
		}
	}

}
