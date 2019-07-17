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

import java.awt.Component;
import java.beans.PropertyEditorSupport;
import java.text.*;
import java.util.Date;

import javax.swing.*;

/**
 * Non-editable Editor for date and time; creates a text field for the string version of the date.
 */
public class DateEditor extends PropertyEditorSupport {

	public static DateFormat DEFAULT_DATE_FORMAT = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss z");

	private final static int NUMBER_OF_COLUMNS = 20;

	private Date date;
	private JTextField textField;
	private DateFormat dateFormat = DEFAULT_DATE_FORMAT;

	public void setDateFormat(DateFormat format) {
		this.dateFormat = format;

		// reformat the date in the display
		if (textField != null) {
			textField.setText(format(date));
		}
	}

	public synchronized String format(Date d) {
		return dateFormat.format(d);
	}

	@Override
	public Component getCustomEditor() {
		return new DatePanel();
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Object getValue() {
		return date;
	}

	@Override
	public void setValue(Object value) {
		if (date != null && date.equals(value)) {
			return;
		}

		this.date = (Date) value;

		if (textField != null) {
			textField.setText(format(date));
		}
	}

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		try {
			Date newDate = dateFormat.parse(text);
			setValue(newDate);
		}
		catch (ParseException e) {
			throw new IllegalArgumentException("Can't parse text as date: " + text);
		}
	}

	private class DatePanel extends JPanel {
		private JButton browseButton;

		DatePanel() {
			BoxLayout bl = new BoxLayout(this, BoxLayout.X_AXIS);
			setLayout(bl);
			textField = new JTextField(NUMBER_OF_COLUMNS);
			textField.setText(date != null ? format(date) : "");
			textField.setEditable(false);

			add(textField);
		}
	}

}
