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

import java.awt.Color;
import java.awt.Toolkit;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;

import com.toedter.calendar.JCalendar;

import ghidra.util.layout.HorizontalLayout;

/**
 * A simple set of label and text fields to show the current time and allow for editing
 */
class Clock extends JPanel implements CaretListener {

	private JLabel dateLabel = new JLabel("Apr 18, 2006");
	private JTextField hoursField;
	private JTextField minutesField;
	private JTextField secondsField;
	private SimpleDateFormat formatter;
	private DocumentListener docListener;
	private boolean isEditing;
	private JTextField currentEditField;

	private int min;
	private int max;
	private int value;
	private Color defaultBackgroundColor;
	private static Color CURRENT_BACKGROUND_COLOR = new Color(204, 204, 255);

	private JCalendar jCalendar;

	/**
	 * Construct a new Clock.
	 * @param calendar JCalendar component that has the Calendar object being edited.
	 */
	Clock(JCalendar calendar) {
		super(new HorizontalLayout(1));
		this.jCalendar = calendar;
		setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		create();
	}

	@Override
	public void caretUpdate(CaretEvent e) {

		JTextField tf = (JTextField) e.getSource();
		Document doc = tf.getDocument();
		max = 59;
		if (hoursField.getDocument() == doc) {
			max = 23;
			currentEditField = hoursField;
			updateColors(minutesField);
			updateColors(secondsField);
		}
		else if (minutesField.getDocument() == doc) {
			currentEditField = minutesField;
			updateColors(hoursField);
			updateColors(secondsField);
		}
		else {
			currentEditField = secondsField;
			updateColors(hoursField);
			updateColors(minutesField);
		}
		currentEditField.setBackground(CURRENT_BACKGROUND_COLOR);
	}

	/*
	 * Update the text fields that show the time.
	 */
	void update(Date date) {
		if (isEditing) {
			return;
		}
		removeDocumentListeners();
		try {
			String dateStr = formatter.format(date);

			dateLabel.setText(getDate(dateStr) + "  ");
			hoursField.setText(getHours(dateStr));
			minutesField.setText(getMinutes(dateStr));
			secondsField.setText(getSeconds(dateStr));
		}
		finally {
			addDocumentListeners();
		}
		if (currentEditField != null) {
			setValue(Integer.parseInt(currentEditField.getText()), false);
		}
	}

	private void create() {
		hoursField = new JTextField(2);
		minutesField = new JTextField(2);
		secondsField = new JTextField(2);

		hoursField.addCaretListener(this);
		minutesField.addCaretListener(this);
		secondsField.addCaretListener(this);

		// junit access
		hoursField.setName("Hours");
		minutesField.setName("Minutes");
		secondsField.setName("Seconds");
		dateLabel.setName("DateString");

		min = 0;
		max = 60;
		value = 0;

		add(dateLabel);
		add(hoursField);
		add(new JLabel(":"));
		add(minutesField);
		add(new JLabel(":"));
		add(secondsField);

		formatter = new SimpleDateFormat("HH:mm:ss MMM dd, yyyy");
		hoursField.setDocument(new TimeDocument(true));
		minutesField.setDocument(new TimeDocument(false));
		secondsField.setDocument(new TimeDocument(false));
		Calendar cal = Calendar.getInstance();
		Date date = cal.getTime();
		update(date);

		docListener = new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				checkInput(e);
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				checkInput(e);
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				checkInput(e);
			}

		};
		addDocumentListeners();
		defaultBackgroundColor = hoursField.getBackground();
	}

	private void addDocumentListeners() {
		hoursField.getDocument().addDocumentListener(docListener);
		minutesField.getDocument().addDocumentListener(docListener);
		secondsField.getDocument().addDocumentListener(docListener);
	}

	private void removeDocumentListeners() {
		hoursField.getDocument().removeDocumentListener(docListener);
		minutesField.getDocument().removeDocumentListener(docListener);
		secondsField.getDocument().removeDocumentListener(docListener);

	}

	private void checkInput(DocumentEvent e) {
		isEditing = true;
		Calendar cal = jCalendar.getCalendar();
		try {
			int hourValue = Integer.parseInt(hoursField.getText());
			int minutesValue = Integer.parseInt(minutesField.getText());
			int secondsValue = Integer.parseInt(secondsField.getText());
			if (hourValue >= 0 && hourValue <= 23 && minutesValue >= 0 && minutesValue <= 59 &&
				secondsValue >= 0 && secondsValue <= 59) {
				cal.set(Calendar.HOUR_OF_DAY, hourValue);
				cal.set(Calendar.MINUTE, minutesValue);
				cal.set(Calendar.SECOND, secondsValue);
			}
		}
		catch (NumberFormatException exc) {
			// this can happen for the empty string
		}
		finally {
			isEditing = false;
		}
	}

	private void updateColors(JTextField field) {
		field.setBackground(defaultBackgroundColor);
	}

	private void setValue(int newValue, boolean updateTextField) {

		if (newValue < min) {
			value = min;
		}
		else if (newValue > max) {
			value = max;
		}
		else {
			value = newValue;
		}

		if (updateTextField) {
			String str = Integer.toString(value);
			if (str.length() < 2) {
				str = "0" + str;
			}
			currentEditField.setText(str);
		}
	}

	private String getHours(String dateStr) {
		int pos = dateStr.indexOf(":");
		return dateStr.substring(0, pos);
	}

	private String getMinutes(String dateStr) {
		return dateStr.substring(3, 5);
	}

	private String getSeconds(String dateStr) {
		return dateStr.substring(6, 8);
	}

	private String getDate(String dateStr) {
		int pos = dateStr.indexOf(" ");
		return dateStr.substring(pos + 1);
	}

	private class TimeDocument extends PlainDocument {

		private boolean isHours;

		TimeDocument(boolean isHours) {
			super();
			this.isHours = isHours;
		}

		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
			char[] source = str.toCharArray();
			char[] result = new char[source.length];
			int j = 0;
			for (int i = 0; i < result.length; i++) {
				if (Character.isDigit(source[i]) && isValidDigit(source[i])) {
					result[j++] = source[i];
				}
				else {
					Toolkit.getDefaultToolkit().beep();
				}
				String s = this.getText(0, getLength());
				try {
					if (s.length() > 0) {
						if (offs == 0) {
							s = str + s;
						}
						else {
							s = s + str;
						}
						int numericValue = Integer.parseInt(s);
						if (s.length() > 2 ||
							(isHours && (numericValue < 0 || numericValue > 23)) ||
							(!isHours && (numericValue < 0 || numericValue >= 60))) {
							Toolkit.getDefaultToolkit().beep();
							return;
						}
					}
				}
				catch (NumberFormatException e) {
					Toolkit.getDefaultToolkit().beep();
					return;
				}
			}
			super.insertString(offs, new String(result, 0, j), a);
		}

		private boolean isValidDigit(char c) {
			return c >= 0x30 && c <= 0x39;
		}

	}

}
