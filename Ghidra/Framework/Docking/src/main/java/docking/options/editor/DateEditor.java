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
import java.beans.*;
import java.text.*;
import java.util.Calendar;
import java.util.Date;

import javax.swing.*;

import com.toedter.calendar.JCalendar;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;

/**
 * Editor for date and time; creates a text field for the string version of the date, and
 * a browse button to pop up the editor panel that contains a JCalendar to edit the date,
 * and a separate component to edit the time.
 */
public class DateEditor extends PropertyEditorSupport {

	public static DateFormat DEFAULT_DATE_FORMAT = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss z");

	private final static int NUMBER_OF_COLUMNS = 20;

	private Date date;
	private CalendarPanel calendarPanel;
	private JTextField textField;
	private EditDateDialog dialog;
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

		if (calendarPanel != null) {
			calendarPanel.setDate(date);
		}

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

	private void displayCalendarEditor(Component parent) {
		if (calendarPanel == null) {
			calendarPanel = new CalendarPanel();
		}
		if (date != null) {
			calendarPanel.setDate(date);
		}
		if (dialog == null) {
			dialog = new EditDateDialog(parent);
		}
		DockingWindowManager.showDialog(parent, dialog);
	}

	private class DatePanel extends JPanel {
		private JButton browseButton;

		DatePanel() {
			BoxLayout bl = new BoxLayout(this, BoxLayout.X_AXIS);
			setLayout(bl);
			textField = new JTextField(NUMBER_OF_COLUMNS);
			textField.setText(date != null ? format(date) : "");
			textField.setEditable(false);
			browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
			Font f = browseButton.getFont();
			f = new Font(f.getName(), Font.BOLD, f.getSize());
			browseButton.setFont(f);

			add(textField);
			add(Box.createHorizontalStrut(5));
			add(browseButton);
			setBorder(BorderFactory.createEmptyBorder());

			browseButton.addActionListener(e -> displayCalendarEditor(browseButton));
		}
	}

	private class CalendarPanel extends JPanel implements PropertyChangeListener {
		private JCalendar jcal;
		private Clock clock;

		// this formatter is just used for parsing dates for input into JCalendar
		private SimpleDateFormat formatter;

		CalendarPanel() {
			super(new BorderLayout(0, 5));
			setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));
			jcal = new JCalendar();
			jcal.addPropertyChangeListener(this);
			clock = new Clock(jcal);
			add(jcal, BorderLayout.CENTER);
			add(clock, BorderLayout.SOUTH);
			formatter = new SimpleDateFormat("MM dd yyyy");
		}

		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			String propertyName = evt.getPropertyName();
			if (propertyName == null || propertyName.equals("calendar")) {
				Calendar newCal = (Calendar) evt.getNewValue();
				Date newDate = newCal.getTime();
				clock.update(newDate);
			}
		}

		@Override
		public Dimension getPreferredSize() {
			return super.getPreferredSize();
		}

		void setDate(Date date) {
			Calendar calendar = jcal.getCalendar();
			Calendar c = (Calendar) calendar.clone();

			//need the month,day, year from the date
			String dateString = formatter.format(date);

			int month = Integer.parseInt(dateString.substring(0, 2));
			int day = Integer.parseInt(dateString.substring(3, 5));
			int year = Integer.parseInt(dateString.substring(6));

			c.set(Calendar.MONTH, month);
			c.set(Calendar.DAY_OF_WEEK, day);
			c.set(Calendar.YEAR, year);
			c.setTime(date);
			jcal.setCalendar(c);

			clock.update(date);
		}
	}

	private class EditDateDialog extends DialogComponentProvider {

		EditDateDialog(Component parent) {
			super("Edit Date", true);
			JPanel dialogPanel = new JPanel();
			dialogPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
			dialogPanel.setLayout(new BorderLayout());
			dialogPanel.add(calendarPanel, BorderLayout.CENTER);
			addWorkPanel(dialogPanel);
			addOKButton();
			addCancelButton();
		}

		/**
		 * Gets called when the user clicks on the OK Action for the dialog.
		 */
		@Override
		protected void okCallback() {
			Date newDate = calendarPanel.jcal.getCalendar().getTime();
			DateEditor.this.setValue(newDate);
			DateEditor.this.firePropertyChange();
			close();
		}

		@Override
		protected void cancelCallback() {
			close();
		}
	}
}
