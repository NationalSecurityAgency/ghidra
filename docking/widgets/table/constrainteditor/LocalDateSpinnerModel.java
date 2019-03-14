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
package docking.widgets.table.constrainteditor;

import java.time.LocalDate;
import java.util.Calendar;

import javax.swing.AbstractSpinnerModel;

/**
 * Spinner Model for LocalDate
 */
public class LocalDateSpinnerModel extends AbstractSpinnerModel {

	private LocalDate currentValue;
	private int calendarField;
	private LocalDate minDate;
	private LocalDate maxDate;

	/**
	 * Constructor
	 *
	 * @param value initial value for spinner model
	 * @param minDate minimum value for spinner model. (Can be null)
	 * @param maxDate maximum value for spinner model. (Can be null)
	 * @param calendarField specifies the year, month, or day to increment/decrement. One of:
	 *  <ul>
	 *    <li><code>Calendar.YEAR</code>
	 *    <li><code>Calendar.MONTH</code>
	 *    <li><code>Calendar.DAY_OF_MONTH</code>
	 *  </ul>
	 * <p>
	 */
	public LocalDateSpinnerModel(LocalDate value, LocalDate minDate, LocalDate maxDate,
			int calendarField) {
		this.currentValue = value;
		this.minDate = minDate;
		this.maxDate = maxDate;
		checkIsValidCalendarField(calendarField);
		this.calendarField = calendarField;
	}

	@Override
	public Object getValue() {
		return currentValue;
	}

	@Override
	public void setValue(Object value) {
		if (value.equals(currentValue)) {
			return;
		}
		currentValue = (LocalDate) value;
		fireStateChanged();
	}

	@Override
	public Object getNextValue() {
		LocalDate nextDate = null;
		switch (calendarField) {
			case Calendar.DAY_OF_MONTH:
				nextDate = currentValue.plusDays(1);
				break;
			case Calendar.MONTH:
				nextDate = currentValue.plusMonths(1);
				break;
			case Calendar.YEAR:
				nextDate = currentValue.plusYears(1);
				break;
		}
		if (minDate != null && minDate.compareTo(nextDate) < 0) {
			return nextDate;
		}
		return null;
	}

	@Override
	public Object getPreviousValue() {
		LocalDate previousDate = null;
		switch (calendarField) {
			case Calendar.DAY_OF_MONTH:
				previousDate = currentValue.minusDays(1);
				break;
			case Calendar.MONTH:
				previousDate = currentValue.minusMonths(1);
				break;
			case Calendar.YEAR:
				previousDate = currentValue.minusYears(1);
				break;
		}
		if (minDate != null && minDate.compareTo(previousDate) < 0) {
			return previousDate;
		}
		return null;
	}

	/**
	 * Returns the current minimum allowed date.
	 * @return  the current minimum allowed date.
	 */
	public LocalDate getMinDate() {
		return minDate;
	}

	/**
	 * Returns the current maximum allowed date.
	 * @return  the current maximum allowed date.
	 */
	public LocalDate getMaxDate() {
		return maxDate;
	}

	/**
	 * Specifies whether the increment/decrement methods should adjust the year, month, or day.
	 *
	 * @param calendarField one of
	 *  <ul>
	 *    <li><code>Calendar.YEAR</code>
	 *    <li><code>Calendar.MONTH</code>
	 *    <li><code>Calendar.DAY_OF_MONTH</code>
	 *  </ul>
	 * <p>
	 *
	 */
	public void setCalendarField(int calendarField) {
		checkIsValidCalendarField(calendarField);
		if (calendarField != this.calendarField) {
			this.calendarField = calendarField;
			fireStateChanged();
		}
	}

	private void checkIsValidCalendarField(int calField) {
		switch (calField) {
			case Calendar.DAY_OF_MONTH:
			case Calendar.MONTH:
			case Calendar.YEAR:
				return;
			default:
				throw new IllegalArgumentException("invalid calendarField");
		}
	}

	public LocalDate getDate() {
		return currentValue;
	}
}
