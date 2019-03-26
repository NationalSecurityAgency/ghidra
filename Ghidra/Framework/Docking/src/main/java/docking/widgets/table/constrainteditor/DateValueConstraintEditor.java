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

import java.awt.BorderLayout;
import java.awt.Component;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;

import javax.swing.JPanel;

import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.SingleValueColumnConstraint;
import docking.widgets.table.constraint.provider.DateColumnConstraintProvider;

/**
 * A constraint editor for specifying comparison with a single Date value.
 */
public class DateValueConstraintEditor extends AbstractColumnConstraintEditor<LocalDate> {
	public static final String DATE_PATTERN = "MM/dd/yyyy";
	/**
	 * Specifies how Date values are to be formatted within the editor
	 */
	public static final DateTimeFormatter LOCAL_DATE_FORMAT =
		DateTimeFormatter.ofPattern(DATE_PATTERN);

	private final ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());

	private final LocalDate minDate = LocalDate.of(now.getYear(), 1, 1).minusYears(30);
	private final LocalDate maxDate = LocalDate.of(now.getYear(), 12, 31).plusYears(30);

	private DateSpinner dateSpinner;
	private LocalDateSpinnerModel spinnerModel;

	/**
	 * Constructor.
	 *
	 * @param constraint Date constraint for which this component is an editor.
	 */
	public DateValueConstraintEditor(ColumnConstraint<LocalDate> constraint) {
		super(constraint);
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new BorderLayout());

		LocalDate value = getConstraint().getConstraintValue();

		if (!isValidDate(value)) {
			value = LocalDate.now();
		}

		spinnerModel = new LocalDateSpinnerModel(value, minDate, maxDate, Calendar.DAY_OF_MONTH);

		dateSpinner = new DateSpinner(spinnerModel, DATE_PATTERN);

		spinnerModel.addChangeListener(e -> valueChanged());

		panel.add(dateSpinner.getSpinner());

		return panel;
	}

	private static boolean isValidDate(LocalDate date) {
		if (date == null) {
			return false;
		}

		if (date == DateColumnConstraintProvider.DEFAULT_DATE) {
			return false;
		}
		// the DateColumnConstraintProvider.DEFAULT_DATE is a made-up illegal Date so that
		// if it is encountered by the editor, it knows to sub in a date relative to the current
		// date
		return date.toEpochDay() != DateColumnConstraintProvider.DEFAULT_DATE.toEpochDay();
	}

	@Override
	public ColumnConstraint<LocalDate> getValueFromComponent() {
		LocalDate spinnerDate = spinnerModel.getDate();
		LocalDate spinnerLocalDate = spinnerDate;
		return getConstraint().copy(spinnerLocalDate);
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			LocalDate constraintValue = getConstraint().getConstraintValue();
			if (constraintValue instanceof LocalDate) {
				LocalDate constraintDate = constraintValue;
				spinnerModel.setValue(constraintDate);
			}
		}
	}

	@Override
	public void reset() {
		setValue(getConstraint().copy(LocalDate.now()));
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return true;
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// this editor does not have any status data
	}

	@Override
	public String getErrorMessage() {
		return "";
	}

	private SingleValueColumnConstraint<LocalDate> getConstraint() {
		return (SingleValueColumnConstraint<LocalDate>) currentConstraint;
	}
}
