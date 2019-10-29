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

import java.awt.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;

import javax.swing.*;

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.RangeColumnConstraint;
import docking.widgets.table.constraint.provider.DateColumnConstraintProvider;
import docking.widgets.textfield.LocalDateTextField;
import ghidra.util.layout.VerticalLayout;

/**
 * A constraint editor for specifying ranges of dates.
 */
public class DateRangeConstraintEditor extends AbstractColumnConstraintEditor<LocalDate> {

	private DateSpinner lowerSpinner;
	private LocalDateSpinnerModel lowerSpinnerModel;

	private DateSpinner upperSpinner;
	private LocalDateSpinnerModel upperSpinnerModel;

	private JLabel infoLabel;
	private String errorMessage;

	private static final DateTimeFormatter LOCAL_DATE_FORMAT =
		DateValueConstraintEditor.LOCAL_DATE_FORMAT;

	private final ZonedDateTime now = ZonedDateTime.now(ZoneId.systemDefault());
	private final LocalDate oneYearAgo = LocalDate.now().minusYears(1);

	private final LocalDate minDate = LocalDate.of(now.getYear(), 1, 1).minusYears(30);
	private final LocalDate maxDate = LocalDate.of(now.getYear(), 12, 31).plusYears(30);

	/**
	 * Constructor.
	 *
	 * @param constraint Date constraint for which this component is an editor.
	 */
	public DateRangeConstraintEditor(ColumnConstraint<LocalDate> constraint) {
		super(constraint);

		if (!isValidDate(getConstraint().getMinValue())) {
			reset();
		}
	}

	private void initLowerSpinner(LocalDate value, LocalDate rangeMin, LocalDate rangeMax) {

		lowerSpinnerModel =
			new LocalDateSpinnerModel(value, rangeMin, rangeMax, Calendar.DAY_OF_MONTH);
		lowerSpinner = new DateSpinner(lowerSpinnerModel, DateValueConstraintEditor.DATE_PATTERN);
		lowerSpinner.getSpinner().setName("lower.date.spinner");

		lowerSpinner.addChangeListener(e -> {
			valueChanged();
		});
	}

	private void initUpperSpinner(LocalDate value, LocalDate rangeMin, LocalDate rangeMax) {

		upperSpinnerModel =
			new LocalDateSpinnerModel(value, rangeMin, rangeMax, Calendar.DAY_OF_MONTH);
		upperSpinner = new DateSpinner(upperSpinnerModel, DateValueConstraintEditor.DATE_PATTERN);
		upperSpinner.getSpinner().setName("upper.date.spinner");

		upperSpinner.addChangeListener(e -> {
			valueChanged();
		});

	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new VerticalLayout(2));

		LocalDate minValue = getConstraint().getMinValue();
		LocalDate maxValue = getConstraint().getMaxValue();

		initLowerSpinner(minValue, minDate, maxDate);
		initUpperSpinner(maxValue, minDate, maxDate);

		JPanel controlPanel = new JPanel(new GridLayout(1, 2));
		controlPanel.add(lowerSpinner.getSpinner());
		controlPanel.add(upperSpinner.getSpinner());

		panel.add(controlPanel);

		infoLabel = new GDHtmlLabel();
		infoLabel.setForeground(Color.GRAY);
		infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(infoLabel);

		return panel;
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		if (isValid) {

			LocalDate start = lowerSpinnerModel.getDate();
			LocalDate end = upperSpinnerModel.getDate();

			// add one because the date range is inclusive.
			long days = ChronoUnit.DAYS.between(start, end) + 1;
			infoLabel.setText(formatStatus(String.format("Range Size: %,d days", days), false));
		}
		else {
			infoLabel.setText(formatStatus(getErrorMessage(), true));
		}

	}

	private static boolean isValidDate(LocalDate date) {
		if (date == null) {
			return false;
		}

		// Ensure parameter date isn't the default (invalid) date:

		// ... by object equality
		if (date == DateColumnConstraintProvider.DEFAULT_DATE) {
			return false;
		}

		// ... and manual construction
		// epochDay are the number of days since the epoch (1/1/1970)
		return date.toEpochDay() != DateColumnConstraintProvider.DEFAULT_DATE.toEpochDay();
	}

	@Override
	protected ColumnConstraint<LocalDate> getValueFromComponent() {
		LocalDate modelMin = lowerSpinnerModel.getDate();
		LocalDate modelMax = upperSpinnerModel.getDate();
		return getConstraint().copy(modelMin, modelMax);
	}

	@Override
	protected void updateEditorComponent() {

		LocalDate minValue = getConstraint().getMinValue();
		lowerSpinnerModel.setValue(minValue);

		LocalDate maxValue = getConstraint().getMaxValue();
		upperSpinnerModel.setValue(maxValue);

		valueChanged();
	}

	@Override
	public void reset() {
		LocalDate minVal = oneYearAgo;
		LocalDate maxVal = LocalDate.now();

		setValue(getConstraint().copy(minVal, maxVal));
	}

	@Override
	protected boolean checkEditorValueValidity() {

		boolean isValidLower = hasValidValue(lowerSpinner);
		boolean isValidUpper = hasValidValue(upperSpinner);

		markSpinnerAsValid(lowerSpinner, isValidLower);
		markSpinnerAsValid(upperSpinner, isValidUpper);

		errorMessage = "";

		if (!isValidLower && !isValidUpper) {
			errorMessage = "Invalid lower and upper bounds!";
			return false;
		}

		if (!isValidLower) {
			errorMessage = "Invalid lower bounds!";
			return false;
		}
		if (!isValidUpper) {
			errorMessage = "Invalid upper bounds!";
			return false;
		}

		LocalDate lVal = (LocalDate) lowerSpinnerModel.getValue();
		LocalDate uVal = (LocalDate) upperSpinnerModel.getValue();
		if (lVal.compareTo(uVal) > 0) {
			errorMessage = "Upper bounds value must be greater than lower bounds!";
			return false;
		}
		return true;

	}

	private static boolean hasValidValue(DateSpinner spinner) {
		LocalDateTextField textField = spinner.getDateField();
		String text = textField.getTextField().getText();

		LocalDate value = (LocalDate) spinner.getSpinner().getValue();
		String valueString = value.format(LOCAL_DATE_FORMAT);

		return valueString.equals(text);
	}

	private static void markSpinnerAsValid(DateSpinner spinner, boolean valid) {
		spinner.getDateField().getTextField().setBackground(
			valid ? VALID_INPUT_COLOR : INVALID_INPUT_COLOR);
	}

	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

	private RangeColumnConstraint<LocalDate> getConstraint() {
		return (RangeColumnConstraint<LocalDate>) currentConstraint;
	}

}
