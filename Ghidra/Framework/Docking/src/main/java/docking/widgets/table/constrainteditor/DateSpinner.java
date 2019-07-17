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
package docking.widgets.table.constrainteditor;

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.time.LocalDate;
import java.util.*;

import javax.swing.JSpinner;
import javax.swing.SpinnerModel;
import javax.swing.event.*;

import docking.DockingUtils;
import docking.widgets.textfield.LocalDateTextField;

/**
 * Creates a component for editing Dates using a formated textfield and a Jspinner.
 */
public class DateSpinner {

	private final JSpinner spinner;
	private final LocalDateSpinnerModel spinnerModel;
	private final LocalDateTextField dateTextField;

	private List<ChangeListener> changeListeners = new ArrayList<>();

	/**
	 * Creates a DateSpinner object using the given spinnerModel and a pattern for a formated text field.
	 *
	 * @param spinnerModel the spinner model
	 * @param pattern a pattern to be used by a JFormattedTextField
	 */
	public DateSpinner(LocalDateSpinnerModel spinnerModel, String pattern) {

		this.spinnerModel = spinnerModel;

		spinner = new JSpinner(spinnerModel);

		dateTextField = new LocalDateTextField(pattern);
		dateTextField.getTextField().setName("date.spinner.editor");
		dateTextField.setMinimum(spinnerModel.getMinDate());
		dateTextField.setMaximum(spinnerModel.getMaxDate());

		spinner.setEditor(dateTextField.getComponent());

		spinner.getModel().addChangeListener(e -> {

			dateTextField.setMinimum(spinnerModel.getMinDate());
			dateTextField.setMaximum(spinnerModel.getMaxDate());

			LocalDate newDate = (LocalDate) spinner.getModel().getValue();

			setValue(newDate);
		});

		dateTextField.getTextField().addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {

				if (DockingUtils.isControlModifier(e)) {
					spinnerModel.setCalendarField(Calendar.MONTH);
					dateTextField.setMonthMode();
				}
				else {
					spinnerModel.setCalendarField(Calendar.DAY_OF_MONTH);
					dateTextField.setDayMode();
				}

				switch (e.getKeyCode()) {
					case KeyEvent.VK_UP:
						increment();
						break;
					case KeyEvent.VK_DOWN:
						decrement();
						break;
					default:
						break;
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				if (DockingUtils.isControlModifier(e)) {
					spinnerModel.setCalendarField(Calendar.MONTH);
					dateTextField.setMonthMode();
				}
				else {
					spinnerModel.setCalendarField(Calendar.DAY_OF_MONTH);
					dateTextField.setDayMode();
				}
			}
		});

		spinner.addMouseWheelListener(e -> {

			if (DockingUtils.isControlModifier(e)) {
				spinnerModel.setCalendarField(Calendar.MONTH);
				dateTextField.setMonthMode();
			}
			else {
				spinnerModel.setCalendarField(Calendar.DAY_OF_MONTH);
				dateTextField.setDayMode();
			}

			if (e.getWheelRotation() > 0) {
				decrement();
			}
			else {
				increment();
			}
		});

		spinner.setToolTipText(
			"<html>Use the mouse wheel or arrow keys to adjust by days; add the <code>" +
				DockingUtils.CONTROL_KEY_NAME + "</code> key to adjust by months");

		spinner.setToolTipText(dateTextField.getTextField().getToolTipText());

		dateTextField.addChangeListener(e -> {
			LocalDate newDate = dateTextField.getValue();
			if (newDate != null) {
				spinnerModel.setValue(newDate);
			}
			fireStateChanged();
		});

		setValue(spinnerModel.getDate());
	}

	/**
	 * Returns the spinner component.
	 *
	 * @return the spinner component.
	 */
	public JSpinner getSpinner() {
		return spinner;
	}

	/**
	 * Returns the DateTextField component.
	 *
	 * @return  the DateTextField component.
	 */
	public LocalDateTextField getDateField() {
		return dateTextField;
	}

	private void increment() {
		setValue((LocalDate) spinnerModel.getNextValue());
	}

	private void decrement() {
		setValue((LocalDate) spinnerModel.getPreviousValue());
	}

	/**
	 * Sets the Date value for this DateSpinner.
	 *
	 * @param newValue the new Date for this DateSpinner.
	 */
	public void setValue(LocalDate newValue) {
		if (newValue == null) {
			return;
		}
		try {
			spinner.setValue(newValue);
			dateTextField.setValue(newValue);
		}
		catch (IllegalArgumentException iae) {
			// ignored?
		}

		fireStateChanged();
	}

	/**
	 * Adds a ChangeListener to the model's listener list.  The
	 * ChangeListeners must be notified when the models value changes.
	 *
	 * @param listener the ChangeListener to add
	 * @see #removeChangeListener
	 * @see SpinnerModel#addChangeListener
	 */
	public void addChangeListener(ChangeListener listener) {
		changeListeners.add(listener);
	}

	/**
	 * Removes a ChangeListener from the model's listener list.
	 *
	 * @param listener the ChangeListener to remove
	 * @see #addChangeListener
	 * @see SpinnerModel#removeChangeListener
	 */
	public void removeChangeListener(ChangeListener listener) {
		changeListeners.remove(listener);
	}

	/**
	 * Run each ChangeListeners stateChanged() method.
	 *
	 * @see #setValue
	 * @see EventListenerList
	 */
	protected void fireStateChanged() {
		ChangeEvent changeEvent = new ChangeEvent(this);
		for (ChangeListener changeListener : changeListeners) {
			changeListener.stateChanged(changeEvent);
		}
	}

}
