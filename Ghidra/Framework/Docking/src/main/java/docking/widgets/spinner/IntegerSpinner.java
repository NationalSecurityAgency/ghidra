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
package docking.widgets.spinner;

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.event.*;

import docking.widgets.textfield.IntegerTextField;

/**
 * Creates a component for editing Integer values using an {@link IntegerTextField} and a {@link JSpinner}.
 */
public class IntegerSpinner {

	private final JSpinner spinner;
	private final IntegerTextField integerTextField;

	private List<ChangeListener> changeListeners = new ArrayList<>();

	/**
	 * Creates a new IntegerSpinner using the given spinner model.
	 *
	 * @param spinnerModel the spinner model to use in the JSpinner.
	 */
	public IntegerSpinner(SpinnerNumberModel spinnerModel) {

		spinner = new JSpinner(spinnerModel);

		integerTextField = new IntegerTextField(10, ((Number) spinnerModel.getValue()).longValue());
		integerTextField.getComponent().setName("integer.spinner.editor");
		Number maximum = (Number) spinnerModel.getMaximum();
		integerTextField.setMaxValue(
			maximum == null ? null : BigInteger.valueOf(maximum.longValue()));

		spinner.setEditor(integerTextField.getComponent());

		spinnerModel.addChangeListener(e -> {
			Number newVal = (Number) spinnerModel.getValue();
			integerTextField.setValue(newVal.longValue());
		});

		integerTextField.getComponent().addKeyListener(new KeyAdapter() {

			@Override
			public void keyPressed(KeyEvent e) {

				Object newVal = null;
				switch (e.getKeyCode()) {
					case KeyEvent.VK_UP:
						newVal = spinnerModel.getNextValue();
						break;

					case KeyEvent.VK_DOWN:
						newVal = spinnerModel.getPreviousValue();
						break;
					default:
						break;
				}
				if (newVal != null) {
					spinner.setValue(newVal);
				}
			}
		});

		spinner.addMouseWheelListener(e -> {
			SpinnerNumberModel model = (SpinnerNumberModel) spinner.getModel();
			try {
				if (e.getWheelRotation() > 0) {
					Object previousValue = model.getPreviousValue();
					if (previousValue != null) {
						spinner.setValue(previousValue);
					}
				} else {
					Object nextValue = model.getNextValue();
					if (nextValue != null) {
						spinner.setValue(nextValue);
					}
				}
			} catch (IllegalArgumentException iae) {
				// ignored
			}
		});

		integerTextField.addChangeListener(e -> {
			BigInteger value = integerTextField.getValue();
			if (value == null) {
				return;
			}
			spinnerModel.setValue(value.longValue());
		});

	}

	/**
	 * Returns the JSpinner that has been attached to the text field.
	 *
	 * @return the JSpinner that has been attached to the text field
	 */
	public JSpinner getSpinner() {
		return spinner;
	}

	/**
	 * Returns the IntegerTextField that has been attached to the spinner.
	 *
	 * @return the IntegerTextField that has been attached to the spinner.
	 */
	public IntegerTextField getTextField() {
		return integerTextField;
	}

	/**
	 * Sets the given value to both the spinner and the text field.
	 *
	 * @param value the value to set.
	 */
	public void setValue(Number value) {
		spinner.setValue(value);
		integerTextField.setValue(value.longValue());

		fireStateChanged();
	}

	/**
	 * Adds a ChangeListener to the model's listener list.  The
	 * ChangeListeners must be notified when the models value changes.
	 *
	 * @param listener the ChangeListener to add
	 */
	public void addChangeListener(ChangeListener listener) {
		changeListeners.add(listener);
	}

	/**
	 * Removes a ChangeListener from the model's listener list.
	 *
	 * @param listener the ChangeListener to remove
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
