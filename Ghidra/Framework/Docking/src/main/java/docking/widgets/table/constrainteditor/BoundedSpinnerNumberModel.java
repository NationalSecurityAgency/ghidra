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

import javax.swing.SpinnerNumberModel;

/**
 * {@link SpinnerNumberModel} that adds checking to make sure setValue is in the allowed range.  Strangely,
 * the default SpinnerNumberModel has min and max values, but does not check except during the
 * increment/decrement using the spinner widget.
 */
class BoundedSpinnerNumberModel extends SpinnerNumberModel {

	public BoundedSpinnerNumberModel(Number value, Comparable<? extends Number> minimum,
			Comparable<? extends Number> maximum, Number stepSize) {
		super(value, minimum, maximum, stepSize);
	}

	public BoundedSpinnerNumberModel(int value, int minimum, int maximum, int stepSize) {
		this(new Integer(value), new Integer(minimum), new Integer(maximum), new Integer(stepSize));
	}

	public BoundedSpinnerNumberModel(double value, double minimum, double maximum,
			double stepSize) {
		this(new Double(value), new Double(minimum), new Double(maximum), new Double(stepSize));
	}

	public BoundedSpinnerNumberModel() {
		super();
	}

	@Override
	public void setValue(Object value) {
		if (value != null && value instanceof Number) {
			Comparable minimum = getMinimum();
			Comparable maximum = getMaximum();

			Number val = (Number) value;

			if (minimum != null && minimum.compareTo(val) > 0) {
				return;
			}
			if (maximum != null && maximum.compareTo(val) < 0) {
				return;
			}
			super.setValue(value);
		}

	}

}
