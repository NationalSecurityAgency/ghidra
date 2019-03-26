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
package docking.widgets.table.constraint;

import java.time.LocalDate;

import docking.widgets.table.constraint.provider.EditorProvider;

/**
 * Column Constraint where acceptable column values are within some range defined by a min value and
 * a max value.
 *
 */
public class InDateRangeColumnConstraint extends RangeColumnConstraint<LocalDate> {

	/**
	 * Construct a new InDateRangeConstraint that uses the default name and group and specifies the min
	 * and max values for the range.
	 *
	 * @param minValue the min value of the acceptable range.
	 * @param maxValue the max value of the acceptable range.
	 * @param editorProvider an object that can provide an appropriate range editor for the column type.
	 */
	public InDateRangeColumnConstraint(LocalDate minValue, LocalDate maxValue,
			EditorProvider<LocalDate> editorProvider) {
		super("Between Dates", minValue, maxValue, editorProvider, "date");
	}

	@Override
	public boolean accepts(LocalDate value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return value.compareTo(getMinValue()) >= 0 && value.compareTo(getMaxValue()) <= 0;
	}

	@Override
	public RangeColumnConstraint<LocalDate> copy(LocalDate min, LocalDate max) {
		return new InDateRangeColumnConstraint(min, max, editorProvider);
	}

}
