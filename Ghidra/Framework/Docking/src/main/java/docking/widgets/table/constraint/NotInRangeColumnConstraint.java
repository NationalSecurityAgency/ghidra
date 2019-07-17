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

import docking.widgets.table.constraint.provider.EditorProvider;

/**
 * Column Constraint where acceptable column values are outside some range defined by a min value and
 * a max value.
 *
 * @param <T> the column type.
 */
public class NotInRangeColumnConstraint<T extends Comparable<T>> extends RangeColumnConstraint<T> {

	/**
	 * Construct a new instance of this class that uses the default name and group and specifies the min
	 * and max values for the range.
	 *
	 * @param minValue the min value of the acceptable range.
	 * @param maxValue the max value of the acceptable range.
	 * @param editorProvider an object that can provide an appropriate range editor for the column type.
	 */
	public NotInRangeColumnConstraint(T minValue, T maxValue, EditorProvider<T> editorProvider) {
		this("Not In Range", minValue, maxValue, editorProvider, "number");
	}

	/**
	 * Construct a new instance of this class that specifies the name and group and specifies the min
	 * and max values for the range.
	 *
	 * @param name the constraint to use instead of the default "Not In Range".
	 * @param minValue the min value of the acceptable range.
	 * @param maxValue the max value of the acceptable range.
	 * @param editorProvider an object that can provide an appropriate range editor for the column type.
	 * @param group the group to use instead of the default value of "number".
	 */
	public NotInRangeColumnConstraint(String name, T minValue, T maxValue,
			EditorProvider<T> editorProvider, String group) {
		super(name, minValue, maxValue, editorProvider, group);
	}

	@Override
	public boolean accepts(T value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return value.compareTo(getMinValue()) < 0 || value.compareTo(getMaxValue()) > 0;
	}

	@Override
	public RangeColumnConstraint<T> copy(T min, T max) {
		return new NotInRangeColumnConstraint<>(getName(), min, max, editorProvider, getGroup());
	}

}
