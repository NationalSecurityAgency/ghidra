/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.dialogs;

import java.util.Arrays;

/**
 * StringEnum objects represent a choice from a limited set of options.
 */
public class StringChoices {

	protected String[] values;
	protected int selected;

	/**
	 * Construct from an array of Strings.
	 * The order of Strings is preserved.
	 */
	public StringChoices(String[] values) {
		if ((values == null) || (values.length == 0)) {
			throw new IllegalArgumentException("Set of values must contain at least one value");
		}
		this.values = values;
		selected = 0;
	}

	/**
	 * Construct from another StringEnum instance.
	 */
	public StringChoices(StringChoices strEnum) {
		if (strEnum == null) {
			throw new IllegalArgumentException("Set of values must contain at least one value");
		}
		this.values = strEnum.values.clone();
		this.selected = strEnum.selected;
	}

	/**
	 * Returns a list of all allowed string values.
	 */
	public String[] getValues() {
		String[] copy = new String[values.length];
		System.arraycopy(values, 0, copy, 0, values.length);
		return copy;
	}

	/**
	 * Returns the currently selected value.
	 */
	public String getSelectedValue() {
		return values[selected];
	}

	/**
	 * Returns the index of the currently selected value;
	 */
	public int getSelectedValueIndex() {
		return selected;
	}

	/**
	 * Returns true if the given value is contained in this StringEnum
	 * @param value The value for which to search
	 * @return true if the given value is contained in this StringEnum
	 */
	public boolean contains(String value) {
		return (indexOf(value) != -1);
	}

	/**
	 * Returns the index of the given value in this StringEnum; -1 if the value is not contained
	 * herein.
	 * @param value The value for which to search
	 * @return the index of the given value in this StringEnum; -1 if the value is not contained
	 *         herein.
	 */
	public int indexOf(String value) {
		for (int i = 0; i < values.length; i++) {
			if (values[i].equals(value)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Sets the currentValue to the given value.
	 * @exception IllegalArgumentException thrown if the given value is not one
	 * of the set of allowed values.
	 */
	public void setSelectedValue(String value) {
		int index = indexOf(value);
		if (index == -1) {
			throw new IllegalArgumentException("No such value in Enum");
		}

		selected = index;
	}

	/**
	 * Sets the current value to the object at the given position as if indexed
	 * into the array returned by getValues().
	 */
	public void setSelectedValue(int index) {
		if (index < 0 || index >= values.length) {
			throw new IllegalArgumentException("index out of range");
		}
		selected = index;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + selected;
		result = prime * result + Arrays.hashCode(values);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		StringChoices other = (StringChoices) obj;
		if (selected != other.selected) {
			return false;
		}
		if (!Arrays.equals(values, other.values)) {
			return false;
		}
		return true;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getSelectedValue();
	}
}
