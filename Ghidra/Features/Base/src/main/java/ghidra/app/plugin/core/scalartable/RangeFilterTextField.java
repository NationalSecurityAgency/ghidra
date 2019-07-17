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
package ghidra.app.plugin.core.scalartable;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.listing.Program;

/**
 * Extends {@link IntegerTextField} to allow use as a range filter in the {@link ScalarSearchPlugin}. 
 * <p>
 * Specifically this provides the following:
 * <ul>
 * <li>Ability to specify if this is a min/max range field
 * <li>Allows hex input of the form "0x...." for hex values
 * </ul>
 */
public class RangeFilterTextField extends IntegerTextField {

	public enum FilterType {
		MIN, MAX
	}

	private Program program;
	private FilterType filterType;

	// Specifies the maximum value this filter should allow. In the case of a 
	// MIN filter, this value will be negative.
	private int maxValue;

	public RangeFilterTextField(FilterType filterType, Program program) {
		super(8);

		this.program = program;
		this.filterType = filterType;
		this.maxValue = getMaxScalarValue();

		setValue(maxValue);
	}

	public int getLimitValue() {
		return maxValue;
	}

	public FilterType getFilterType() {
		return filterType;
	}

	public long getFilterValue() {
		String text = getText();
		long longVal;

		if (StringUtils.isBlank(text)) {
			return maxValue;
		}

		try {
			if (text.startsWith("0x")) {
				text = text.substring("0x".length());
				longVal = Long.parseUnsignedLong(text, 16);
			}

			else {
				longVal = Long.parseLong(text);
			}
		}

		catch (NumberFormatException e) {
			// This situation is not expected because the user is 
			// restricted to only entering digits.
			return maxValue;
		}

		return longVal;
	}

	/**
	 * Returns the maximum value a scalar can have for the current program. This is
	 * used to bound the min/max filters.
	 * 
	 * @return the max scalar value
	 */
	private int getMaxScalarValue() {

		// TODO this code is odd--why calculate the pointer size just to truncate at 
		//      Integer min/max value?  This code should default to no value in the field, letting
		//      the user input min and max values themselves.  Then, just use those values 
		//      directly.

		int defaultPointerSize = program.getDefaultPointerSize();
		int max = (int) Math.pow(2, (defaultPointerSize * 8));

		return filterType == FilterType.MAX ? max : -max;
	}
}
