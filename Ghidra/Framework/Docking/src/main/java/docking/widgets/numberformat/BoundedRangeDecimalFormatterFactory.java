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
package docking.widgets.numberformat;

import java.text.DecimalFormat;

import javax.swing.JFormattedTextField;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.text.DefaultFormatterFactory;

/**
 * Bounded range factory for formatters with a min and max allowed value.
 */
public class BoundedRangeDecimalFormatterFactory extends DefaultFormatterFactory {

	private AbstractFormatter decimalFormatter;

	/**
	 * Constructor
	 * 
	 * @param numberFormat a format string compatible with {@link DecimalFormat}
	 */
	public BoundedRangeDecimalFormatterFactory(String numberFormat) {
		this(Double.MAX_VALUE, Double.MIN_VALUE, numberFormat);
	}

	/**
	 * Constructor
	 * 
	 * @param upperRangeValue the max value allowed
	 * @param lowerRangeValue the min value allowed
	 * @param numberFormat a format string compatible with {@link DecimalFormat}
	 */
	public BoundedRangeDecimalFormatterFactory(Double upperRangeValue, Double lowerRangeValue,
			String numberFormat) {
		decimalFormatter =
			new BoundedRangeDecimalFormatter(upperRangeValue, lowerRangeValue, numberFormat);
	}

	@Override
	public AbstractFormatter getFormatter(JFormattedTextField tf) {
		return decimalFormatter;
	}
}
