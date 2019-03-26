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
package docking.widgets.textfield;

import java.text.DecimalFormat;

import javax.swing.*;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.JFormattedTextField.AbstractFormatterFactory;
import javax.swing.text.NumberFormatter;

public class DecimalFormatterFactory extends AbstractFormatterFactory {

	private NumberFormatter numberFormatter;
	private DecimalFormat decimalFormat;

	public DecimalFormatterFactory() {
		this("0.0#");
	}

	public DecimalFormatterFactory(String formatPattern) {
		decimalFormat = new DecimalFormat(formatPattern);
		numberFormatter = new NumberFormatter(decimalFormat);
	}

	public DecimalFormat getDecimalFormat() {
		return decimalFormat;
	}

	@Override
	public AbstractFormatter getFormatter(JFormattedTextField tf) {
		return numberFormatter;
	}

}
