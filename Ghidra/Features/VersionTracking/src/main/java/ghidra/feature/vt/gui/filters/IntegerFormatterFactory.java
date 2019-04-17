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
package ghidra.feature.vt.gui.filters;

import javax.swing.JFormattedTextField;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.text.DefaultFormatterFactory;

import docking.widgets.textfield.IntegerFormatter;

public class IntegerFormatterFactory extends DefaultFormatterFactory {

	private AbstractFormatter formatter = new IntegerFormatter();

	public IntegerFormatterFactory(boolean allowsNegativeInput) {
		this(new IntegerFormatter(), allowsNegativeInput);
	}

	public IntegerFormatterFactory(IntegerFormatter formatter, boolean allowsNegativeInput) {
		this.formatter = formatter;

		if (allowsNegativeInput) {
			formatter.setAllowsInvalid(true);
		}
	}

	@Override
	public AbstractFormatter getFormatter(JFormattedTextField tf) {
		return formatter;
	}
}
