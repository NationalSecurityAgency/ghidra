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
package docking.widgets.formatter;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.text.ParseException;

import javax.swing.JFormattedTextField;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.textfield.HexIntegerFormatter;
import ghidra.feature.vt.gui.filters.IntegerFormatterFactory;

public class HexIntegerFormatterTest {

	private HexIntegerFormatter formatter;
	private JFormattedTextField formattedField;

	@Before
	public void setUp() throws Exception {
		formatter = new HexIntegerFormatter();
		IntegerFormatterFactory factory = new IntegerFormatterFactory(formatter, false);
		formattedField = new JFormattedTextField(factory);
	}

	@Test(expected = ParseException.class)
	public void invalidInput() throws ParseException {
		formattedField.setText("bob");
		formattedField.commitEdit();
		assertThat(formattedField.getValue(), is(nullValue()));
	}

	@Test
	public void positiveInput() throws ParseException {
		long value = 1L;
		formattedField.setText(Long.toString(value));
		formattedField.commitEdit();
		assertThat(formattedField.getValue(), is(value));

		String hexString = "ab";
		formattedField.setText(hexString);
		formattedField.commitEdit();
		String currentStringValue = Long.toHexString((Long) formattedField.getValue());
		assertThat(currentStringValue, is(hexString));
	}

	@Test(expected = ParseException.class)
	public void negativeIntegerInput() throws ParseException {
		long value = -1L;
		formattedField.setText(Long.toString(value));
		formattedField.commitEdit();
	}

	@Test
	public void negativeInput() throws ParseException {
		String hexString = "ab";
		formattedField.setText(hexString);
		formattedField.commitEdit();
		String currentStringValue = Long.toHexString((Long) formattedField.getValue());
		assertThat(currentStringValue, is(hexString));
	}

	@Test
	public void emptyString() throws ParseException {
		long value = 1;
		formattedField.setValue(value);
		formattedField.commitEdit();
		assertThat(formattedField.getValue(), is(1L));
	}
}
