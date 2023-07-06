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
package docking.widgets.textfield;

import static org.junit.Assert.*;

import javax.swing.JFrame;
import javax.swing.UIManager;

import org.junit.*;

import docking.test.AbstractDockingTest;

public class FloatingPointTextFieldTest extends AbstractDockingTest {

	private JFrame frame;
	private FloatingPointTextField field;

	@Before
	public void setUp() throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		field = new FloatingPointTextField(10);
		frame = new JFrame("Test");
		frame.getContentPane().add(field);
		frame.pack();
		frame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {
		frame.setVisible(false);
	}

	@Test
	public void testDefaultState() {
		assertEquals("", field.getText());
		assertEquals(0.0d, field.getValue(), 0.00001d);
	}

	@Test
	public void testTypeValidPositiveFloatingPointNumber() {
		triggerText(field, "123.456");
		assertEquals(123.456d, field.getValue(), 0.0001d);
	}

	@Test
	public void testTypeValidNegativeFloatingPointNumber() {
		triggerText(field, "-342.312");
		assertEquals(-342.312d, field.getValue(), 0.0001d);
	}

	@Test
	public void testTypeValidHexNumber() {
		triggerText(field, "1.2abcdef");
		assertEquals("1.2", field.getText());
	}

	@Test
	public void testPartial1() {
		triggerText(field, "-");
		assertEquals("-", field.getText());
		assertEquals(0.0d, field.getValue(), 0.0001d);
	}

	@Test
	public void testPartial2() {
		triggerText(field, ".");
		assertEquals(".", field.getText());
		assertEquals(0.0d, field.getValue(), 0.0001d);
	}

	@Test
	public void testPartial3() {
		triggerText(field, "-.");
		assertEquals("-.", field.getText());
		assertEquals(0.0d, field.getValue(), 0.0001d);
	}

	@Test
	public void testMinValue0() {
		field.setMinValue(0.0d);
		triggerText(field, "-");
		assertEquals("", field.getText());
	}

	@Test
	public void testMinValueNegative() {
		field.setMinValue(-1.0);
		triggerText(field, "-3.1");
		assertEquals("-.1", field.getText());
		field.setText("");
		triggerText(field, "-.999");
		assertEquals("-.999", field.getText());
	}

	@Test
	public void testMinValuePositive() {
		try {
			field.setMinValue(1.0d);
			fail("Expected exception trying to set min value to positive number");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testMaxValue0() {
		field.setMaxValue(0.0d);
		triggerText(field, "12");
		assertEquals("", field.getText());
		triggerText(field, "-5.3");
		assertEquals("-5.3", field.getText());
	}

	@Test
	public void testMaxValuePositive() {
		field.setMaxValue(10.0d);
		triggerText(field, "12.123");
		assertEquals("1.123", field.getText());
		field.setText("");
		triggerText(field, "-50.3");
		assertEquals("-50.3", field.getText());
		field.setText("");
		triggerText(field, "50.3");
		assertEquals("5.3", field.getText());
	}

	@Test
	public void testMaxValueNegative() {
		try {
			field.setMaxValue(-1.0d);
			fail("Expected exception trying to set max value to negative number");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testLeadingTrailingSpaces() {
		field.setText("   3.14  ");
		assertEquals("3.14", field.getText());
	}

	@Test
	public void testSetValue() {
		field.setValue(123.456d);
		assertEquals("123.456", field.getText());
	}
}
