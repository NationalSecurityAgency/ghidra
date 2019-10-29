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

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.junit.*;

import docking.test.AbstractDockingTest;

public class IntegerTextFieldTest extends AbstractDockingTest {

	private JFrame frame;
	private IntegerTextField field;
	private JTextField textField;

	@Before
	public void setUp() throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		field = new IntegerTextField(10);
		field.setShowNumberMode(true);
		textField = (JTextField) field.getComponent();
		frame = new JFrame("Test");
		frame.getContentPane().add(field.getComponent());
		frame.pack();
		frame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {
		frame.setVisible(false);
	}

	@Test
	public void testDefaultState() {
		assertNull(field.getValue());// no value
		assertEquals(0, field.getIntValue());// the "int value" return for null is 0
		assertEquals(0, field.getLongValue());
		assertTrue(!field.isHexMode());
		assertNull(field.getMaxValue());
	}

	@Test
	public void testTypeValidDecimalNumber() {
		triggerText(textField, "123");
		assertEquals(123, field.getIntValue());
	}

	@Test
	public void testTypeValidHexNumber() {
		triggerText(textField, "0x2abcdef");
		assertEquals(0x2abcdef, field.getIntValue());
	}

	@Test
	public void testInvalidCharsIgnored() {
		triggerText(textField, "123ghijklmnopqrstuvwxyz4");
		assertEquals(1234, field.getIntValue());
	}

	@Test
	public void testHexCharsIgnoredInDecimalMode() {
		assertTrue(!field.isHexMode());
		triggerText(textField, "123ghijklmnopqrstuvwxyz4");
		assertEquals(1234, field.getIntValue());
	}

	@Test
	public void testXchangesHexMode() {
		assertTrue(!field.isHexMode());
		triggerText(textField, "0");
		assertTrue(!field.isHexMode());
		triggerText(textField, "x");
		assertTrue(field.isHexMode());
		triggerBackspaceKey(textField);
		assertTrue(!field.isHexMode());
	}

	@Test
	public void testHexModeWithoutPrefix() {
		triggerText(textField, "abc");// not allowed when using hex prefix, so expect empty
		assertEquals(null, field.getValue());

		field.setAllowsHexPrefix(false);
		field.setHexMode();
		triggerText(textField, "abc");
		assertEquals(0xabc, field.getIntValue());
	}

	@Test
	public void testNegative() {
		triggerText(textField, "-123");
		assertEquals(-123, field.getIntValue());
	}

	@Test
	public void testNegativeHex() {
		triggerText(textField, "-0xa");
		assertEquals(-10, field.getIntValue());
	}

	@Test
	public void testNegativeNotAllowed() {
		field.setAllowNegativeValues(false);
		triggerText(textField, "-123");
		assertEquals(123, field.getIntValue());
	}

	@Test
	public void testSetNegativeWithCurrentNegativeValue() {
		field.setValue(-123);
		field.setAllowNegativeValues(false);
		assertEquals(null, field.getValue());
	}

	@Test
	public void testMax() {
		field.setMaxValue(BigInteger.valueOf(13l));
		triggerText(textField, "12");
		assertEquals(12, field.getIntValue());

		field.setValue(null);
		triggerText(textField, "13");
		assertEquals(13, field.getIntValue());

		field.setValue(null);
		triggerText(textField, "14");// four should be ignored
		assertEquals(1, field.getIntValue());

	}

	@Test
	public void testSetMaxToValueSmallerThanCurrent() {
		field.setValue(500);
		field.setMaxValue(BigInteger.valueOf(400));
		assertEquals(400, field.getIntValue());
	}

	@Test
	public void testMaxInHex() {
		field.setMaxValue(BigInteger.valueOf(0xd));
		triggerText(textField, "0xc");
		assertEquals(12, field.getIntValue());

		field.setValue(null);
		triggerText(textField, "0xd");
		assertEquals(13, field.getIntValue());

		field.setValue(null);
		triggerText(textField, "0xe");// e should be ignored
		assertEquals(0, field.getIntValue());

	}

	@Test
	public void testSwitchingHexMode() {
		field.setValue(255);
		assertEquals("255", field.getText());
		field.setHexMode();
		assertEquals("0xff", field.getText());
		field.setDecimalMode();
		assertEquals("255", field.getText());
	}

	@Test
	public void testChangeListenerAfterValidInput() {
		TestChangeListener listener = new TestChangeListener();
		field.addChangeListener(listener);

		triggerText(textField, "123");
		assertEquals(3, listener.count);
		assertEquals(1, listener.values.get(0));
		assertEquals(12, listener.values.get(1));
		assertEquals(123, listener.values.get(2));

		triggerBackspaceKey(textField);
		assertEquals(12, listener.values.get(3));

	}

	@Test
	public void testChangeListenerAfterSwitchingModes() {
		triggerText(textField, "123");

		TestChangeListener listener = new TestChangeListener();
		field.addChangeListener(listener);

		setHexMode();

		assertEquals(2, listener.count);
		assertEquals(123, listener.values.get(1));

	}

	@Test
	public void testNegativeHexFromValue() {
		field.setValue(-255);
		setHexMode();
		assertEquals("-0xff", field.getText());
	}

	@Test
	public void testNullValue() {
		field.setValue(12);
		assertEquals("12", field.getText());
		field.setValue(null);
		assertEquals("", field.getText());
		assertEquals(0, field.getIntValue());
		assertEquals(0l, field.getLongValue());
		assertEquals(null, field.getValue());
	}

	@Test
	public void testHexValueInDontRequireHexPrefixMode() {
		field.setAllowsHexPrefix(false);
		field.setHexMode();
		field.setValue(255);
		assertEquals("ff", field.getText());
	}

	@Test
	public void testSetNotAllowNegativeModeWhileCurrentValueIsNegative() {
		field.setValue(-10);
		field.setAllowNegativeValues(false);
		assertEquals("", field.getText());
		assertEquals(0, field.getIntValue());
	}

	@Test
	public void testSetLongValue() {
		field.setValue(100L);
		assertEquals(100L, field.getLongValue());
		assertEquals(100, field.getIntValue());
	}

	@Test
	public void testSettingNegativeNumberWhenNegativesArentAllowed() {
		field.setValue(10);
		field.setAllowNegativeValues(false);
		field.setValue(-10);
		assertEquals("", field.getText());
	}

	@Test
	public void testUseHexPrefixUpdatesTextField() {
		field.setAllowsHexPrefix(false);
		field.setHexMode();
		field.setValue(255);
		assertEquals("ff", field.getText());
		field.setAllowsHexPrefix(true);
		assertEquals("0xff", field.getText());
	}

	private void setHexMode() {
		runSwing(() -> field.setHexMode());
		waitForSwing();
	}

	class TestChangeListener implements ChangeListener {
		volatile int count;
		private AtomicIntegerArray values = new AtomicIntegerArray(10);

		@Override
		public void stateChanged(ChangeEvent e) {
			values.set(count++, field.getIntValue());
		}

	}

}
