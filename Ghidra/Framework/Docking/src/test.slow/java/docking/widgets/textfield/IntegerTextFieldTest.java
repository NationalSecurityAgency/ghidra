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

import static docking.widgets.textfield.integer.IntegerFormat.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

public class IntegerTextFieldTest extends AbstractIntegerTextFieldTest<IntegerTextField> {

	@Override
	protected IntegerTextField createField() {
		return new IntegerTextField(10);
	}

	@Test
	public void testDefaultState() {
		assertNull(getBigIntegerValue());// no value
		assertEquals(0, getIntValue());     // the "int value" return for null is 0
		assertEquals(0, getValue());
		assertEquals(DEC, getFormat());
		assertNull(getMaxValue());
	}

	@Test
	public void testTypeValidDecimalNumber() {
		typeText("123");
		assertEquals(123, getIntValue());
	}

	@Test
	public void testTypeValidHexNumber() {
		typeText("0x2abcdef");
		assertEquals(0x2abcdef, getValue());
	}

	@Test
	public void testInvalidCharsIgnored() {
		typeText("123ghijklmnopqrstuvwxyz4");
		assertEquals(1234, getValue());
	}

	@Test
	public void testHexCharsIgnoredInDecimalMode() {
		setFormat(HEX);
		typeText("123ghijklmnopqrstuvwxyz4");
		assertEquals(1234, getValue());
	}

	@Test
	public void testXchangesHexMode() {
		assertEquals(DEC, getFormat());
		typeText("0");
		assertEquals(DEC, getFormat());
		typeText("x");
		assertEquals(HEX, getFormat());
		triggerBackspace(textField);
		assertEquals(HEX, getFormat());
	}

	@Test
	public void testHexModeWithoutPrefix() {
		setFormat(HEX);
		typeText("a");
		assertEquals(null, getBigIntegerValue());

		setUsePrefix(false);
		typeText("abc");
		assertEquals(0xabc, getValue());
	}

	@Test
	public void testNegative() {
		typeText("-123");
		assertEquals(-123, getValue());
	}

	@Test
	public void testNegativeHex() {
		typeText("-0xa");
		assertEquals(-10, getValue());
	}

	@Test
	public void testNegativeNotAllowed() {
		setMinValue(BigInteger.ZERO);
		typeText("-123");
		assertEquals(123, getValue());
	}

	@Test
	public void testSetNegativeWithCurrentNegativeValue() {
		setValue(-123);
		setMinValue(BigInteger.ZERO);
		assertEquals(null, field.getValue());
	}

	@Test
	public void testMax() {
		field.setMaxValue(BigInteger.valueOf(13l));
		typeText("12");
		assertEquals(12, getValue());

		setText("");
		typeText("13");
		assertEquals(13, getValue());

		setText("");
		typeText("14");// four should be ignored
		assertEquals(1, getValue());

	}

	@Test
	public void testSetMaxToValueSmallerThanCurrent() {
		setValue(500);
		field.setMaxValue(BigInteger.valueOf(400));
		assertNull(field.getValue());
	}

	@Test
	public void testMinSetTo1() {
		field.setMinValue(BigInteger.ONE);
		setValue(0);
		assertEquals(1, getValue());

	}

	@Test
	public void testMaxInHex() {
		field.setMaxValue(BigInteger.valueOf(0xd));
		typeText("0xc");
		assertEquals(12, getValue());

		setText("");
		typeText("0xd");
		assertEquals(13, getValue());

		setText("");
		typeText("0xe");// e should be ignored
		assertEquals(0, getValue());

	}

	@Test
	public void testSwitchingHexMode() {
		setValue(255);
		assertEquals("255", field.getText());
		setFormat(HEX);
		assertEquals("0xff", field.getText());
		setFormat(DEC);
		assertEquals("255", field.getText());
	}

	@Test
	public void testChangeListenerAfterValidInput() {
		TestChangeListener listener = new TestChangeListener();
		field.addChangeListener(listener);

		typeText("123");
		assertEquals(3, listener.count);
		assertEquals(1, listener.values.get(0));
		assertEquals(12, listener.values.get(1));
		assertEquals(123, listener.values.get(2));

		triggerBackspace(textField);
		assertEquals(12, listener.values.get(3));

	}

	@Test
	public void testChangeListenerAfterSwitchingModes() {
		setFormat(DEC);
		typeText("12");

		TestChangeListener listener = new TestChangeListener();
		field.addChangeListener(listener);

		setFormat(HEX);
		assertEquals("0xc", getText());

		assertEquals(2, listener.count);
		assertEquals(12, listener.values.get(1));

	}

	@Test
	public void testNegativeHexFromValue() {
		setValue(-255);
		setFormat(HEX);
		assertEquals("-0xff", field.getText());
	}

	@Test
	public void testNullValue() {
		setValue(12);
		assertEquals("12", field.getText());
		setText("");
		assertEquals("", field.getText());
		assertEquals(0, getValue());
		assertEquals(null, getBigIntegerValue());
	}

	@Test
	public void testHexValueInDontRequireHexPrefixMode() {
		field.setUseNumberPrefix(false);
		field.setFormat(HEX);
		setValue(255);
		assertEquals("ff", field.getText());
	}

	@Test
	public void testAutoModeSwitchingIsOffWhenPrefixNotUsed() {
		field.setUseNumberPrefix(false);
		field.setFormat(HEX);
		typeText("15");
		assertEquals(HEX, getFormat());
		assertEquals(21, getValue());
		field.setFormat(DEC);
		field.setText("");
		typeText("0x15");
		assertEquals(DEC, getFormat());
		assertEquals("015", getText());
		assertEquals(15, getValue()); // the 0x should have been ignored
	}

	@Test
	public void testSetNotAllowNegativeModeWhileCurrentValueIsNegative() {
		setValue(-10);
		setMinValue(BigInteger.ZERO);
		assertEquals("", field.getText());
		assertEquals(0, getValue());
	}

	@Test
	public void testSetLongValue() {
		setValue(100L);
		assertEquals(100L, field.getLongValue());
		assertEquals(100, getValue());
	}

	@Test
	public void testSettingNegativeNumberWhenNegativesArentAllowed() {
		setValue(10);
		setMinValue(BigInteger.ZERO);
		setValue(-10);
		assertEquals("", field.getText());
	}

	@Test
	public void testUseHexPrefixUpdatesTextField() {
		field.setUseNumberPrefix(false);
		setFormat(HEX);
		setValue(255);
		assertEquals("ff", field.getText());
		field.setUseNumberPrefix(true);
		assertEquals("0xff", field.getText());
	}

	@Test
	public void testPastingBadText() {
		setFormat(HEX);
		setValue(0);
		assertFalse(field.setText("asdf 0x azzz"));
	}

	@Test
	public void testSetText() {
		setFormat(HEX);
		setValue(0);
		assertTrue(field.setText("0x15"));
		assertEquals(0x15, getValue());
	}

	@Test
	public void testSetTextWithInvalidValue() {
		setFormat(HEX);
		setValue(0);
		assertFalse(field.setText("bad value"));
		assertEquals(0, getValue());
		assertEquals(HEX, getFormat());
	}

	@Test
	public void testSucessfulSetTextChangesHexMode() {
		setFormat(HEX);
		setValue(0);
		assertTrue(field.setText("33"));
		assertEquals(33, getValue());
		assertEquals(DEC, getFormat());

		assertTrue(field.setText("0x33"));
		assertEquals(0x33, getValue());
		assertEquals(HEX, getFormat());
	}

	@Test
	public void testMinValueOfOneDecimalFormat() {
		setFormat(DEC);
		field.setMinValue(BigInteger.ONE);
		typeText("0");
		assertEquals("", field.getText());
		typeText("1");
		assertEquals("1", field.getText());
	}

	@Test
	public void testMinValueOfOneHexFormat() {
		setFormat(HEX);
		field.setMinValue(BigInteger.ONE);
		typeText("0x1");
		assertEquals("0x1", field.getText());
	}

	protected void setMinValue(BigInteger minValue) {
		runSwing(() -> field.setMinValue(minValue));
	}
}
