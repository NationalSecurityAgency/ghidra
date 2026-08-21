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

public class FixedSizeIntegerTextFieldTest
		extends AbstractIntegerTextFieldTest<FixedSizeIntegerTextField> {
	@Override
	protected FixedSizeIntegerTextField createField() {
		return new FixedSizeIntegerTextField(10, 8);
	}

	@Test
	public void testSignedHexSetValue() {
		setFormat(HEX);
		setValue(25);
		assertEquals("0x19", getText());
		setValue(-1);
		assertEquals("-0x1", getText());
	}

	@Test
	public void testSignedHexSetText() {
		setFormat(HEX);
		setText("0x12");
		assertEquals(18, getValue());
		setText("");
		assertEquals(0, getValue());
	}

	@Test
	public void testSignedHexTypeText() {
		setFormat(HEX);
		typeText("mnp0x12");
		assertEquals(18, getValue());
		setText("");
		typeText("-0x5");
		assertEquals(-5, getValue());
	}

	@Test
	public void testSignedHexMin() {
		setFormat(HEX);
		setBitSize(8);

		typeText("-0x8");
		assertEquals("-0x8", getText());
		typeText("1");
		assertEquals("-0x8", getText());	// -0x80 (-128) is min allowed for 8 bits
		typeText("0");
		assertEquals("-0x80", getText());
		assertEquals(-128, getValue());
	}

	@Test
	public void testSignedHexMax() {
		setFormat(HEX);
		setBitSize(8);

		typeText("0x8");
		assertEquals("0x8", getText());
		typeText("0");
		assertEquals("0x8", getText());	// 7f (127) is the max allowed for 8 bits
		setText("");
		typeText("0x7f");
		assertEquals("0x7f", getText());
		assertEquals(127, getValue());
		typeText("1");
		assertEquals("0x7f", getText());
	}

	@Test
	public void testSignedHexConvertsUnsignedValueToNegative() {
		setFormat(HEX);
		setBitSize(8);

		setValue(0xff);
		assertEquals(-1, getValue());
	}

	@Test
	public void testUnsignedHexSetValue() {
		setFormat(U_HEX);
		setValue(25);
		assertEquals("0x19", getText());
		setValue(-130);
		assertEquals("", getText());
		setValue(0xff);
		assertEquals("0xff", getText());
	}

	@Test
	public void testUnsignedHexSetText() {
		setFormat(U_HEX);

		setText("0x12");
		assertEquals(18, getValue());
		setText("-0x1");
		assertEquals(18, getValue()); 	// didn't change the setText was ignored
		setText("0xff");
		assertEquals(255, getValue());
	}

	@Test
	public void testUnsignedHexTypeText() {
		setFormat(U_HEX);
		typeText("mnp0x12");
		setText("0x13");
		assertEquals(19, getValue());
	}

	@Test
	public void testunSignedHexMin() {
		setFormat(U_HEX);
		setBitSize(8);

		typeText("-0x8");
		assertEquals("0x8", getText());
		setText("");
		typeText("0x0");
		assertEquals("0x0", getText());
		assertEquals(0, getValue());
	}

	@Test
	public void testunSignedHexMax() {
		setFormat(U_HEX);
		setBitSize(8);

		typeText("0xff");
		assertEquals("0xff", getText());
		assertEquals(255, getValue());
		setText("");
		typeText("0x10");
		assertEquals("0x10", getText());
		setText("0x10");
		typeText("0");
		assertEquals("0x10", getText());
	}

	@Test
	public void testUnsignedHexConvertsUnsignedValueToNegative() {
		setFormat(U_HEX);
		setBitSize(8);
		setValue(-1);
		assertEquals("0xff", getText());
		assertEquals(255, getValue());
	}

	@Test
	public void testSignedDecimalSetText() {
		setFormat(DEC);
		setText("12");
		assertEquals(12, getValue());
		setText("-4");
		assertEquals(-4, getValue());
	}

	@Test
	public void testSignedDecimalTypeText() {
		setFormat(DEC);
		typeText("mnp12");
		setText("12");
		assertEquals(12, getValue());
		setText("");
		typeText("-5");
		assertEquals(-5, getValue());
	}

	@Test
	public void testSignedDecimalMin() {
		setFormat(DEC);
		setBitSize(8);

		typeText("-128");
		assertEquals("-128", getText());
		setText("");
		typeText("-129");
		assertEquals("-12", getText());
	}

	@Test
	public void testSignedDecimalMax() {
		setFormat(DEC);
		setBitSize(8);

		typeText("127");
		assertEquals("127", getText());
		assertEquals(127, getValue());
		typeText("3");
		assertEquals("127", getText());	// 7f (127) is the max allowed for 8 bits
		setText("");
		typeText("128");
		assertEquals("12", getText());
		assertEquals(12, getValue());
	}

	@Test
	public void testSignedDecimalConvertsUnsignedValueToNegative() {
		setFormat(DEC);
		setBitSize(8);

		setValue(255);
		assertEquals(-1, getValue());
	}

	@Test
	public void testUnsignedDecimalSetValue() {
		setFormat(U_DEC);
		setValue(25);
		assertEquals("25", getText());
		setValue(-130);
		assertEquals("", getText());
		setValue(255);
		assertEquals("255", getText());
	}

	@Test
	public void testUnsignedDecimalSetText() {
		setFormat(U_DEC);

		setText("12");
		assertEquals(12, getValue());
		setText("-0x1");
		assertEquals(12, getValue()); 	// didn't change the setText was ignored
		setText("255");
		assertEquals(255, getValue());
	}

	@Test
	public void testUnsignedDecimalTypeText() {
		setFormat(U_DEC);
		typeText("mnp12");
		setText("12");
		assertEquals(12, getValue());
	}

	@Test
	public void testUnSignedDecimalMin() {
		setFormat(U_DEC);
		setBitSize(8);

		typeText("-8");
		assertEquals("8", getText());
		setText("");
		typeText("0");
		assertEquals("0", getText());
		assertEquals(0, getValue());
	}

	@Test
	public void testUnsignedDecimalMax() {
		setFormat(U_DEC);
		setBitSize(8);

		typeText("255");
		assertEquals("255", getText());
		assertEquals(255, getValue());
		setText("");
		typeText("256");
		assertEquals("25", getText());
	}

	@Test
	public void testUnsignedDecimalConvertsUnsignedValueToNegative() {
		setFormat(U_DEC);
		setBitSize(8);
		setValue(-1);
		assertEquals("255", getText());
		assertEquals(255, getValue());
	}

	@Test
	public void testUnsignedOctSetValue() {
		setFormat(U_OCT);
		setValue(25);
		assertEquals("0O31", getText());
		setValue(-1);
		assertEquals("0O377", getText());
	}

	@Test
	public void testUnsignedOctSetText() {
		setFormat(U_OCT);
		setText("0O12");
		assertEquals(10, getValue());
		setText("");
		assertEquals(0, getValue());
	}

	@Test
	public void testSignedOctTypeText() {
		setFormat(U_OCT);
		typeText("mnp0O12");
		assertEquals(10, getValue());
		setText("");
		typeText("-0O5");	// "-" will be ignored
		assertEquals(5, getValue());
	}

	@Test
	public void testUnsignedBinarySetValue() {
		setFormat(U_BIN);
		setValue(0x25);
		assertEquals("0b100101", getText());
		setValue(-1);
		assertEquals("0b11111111", getText());
	}

	@Test
	public void testUnsignedBinarySetText() {
		setFormat(U_BIN);
		setText("0b101");
		assertEquals(5, getValue());
		setText("");
		assertEquals(0, getValue());
	}

	@Test
	public void testSignedBinaryTypeText() {
		setFormat(U_BIN);
		typeText("mnp0b1210");	// the mnp and 2 are ignored
		assertEquals("0b110", getText());
		assertEquals(6, getValue());
		setText("");
		typeText("-0b101");	// "-" will be ignored
		assertEquals(5, getValue());
	}

	@Test
	public void testChangingBitSizeSigned() {
		setFormat(DEC);
		setBitSize(8);
		setValue(25);
		assertEquals("25", getText());
		assertEquals(BigInteger.valueOf(-128), getMinValue());
		assertEquals(BigInteger.valueOf(127), getMaxValue());

		setBitSize(16);
		assertEquals("25", getText());
		assertEquals(BigInteger.valueOf(-32768), getMinValue());
		assertEquals(BigInteger.valueOf(32767), getMaxValue());

		setValue(32000);
		assertEquals("32000", getText());
		setBitSize(8);
		assertEquals(BigInteger.valueOf(-128), getMinValue());
		assertEquals(BigInteger.valueOf(127), getMaxValue());
		assertEquals("", getText());
	}

	@Test
	public void testChangingBitSizeUnsigned() {
		setFormat(U_DEC);
		setBitSize(8);
		setValue(25);
		assertEquals("25", getText());
		assertEquals(BigInteger.valueOf(0), getMinValue());
		assertEquals(BigInteger.valueOf(255), getMaxValue());

		setBitSize(16);
		assertEquals("25", getText());
		assertEquals(BigInteger.valueOf(0), getMinValue());
		assertEquals(BigInteger.valueOf(65535), getMaxValue());

		setValue(65000);
		assertEquals("65000", getText());
		setBitSize(8);
		assertEquals(BigInteger.valueOf(0), getMinValue());
		assertEquals(BigInteger.valueOf(255), getMaxValue());
		assertEquals("", getText());
	}

	@Test
	public void testChangingFromSignedToUnsignedUpperBitNotSet() {
		setFormat(DEC);
		setBitSize(8);
		setValue(8);
		setFormat(U_DEC);
		assertEquals(8, getValue());
	}

	@Test
	public void testChangingFromSignedToUnsingedUpperBitSet() {
		setFormat(DEC);
		setValue(-1);
		assertEquals(-1, getValue());
		setFormat(U_DEC);
		assertEquals(255, getValue());

	}

	@Test
	public void testChangingFromUnsignedToSignedUpperBitNotSet() {
		setFormat(U_DEC);
		setBitSize(8);
		setValue(8);
		setFormat(DEC);
		assertEquals(8, getValue());
	}

	@Test
	public void testChangingFromUnsignedToSingedUpperBitSet() {
		setFormat(U_DEC);
		setValue(255);
		assertEquals(255, getValue());
		setFormat(DEC);
		assertEquals(-1, getValue());
	}

	protected void setBitSize(int value) {
		runSwing(() -> field.setBitSize(value));
	}
}
