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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.datatype.microsoft.GUID;

public class PdbByteWriterReaderTest extends AbstractGenericTest {

	//==============================================================================================
	// Tests
	//==============================================================================================
	@Test
	public void testWriter() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();

		byte[] byteArrayTest1 = new byte[3];
		byteArrayTest1[0] = (byte) 0xe7;
		byteArrayTest1[1] = (byte) 0xc3;
		byteArrayTest1[2] = (byte) 0x81;

		int byteValueTest1 = 0xff;
		int byteValueTest2 = 0x00;

		short shortValueTest1 = Short.MAX_VALUE;
		short shortValueTest2 = Short.MIN_VALUE;

		int unsignedShortValueTest1 = 0xffff;
		int unsignedShortValueTest2 = 0x0123;

		int intValueTest1 = Integer.MAX_VALUE;
		int intValueTest2 = Integer.MIN_VALUE;

		long unsignedIntValueTest1 = 0xffffffffL;
		long unsignedIntValueTest2 = 0x01234567L;

		long longValueTest1 = Long.MAX_VALUE;
		long longValueTest2 = Long.MIN_VALUE;

		BigInteger unsignedLongValueTest1 = new BigInteger("ffffffffffffffff", 16);
		BigInteger unsignedLongValueTest2 = new BigInteger("0123456789abcdef", 16);

		BigInteger numericValueTest1 = new BigInteger("12", 16);
		int numericCodeTest1 = 0x8000;
		BigInteger numericValueTest2 = new BigInteger("2345", 16);
		int numericCodeTest2 = 0x8001;
		BigInteger numericValueTest3 = new BigInteger("3456", 16);
		int numericCodeTest3 = 0x8002;
		BigInteger numericValueTest4 = new BigInteger("456789ab", 16);
		int numericCodeTest4 = 0x8003;
		BigInteger numericValueTest5 = new BigInteger("56789abc", 16);
		int numericCodeTest5 = 0x8004;
		BigInteger numericValueTest6 = new BigInteger("6789abcdef012345", 16);
		int numericCodeTest6 = 0x8009;
		BigInteger numericValueTest7 = new BigInteger("789abcdef0123456", 16);
		int numericCodeTest7 = 0x800a;

		String stringTest1 = new String("abcd");
		String stringTest2 = new String("efgh");
		String stringTest3 = new String("ijkl");
		String stringTest4 = new String("mnop");
		String stringTest5 = new String("qrst");

		writer.putBytes(byteArrayTest1, byteArrayTest1.length);
		writer.putUnsignedByte(byteValueTest1);
		writer.putUnsignedByte(byteValueTest2);
		writer.putShort(shortValueTest1);
		writer.putShort(shortValueTest2);
		writer.putUnsignedShort(unsignedShortValueTest1);
		writer.putUnsignedShort(unsignedShortValueTest2);
		writer.putInt(intValueTest1);
		writer.putInt(intValueTest2);
		writer.putUnsignedInt(unsignedIntValueTest1);
		writer.putUnsignedInt(unsignedIntValueTest2);
		writer.putLong(longValueTest1);
		writer.putLong(longValueTest2);
		writer.putUnsignedLong(unsignedLongValueTest1);
		writer.putUnsignedLong(unsignedLongValueTest2);
		writer.putNumeric(numericValueTest1, numericCodeTest1);
		writer.putNumeric(numericValueTest2, numericCodeTest2);
		writer.putNumeric(numericValueTest3, numericCodeTest3);
		writer.putNumeric(numericValueTest4, numericCodeTest4);
		writer.putNumeric(numericValueTest5, numericCodeTest5);
		writer.putNumeric(numericValueTest6, numericCodeTest6);
		writer.putNumeric(numericValueTest7, numericCodeTest7);
		writer.putByteLengthPrefixedString(stringTest1);
		writer.putByteLengthPrefixedUtf8String(stringTest2);
		writer.putNullTerminatedString(stringTest3);
		writer.putNullTerminatedUtf8String(stringTest4);
		writer.putNullTerminatedWchartString(stringTest5);

		writer.putGUID(0x0f0e0d0c, (short) 0x0b0a, (short) 0x0908,
			new byte[] { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 });

		writer.putAlign(1);
		writer.putPadding(2);

		byte[] byteArrayValue;
		int byteValue;
		short shortValue;
		int unsignedShortValue;
		int intValue;
		long unsignedIntValue;
		long longValue;
		BigInteger unsignedLongValue;
		BigInteger numericValue;
		String string;
		GUID guid;

		byte[] buffer = writer.get();
		PdbByteReader reader = new PdbByteReader(buffer);

		byteArrayValue = reader.parseBytes(3);
		assertArrayEquals(byteArrayTest1, byteArrayValue);

		byteValue = reader.parseUnsignedByteVal();
		assertEquals(byteValue, byteValueTest1);
		byteValue = reader.parseUnsignedByteVal();
		assertEquals(byteValue, byteValueTest2);

		shortValue = reader.parseShort();
		assertEquals(shortValue, shortValueTest1);
		shortValue = reader.parseShort();
		assertEquals(shortValue, shortValueTest2);

		unsignedShortValue = reader.parseUnsignedShortVal();
		assertEquals(unsignedShortValue, unsignedShortValueTest1);
		unsignedShortValue = reader.parseUnsignedShortVal();
		assertEquals(unsignedShortValue, unsignedShortValueTest2);

		intValue = reader.parseInt();
		assertEquals(intValue, intValueTest1);
		intValue = reader.parseInt();
		assertEquals(intValue, intValueTest2);

		unsignedIntValue = reader.parseUnsignedIntVal();
		assertEquals(unsignedIntValue, unsignedIntValueTest1);
		unsignedIntValue = reader.parseUnsignedIntVal();
		assertEquals(unsignedIntValue, unsignedIntValueTest2);

		longValue = reader.parseLong();
		assertEquals(longValue, longValueTest1);
		longValue = reader.parseLong();
		assertEquals(longValue, longValueTest2);

		unsignedLongValue = reader.parseUnsignedLongVal();
		assertEquals(unsignedLongValue.compareTo(unsignedLongValueTest1), 0);
		unsignedLongValue = reader.parseUnsignedLongVal();
		assertEquals(unsignedLongValue.compareTo(unsignedLongValueTest2), 0);

		Numeric numeric;
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest1), 0);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest2), 0);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest3), 0);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest4), 0);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest5), 0);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest6), 0);
		numeric = new Numeric(reader);
		if (!numeric.isIntegral()) {
			throw new PdbException("Expecting integral numeric");
		}
		numericValue = numeric.getIntegral();
		assertEquals(numericValue.compareTo(numericValueTest7), 0);

		string = reader.parseByteLengthPrefixedString(StandardCharsets.UTF_8);
		assertEquals(string, stringTest1);
		string = reader.parseByteLengthPrefixedUtf8String();
		assertEquals(string, stringTest2);
		string = reader.parseNullTerminatedString(StandardCharsets.UTF_8);
		assertEquals(string, stringTest3);
		string = reader.parseNullTerminatedUtf8String();
		assertEquals(string, stringTest4);
		string = reader.parseNullTerminatedWcharString(StandardCharsets.UTF_16);
		assertEquals(string, stringTest5);

		guid = reader.parseGUID();
		assertEquals("0f0e0d0c-0b0a-0908-0706-050403020100", guid.toString());

		byteArrayValue = reader.parseBytesRemaining();
		assertEquals(byteArrayValue.length, 2);
		assertEquals(byteArrayValue[0], 0x00);
		assertEquals(byteArrayValue[1], (byte) 0xf1);
	}

}
