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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.LittleEndianDataConverter;

public class NumericTest extends AbstractGenericTest {

	private static final BigInteger UNSIGNED_LONG_MAX = new BigInteger("ffffffffffffffff", 16);
	private static final BigInteger OCTOWORD_MIN =
		new BigInteger("-80000000000000000000000000000000", 16);
	private static final BigInteger OCTOWORD_MAX =
		new BigInteger("7fffffffffffffffffffffffffffffff", 16);
	private static final BigInteger UNSIGNED_OCTOWORD_MAX =
		new BigInteger("ffffffffffffffffffffffffffffffff", 16);

	private byte[] getCharByte(short value) {
		if (value < -128 || value > 127) {
			throw new IllegalArgumentException("Char out of range");
		}
		return Arrays.copyOfRange(LittleEndianDataConverter.INSTANCE.getBytes(value), 0, 1);
	}

	private static byte[] getShortBytes(short value) {
		return LittleEndianDataConverter.INSTANCE.getBytes(value);
	}

	private static byte[] getUnsignedShortBytes(int value) {
		if (value < 0 || value > 0xffff) {
			throw new IllegalArgumentException("Unsigned Short out of range");
		}
		return Arrays.copyOfRange(LittleEndianDataConverter.INSTANCE.getBytes(value), 0, 2);
	}

	private static byte[] getIntBytes(int value) {
		return LittleEndianDataConverter.INSTANCE.getBytes(value);
	}

	private static byte[] getUnsignedIntBytes(long value) {
		if (value < 0 || value > 0xffffffffL) {
			throw new IllegalArgumentException("Unsigned Int out of range");
		}
		return Arrays.copyOfRange(LittleEndianDataConverter.INSTANCE.getBytes(value), 0, 4);
	}

	private static byte[] getLongBytes(long value) {
		return LittleEndianDataConverter.INSTANCE.getBytes(value);
	}

	private static byte[] getUnsignedLongBytes(BigInteger value) {
		if (value.compareTo(BigInteger.ZERO) < 0 || value.compareTo(UNSIGNED_LONG_MAX) > 0) {
			throw new IllegalArgumentException("Unsigned Long out of range");
		}
		return LittleEndianDataConverter.INSTANCE.getBytes(value, 16);
	}

	private static byte[] getOctowordBytes(BigInteger value) {
		if (value.compareTo(OCTOWORD_MIN) < 0 || value.compareTo(OCTOWORD_MAX) > 0) {
			throw new IllegalArgumentException("Octoword out of range");
		}
		return LittleEndianDataConverter.INSTANCE.getBytes(value, 32);
	}

	private static byte[] getUnsignedOctowordBytes(BigInteger value) {
		if (value.compareTo(BigInteger.ZERO) < 0 || value.compareTo(UNSIGNED_OCTOWORD_MAX) > 0) {
			throw new IllegalArgumentException("Unsigned Octoword out of range");
		}
		return LittleEndianDataConverter.INSTANCE.getBytes(value, 32);
	}

	private static byte[] getSubTypeBytes(int value) {
		return getUnsignedShortBytes(value);
	}

	//==============================================================================================
	// Tests
	//==============================================================================================
	@Test
	public void testNumericNoSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x0000;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		PdbByteReader reader = new PdbByteReader(subTypeBytes);
		Numeric numeric = new Numeric(reader);
		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(unsignedShortSubType, longResult);
	}

	@Test
	public void testNumericNoSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x7fff;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		PdbByteReader reader = new PdbByteReader(subTypeBytes);
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(unsignedShortSubType, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericCharSubTypeMin() throws Exception {
		int unsignedShortSubType = 0x8000;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		short charVal = -128;
		byte[] valBytes = getCharByte(charVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(charVal, longResult);
	}

	@Test
	public void testNumericCharSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8000;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		short charVal = 0;
		byte[] valBytes = getCharByte(charVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(charVal, longResult);
	}

	@Test
	public void testNumericCharSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8000;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		short charVal = 127;
		byte[] valBytes = getCharByte(charVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(charVal, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericShortSubTypeMin() throws Exception {
		int unsignedShortSubType = 0x8001;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		short shortVal = Short.MIN_VALUE;
		byte[] valBytes = getShortBytes(shortVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(shortVal, longResult);
	}

	@Test
	public void testNumericShortSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8001;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		short shortVal = 0x0000;
		byte[] valBytes = getShortBytes(shortVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(shortVal, longResult);
	}

	@Test
	public void testNumericShortSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8001;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		short shortVal = Short.MAX_VALUE;
		byte[] valBytes = getShortBytes(shortVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(shortVal, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericUnsignedShortSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8002;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		int unsignedShortVal = 0x0;
		byte[] valBytes = getUnsignedShortBytes(unsignedShortVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(unsignedShortVal, longResult);
	}

	@Test
	public void testNumericUnsignedShortSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8002;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		int unsignedShortVal = 0xffff;
		byte[] valBytes = getUnsignedShortBytes(unsignedShortVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(unsignedShortVal, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericIntSubTypeMin() throws Exception {
		int unsignedShortSubType = 0x8003;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		int intVal = Integer.MIN_VALUE;
		byte[] valBytes = getIntBytes(intVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(intVal, longResult);
	}

	@Test
	public void testNumericIntSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8003;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		int intVal = 0x00000000;
		byte[] valBytes = getIntBytes(intVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(intVal, longResult);
	}

	@Test
	public void testNumericIntSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8003;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		int intVal = Integer.MAX_VALUE;
		byte[] valBytes = getIntBytes(intVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(intVal, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericUnsignedIntSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8004;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		long unsignedIntVal = 0x0L;
		byte[] valBytes = getUnsignedIntBytes(unsignedIntVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(unsignedIntVal, longResult);
	}

	@Test
	public void testNumericUnsignedIntSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8004;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		long unsignedIntVal = 0xffffffffL;
		byte[] valBytes = getUnsignedIntBytes(unsignedIntVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(unsignedIntVal, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericLongSubTypeMin() throws Exception {
		int unsignedShortSubType = 0x8009;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		long longVal = Long.MIN_VALUE;
		byte[] valBytes = getLongBytes(longVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(longVal, longResult);
	}

	@Test
	public void testNumericLongSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8009;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		long longVal = 0x0L;
		byte[] valBytes = getLongBytes(longVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(longVal, longResult);
	}

	@Test
	public void testNumericLongSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8009;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		long longVal = Long.MAX_VALUE;
		byte[] valBytes = getLongBytes(longVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		long longResult = bigResult.longValueExact();
		assertEquals(longVal, longResult);
	}

	//**********************************************************************************************
	@Test
	public void testNumericUnsignedLongSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x800a;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger unsignedLongVal = new BigInteger("0", 16);
		byte[] valBytes = getUnsignedLongBytes(unsignedLongVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(unsignedLongVal), 0);
	}

	@Test
	public void testNumericUnsignedLongSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x800a;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger unsignedLongVal = new BigInteger("ffffffffffffffff", 16);
		byte[] valBytes = getUnsignedLongBytes(unsignedLongVal);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(unsignedLongVal), 0);
	}

	//**********************************************************************************************
	@Test
	public void testNumericOctowordSubTypeMin() throws Exception {
		int unsignedShortSubType = 0x8017;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger octowordVal = new BigInteger("-80000000000000000000000000000000", 16);
		byte[] valBytes = getOctowordBytes(octowordVal);
		assertEquals(valBytes.length, 32);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(octowordVal), 0);
	}

	@Test
	public void testNumericOctowordSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8017;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger octowordVal = new BigInteger("0", 16);
		byte[] valBytes = getOctowordBytes(octowordVal);
		assertEquals(valBytes.length, 32);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(octowordVal), 0);
	}

	@Test
	public void testNumericOctowordSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8017;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger octowordVal = new BigInteger("7fffffffffffffffffffffffffffffff", 16);
		byte[] valBytes = getOctowordBytes(octowordVal);
		assertEquals(valBytes.length, 32);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(octowordVal), 0);
	}

	//**********************************************************************************************
	@Test
	public void testNumericUnsignedOctowordSubTypeZero() throws Exception {
		int unsignedShortSubType = 0x8018;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger unsignedOctowordVal = new BigInteger("0", 16);
		byte[] valBytes = getUnsignedOctowordBytes(unsignedOctowordVal);
		assertEquals(valBytes.length, 32);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(unsignedOctowordVal), 0);
	}

	@Test
	public void testNumericUnsignedOctowordSubTypeMax() throws Exception {
		int unsignedShortSubType = 0x8018;
		byte[] subTypeBytes = getSubTypeBytes(unsignedShortSubType);
		BigInteger unsignedOctowordVal = new BigInteger("ffffffffffffffffffffffffffffffff", 16);
		byte[] valBytes = getUnsignedOctowordBytes(unsignedOctowordVal);
		assertEquals(valBytes.length, 32);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(subTypeBytes, subTypeBytes.length);
		writer.putBytes(valBytes, valBytes.length);
		PdbByteReader reader = new PdbByteReader(writer.get());
		Numeric numeric = new Numeric(reader);

		assertTrue(numeric.isIntegral());
		assertEquals(unsignedShortSubType, numeric.getSubTypeIndex());
		BigInteger bigResult = numeric.getIntegral();
		assertEquals(bigResult.compareTo(unsignedOctowordVal), 0);
	}

}
