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
package ghidra.pcode.floatformat;

import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.pcode.floatformat.FloatFormat.FloatData;

public class FloatFormatTest extends AbstractGenericTest {

	public FloatFormatTest() {
		super();
	}

	@Test
	public void testCreateFloat() {
		double x = 4.5;
		FloatData data = FloatFormat.extractExpSig(x);
		double y = FloatFormat.createFloat(data.sign, data.mantisa, data.exp);
		Assert.assertEquals(x, y, 0);

		x = -4.5;
		data = FloatFormat.extractExpSig(x);
		y = FloatFormat.createFloat(data.sign, data.mantisa, data.exp);
		Assert.assertEquals(x, y, 0);

		x = 0.00000000000000000000000045;
		data = FloatFormat.extractExpSig(x);
		y = FloatFormat.createFloat(data.sign, data.mantisa, data.exp);
		Assert.assertEquals(x, y, 0);

		x = -0.000000000000000000000000045;
		data = FloatFormat.extractExpSig(x);
		y = FloatFormat.createFloat(data.sign, data.mantisa, data.exp);
		Assert.assertEquals(x, y, 0);
	}

	@Test
	public void testGetHostFloatBigInteger() {

		/// 32-bit encoding

		FloatFormat ff = new FloatFormat(4);
		float f = 4.5f;
		int intbits = Float.floatToRawIntBits(f);
		BigDecimal big = BigDecimal.valueOf(f);
		BigInteger encoding = ff.getEncoding(big);
		Assert.assertEquals(intbits, encoding.longValue());
		Assert.assertEquals(big, ff.getHostFloat(encoding));

//		f = 8.908155E-39f;
//		intbits = Float.floatToRawIntBits(f);
//		big = BigDecimal.valueOf(f);
//		encoding = ff.getEncoding(big);
//		Assert.assertEquals(intbits, encoding.longValue());
//		Assert.assertEquals(big, ff.getHostFloat(encoding));

		f = 3.75f;
		intbits = Float.floatToRawIntBits(f);
		big = BigDecimal.valueOf(f);
		encoding = ff.getEncoding(big);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding.longValue());
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		f = -4.5f;
		intbits = Float.floatToRawIntBits(f);
		big = BigDecimal.valueOf(f);
		encoding = ff.getEncoding(big);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding.longValue());
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		f = Float.POSITIVE_INFINITY;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		Assert.assertEquals(intbits, encoding.longValue());
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(encoding));

		f = Float.NEGATIVE_INFINITY;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding.longValue());
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(encoding));

		f = Float.NaN;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(FloatFormat.BIG_NaN);
		Assert.assertEquals(intbits, encoding.longValue());
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(encoding));

		/// 64-bit encoding

		ff = new FloatFormat(8);
		double d = 4.5d;
		long longbits = Double.doubleToRawLongBits(d);
		big = BigDecimal.valueOf(d);
		encoding = ff.getEncoding(big);
		Assert.assertEquals(longbits, encoding.longValue());
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		d = 3.75d;
		longbits = Double.doubleToRawLongBits(d);
		big = BigDecimal.valueOf(d);
		encoding = ff.getEncoding(big);
		Assert.assertEquals(longbits, encoding.longValue());
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		d = -4.5d;
		longbits = Double.doubleToRawLongBits(d);
		big = BigDecimal.valueOf(d);
		encoding = ff.getEncoding(big);
		Assert.assertEquals(longbits, encoding.longValue());
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		d = Double.POSITIVE_INFINITY;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		Assert.assertEquals(longbits, encoding.longValue());
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(encoding));

		d = Double.NEGATIVE_INFINITY;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		Assert.assertEquals(longbits, encoding.longValue());
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(encoding));

		d = Double.NaN;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(FloatFormat.BIG_NaN);
		Assert.assertEquals(longbits, encoding.longValue());
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(encoding));

		/// 80-bit encoding

		ff = new FloatFormat(10);
		big = BigDecimal.valueOf(4.5);
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = BigDecimal.valueOf(3.75);
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = BigDecimal.valueOf(-4.5);
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = FloatFormat.BIG_POSITIVE_INFINITY;
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = FloatFormat.BIG_NEGATIVE_INFINITY;
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = FloatFormat.BIG_NaN;
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		/// 128-bit encoding

		ff = new FloatFormat(16);
		big = BigDecimal.valueOf(4.5);
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = BigDecimal.valueOf(3.75);
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = BigDecimal.valueOf(-4.5);
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = FloatFormat.BIG_POSITIVE_INFINITY;
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = FloatFormat.BIG_NEGATIVE_INFINITY;
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

		big = FloatFormat.BIG_NaN;
		encoding = ff.getEncoding(big);
		// use round trip to verify
		Assert.assertEquals(big, ff.getHostFloat(encoding));

	}

	@Test
	public void testGetHostFloat() {

		/// 32-bit encoding

		FloatFormat ff = new FloatFormat(4);
		float f = 4.5f;
		int intbits = Float.floatToRawIntBits(f);
		long encoding = ff.getEncoding(f);
		Assert.assertEquals(intbits, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		f = 8.908155E-39f;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(f);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		f = 3.75f;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(f);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		f = -4.5f;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(f);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		f = Float.POSITIVE_INFINITY;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(f);
		Assert.assertEquals(intbits, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		f = Float.NEGATIVE_INFINITY;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(f);
		Assert.assertEquals((intbits) & 0xffffffffL, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		f = Float.NaN;
		intbits = Float.floatToRawIntBits(f);
		encoding = ff.getEncoding(f);
		Assert.assertEquals(intbits, encoding);
		Assert.assertEquals(f, (float) ff.getHostFloat(encoding), 0);

		/// 64-bit encoding

		ff = new FloatFormat(8);
		double d = 4.5d;
		long longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(d);
		Assert.assertEquals(longbits, encoding);
		Assert.assertEquals(d, ff.getHostFloat(encoding), 0);

		d = 3.75d;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(d);
		Assert.assertEquals(longbits, encoding);
		Assert.assertEquals(d, ff.getHostFloat(encoding), 0);

		d = -4.5d;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(d);
		Assert.assertEquals(longbits, encoding);
		Assert.assertEquals(d, ff.getHostFloat(encoding), 0);

		d = Double.POSITIVE_INFINITY;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(d);
		Assert.assertEquals(longbits, encoding);
		Assert.assertEquals(d, ff.getHostFloat(encoding), 0);

		d = Double.NEGATIVE_INFINITY;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(d);
		Assert.assertEquals(longbits, encoding);
		Assert.assertEquals(d, ff.getHostFloat(encoding), 0);

		d = Double.NaN;
		longbits = Double.doubleToRawLongBits(d);
		encoding = ff.getEncoding(d);
		Assert.assertEquals(longbits, encoding);
		Assert.assertEquals(d, ff.getHostFloat(encoding), 0);
	}

	@Test
	public void testOpEqualLongLong() {
		FloatFormat ff = new FloatFormat(8);
		Assert.assertEquals(1, ff.opEqual(ff.getEncoding(1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(1, ff.opEqual(ff.getEncoding(-1.234), ff.getEncoding(-1.234)));
		Assert.assertEquals(0, ff.opEqual(ff.getEncoding(-1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(1, ff.opEqual(ff.getEncoding(Double.POSITIVE_INFINITY),
			ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(0, ff.opEqual(ff.getEncoding(Double.POSITIVE_INFINITY),
			ff.getEncoding(Double.NEGATIVE_INFINITY)));
		Assert.assertEquals(1, ff.opEqual(ff.getEncoding(Double.NEGATIVE_INFINITY),
			ff.getEncoding(Double.NEGATIVE_INFINITY)));
		Assert.assertEquals(0,
			ff.opEqual(ff.getEncoding(Double.POSITIVE_INFINITY), ff.getEncoding(Double.NaN)));
	}

	@Test
	public void testOpEqualBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);
		BigDecimal a = BigDecimal.valueOf(1.234d);
		BigDecimal b = BigDecimal.valueOf(-1.234d);
		Assert.assertEquals(BigInteger.ONE, ff.opEqual(ff.getEncoding(a), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE, ff.opEqual(ff.getEncoding(b), ff.getEncoding(b)));
		Assert.assertEquals(BigInteger.ZERO, ff.opEqual(ff.getEncoding(b), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opEqual(ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NaN)));
	}

	@Test
	public void testOpNotEqualLongLong() {
		FloatFormat ff = new FloatFormat(8);
		Assert.assertEquals(0, ff.opNotEqual(ff.getEncoding(1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(0, ff.opNotEqual(ff.getEncoding(-1.234), ff.getEncoding(-1.234)));
		Assert.assertEquals(1, ff.opNotEqual(ff.getEncoding(-1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(0, ff.opNotEqual(ff.getEncoding(Double.POSITIVE_INFINITY),
			ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(1, ff.opNotEqual(ff.getEncoding(Double.POSITIVE_INFINITY),
			ff.getEncoding(Double.NEGATIVE_INFINITY)));
		Assert.assertEquals(0, ff.opNotEqual(ff.getEncoding(Double.NEGATIVE_INFINITY),
			ff.getEncoding(Double.NEGATIVE_INFINITY)));
		Assert.assertEquals(1,
			ff.opNotEqual(ff.getEncoding(Double.POSITIVE_INFINITY), ff.getEncoding(Double.NaN)));
	}

	@Test
	public void testOpNotEqualBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);
		BigDecimal a = BigDecimal.valueOf(1.234d);
		BigDecimal b = BigDecimal.valueOf(-1.234d);
		Assert.assertEquals(BigInteger.ZERO, ff.opNotEqual(ff.getEncoding(a), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ZERO, ff.opNotEqual(ff.getEncoding(b), ff.getEncoding(b)));
		Assert.assertEquals(BigInteger.ONE, ff.opNotEqual(ff.getEncoding(b), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opNotEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opNotEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opNotEqual(ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opNotEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NaN)));
	}

	@Test
	public void testOpLessLongLong() {
		FloatFormat ff = new FloatFormat(8);

		Assert.assertEquals(0, ff.opLess(ff.getEncoding(1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(0, ff.opLess(ff.getEncoding(-1.234), ff.getEncoding(-1.234)));
		Assert.assertEquals(0, ff.opLess(ff.getEncoding(1.234), ff.getEncoding(-1.234)));
		Assert.assertEquals(0, ff.opLess(ff.getEncoding(0), ff.getEncoding(-1.234)));

		Assert.assertEquals(1, ff.opLess(ff.getEncoding(0), ff.getEncoding(1.234)));
		Assert.assertEquals(1, ff.opLess(ff.getEncoding(-1.234), ff.getEncoding(1.234)));

		Assert.assertEquals(0,
			ff.opLess(ff.getEncoding(Double.POSITIVE_INFINITY), ff.getEncoding(1.234)));
		Assert.assertEquals(1,
			ff.opLess(ff.getEncoding(Double.NEGATIVE_INFINITY), ff.getEncoding(1.234)));
		Assert.assertEquals(1,
			ff.opLess(ff.getEncoding(1.234), ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(0,
			ff.opLess(ff.getEncoding(1.234), ff.getEncoding(Double.NEGATIVE_INFINITY)));

		Assert.assertEquals(0, ff.opLess(ff.getEncoding(Double.POSITIVE_INFINITY),
			ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(1, ff.opLess(ff.getEncoding(Double.NEGATIVE_INFINITY),
			ff.getEncoding(Double.POSITIVE_INFINITY)));
	}

	@Test
	public void testOpLessBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);
		BigDecimal a = BigDecimal.valueOf(1.234d);
		BigDecimal b = BigDecimal.valueOf(-1.234d);

		Assert.assertEquals(BigInteger.ZERO, ff.opLess(ff.getEncoding(a), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ZERO, ff.opLess(ff.getEncoding(b), ff.getEncoding(b)));
		Assert.assertEquals(BigInteger.ZERO, ff.opLess(ff.getEncoding(a), ff.getEncoding(b)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opLess(ff.getEncoding(BigDecimal.ZERO), ff.getEncoding(b)));

		Assert.assertEquals(BigInteger.ONE,
			ff.opLess(ff.getEncoding(BigDecimal.ZERO), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE, ff.opLess(ff.getEncoding(b), ff.getEncoding(a)));

		Assert.assertEquals(BigInteger.ZERO,
			ff.opLess(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opLess(ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opLess(ff.getEncoding(a), ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opLess(ff.getEncoding(a), ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));

		Assert.assertEquals(BigInteger.ZERO,
			ff.opLess(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opLess(ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
	}

	@Test
	public void testOpLessEqualLongLong() {
		FloatFormat ff = new FloatFormat(8);

		Assert.assertEquals(1, ff.opLessEqual(ff.getEncoding(1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(1, ff.opLessEqual(ff.getEncoding(-1.234), ff.getEncoding(-1.234)));

		Assert.assertEquals(0, ff.opLessEqual(ff.getEncoding(1.234), ff.getEncoding(-1.234)));
		Assert.assertEquals(0, ff.opLessEqual(ff.getEncoding(0), ff.getEncoding(-1.234)));

		Assert.assertEquals(1, ff.opLessEqual(ff.getEncoding(0), ff.getEncoding(1.234)));
		Assert.assertEquals(1, ff.opLessEqual(ff.getEncoding(-1.234), ff.getEncoding(1.234)));

		Assert.assertEquals(0,
			ff.opLessEqual(ff.getEncoding(Double.POSITIVE_INFINITY), ff.getEncoding(1.234)));
		Assert.assertEquals(1,
			ff.opLessEqual(ff.getEncoding(Double.NEGATIVE_INFINITY), ff.getEncoding(1.234)));
		Assert.assertEquals(1,
			ff.opLessEqual(ff.getEncoding(1.234), ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(0,
			ff.opLessEqual(ff.getEncoding(1.234), ff.getEncoding(Double.NEGATIVE_INFINITY)));

		Assert.assertEquals(1, ff.opLessEqual(ff.getEncoding(Double.POSITIVE_INFINITY),
			ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(1, ff.opLessEqual(ff.getEncoding(Double.NEGATIVE_INFINITY),
			ff.getEncoding(Double.POSITIVE_INFINITY)));
	}

	@Test
	public void testOpLessEqualBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);
		BigDecimal a = BigDecimal.valueOf(1.234d);
		BigDecimal b = BigDecimal.valueOf(-1.234d);

		Assert.assertEquals(BigInteger.ONE, ff.opLessEqual(ff.getEncoding(a), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE, ff.opLessEqual(ff.getEncoding(b), ff.getEncoding(b)));

		Assert.assertEquals(BigInteger.ZERO, ff.opLessEqual(ff.getEncoding(a), ff.getEncoding(b)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opLessEqual(ff.getEncoding(BigDecimal.ZERO), ff.getEncoding(b)));

		Assert.assertEquals(BigInteger.ONE,
			ff.opLessEqual(ff.getEncoding(BigDecimal.ZERO), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE, ff.opLessEqual(ff.getEncoding(b), ff.getEncoding(a)));

		Assert.assertEquals(BigInteger.ZERO,
			ff.opLessEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opLessEqual(ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opLessEqual(ff.getEncoding(a), ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ZERO,
			ff.opLessEqual(ff.getEncoding(a), ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));

		Assert.assertEquals(BigInteger.ONE,
			ff.opLessEqual(ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(BigInteger.ONE,
			ff.opLessEqual(ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
	}

	@Test
	public void testOpNanLong() {
		FloatFormat ff = new FloatFormat(8);
		Assert.assertEquals(1, ff.opNan(ff.getEncoding(Double.NaN)));
		Assert.assertEquals(0, ff.opNan(ff.getEncoding(0)));
		Assert.assertEquals(0, ff.opNan(ff.getEncoding(1.234)));
	}

	@Test
	public void testOpNanBigInteger() {
		FloatFormat ff = new FloatFormat(8);
		Assert.assertEquals(BigInteger.ONE, ff.opNan(ff.getEncoding(FloatFormat.BIG_NaN)));
		Assert.assertEquals(BigInteger.ZERO, ff.opNan(ff.getEncoding(BigDecimal.ZERO)));
		Assert.assertEquals(BigInteger.ZERO, ff.opNan(ff.getEncoding(BigDecimal.valueOf(1.234d))));
	}

	@Test
	public void testOpAddLongLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(1.234);
		long b = ff.getEncoding(1.123);
		long result = ff.opAdd(a, b);// 1.234 + 1.123
		Assert.assertEquals(2.357, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-1.123);
		result = ff.opAdd(a, b);// -1.123 + 1.123
		Assert.assertEquals(0d, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opAdd(a, b);// +INFINITY + 1.123
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opAdd(a, b);// -INFINITY + 1.123
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opAdd(a, b);// -INFINITY + -INFINITY
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opAdd(a, b);// -INFINITY + +INFINITY
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		b = ff.getEncoding(1.123);
		result = ff.opAdd(a, b);// NaN + 1.123
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpAddBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(1.234d));
		BigInteger b = ff.getEncoding(BigDecimal.valueOf(1.123d));
		BigInteger result = ff.opAdd(a, b);// 1.234 + 1.123
		Assert.assertEquals(BigDecimal.valueOf(2.357), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-1.123d));
		result = ff.opAdd(a, b);// -1.123 + 1.123
		Assert.assertEquals(BigDecimal.ZERO, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opAdd(a, b);// +INFINITY + 1.123
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opAdd(a, b);// -INFINITY + 1.123
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opAdd(a, b);// -INFINITY + -INFINITY
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opAdd(a, b);// -INFINITY + +INFINITY
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		b = ff.getEncoding(BigDecimal.valueOf(1.123d));
		result = ff.opAdd(a, b);// NaN + 1.123
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpSubLongLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(1.5);
		long b = ff.getEncoding(1.25);
		long result = ff.opSub(a, b);// 1.5 - 1.25
		Assert.assertEquals(0.25, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-1.25);
		result = ff.opSub(a, b);// -1.25 - 1.25
		Assert.assertEquals(-2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opSub(a, b);// +INFINITY - 1.25
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opSub(a, b);// -INFINITY - 1.25
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opSub(a, b);// -INFINITY - -INFINITY
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opSub(a, b);// -INFINITY - +INFINITY
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		b = ff.getEncoding(1.25);
		result = ff.opSub(a, b);// NaN - 1.25
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpSubBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(1.5d));
		BigInteger b = ff.getEncoding(BigDecimal.valueOf(1.25d));
		BigInteger result = ff.opSub(a, b);// 1.5 - 1.25
		Assert.assertEquals(BigDecimal.valueOf(0.25d), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-1.25d));
		result = ff.opSub(a, b);// -1.25 - 1.25
		Assert.assertEquals(BigDecimal.valueOf(-2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opSub(a, b);// +INFINITY - 1.25
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opSub(a, b);// -INFINITY - 1.25
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opSub(a, b);// -INFINITY - -INFINITY
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opSub(a, b);// -INFINITY - +INFINITY
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		b = ff.getEncoding(BigDecimal.valueOf(1.25d));
		result = ff.opSub(a, b);// NaN - 1.25
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpDivLongLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(3.75);
		long b = ff.getEncoding(1.5);
		long result = ff.opDiv(a, b);
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		b = ff.getEncoding(0);
		result = ff.opDiv(a, b);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-3.75);
		result = ff.opDiv(a, b);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NaN);
		result = ff.opDiv(a, b);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpDivBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(3.75d));
		BigInteger b = ff.getEncoding(BigDecimal.valueOf(1.5d));
		BigInteger result = ff.opDiv(a, b);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		b = ff.getEncoding(BigDecimal.ZERO);
		result = ff.opDiv(a, b);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-3.75d));
		result = ff.opDiv(a, b);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opDiv(a, b);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpMultLongLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long b = ff.getEncoding(1.5);
		long result = ff.opMult(a, b);
		Assert.assertEquals(3.75, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opMult(a, b);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opMult(a, b);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NaN);
		result = ff.opMult(a, b);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpMultBigIntegerBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger b = ff.getEncoding(BigDecimal.valueOf(1.5d));
		BigInteger result = ff.opMult(a, b);
		Assert.assertEquals(BigDecimal.valueOf(3.75d), ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opMult(a, b);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opMult(a, b);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opMult(a, b);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpNegLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = ff.opNeg(a);
		Assert.assertEquals(-2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = ff.opNeg(a);
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opNeg(a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opNeg(a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = ff.opNeg(a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpNegBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = ff.opNeg(a);
		Assert.assertEquals(BigDecimal.valueOf(-2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = ff.opNeg(a);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opNeg(a);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opNeg(a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opNeg(a);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpAbsLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = ff.opAbs(a);
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = ff.opAbs(a);
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opAbs(a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opAbs(a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = ff.opAbs(a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpAbsBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = ff.opAbs(a);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = ff.opAbs(a);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opAbs(a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opAbs(a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opAbs(a);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpSqrtLong() {
		FloatFormat ff = new FloatFormat(8);
		long longbits = ff.getEncoding(2.0);
		longbits = ff.opSqrt(longbits);
		double d = ff.getHostFloat(longbits);
		Assert.assertEquals("1.414213562373095", Double.toString(d).substring(0, 17));
	}

	@Test
	public void testOpSqrtBigInteger() {
		FloatFormat ff = new FloatFormat(8);
		BigDecimal big = BigDecimal.valueOf(2.0);
		BigInteger encoding = ff.getEncoding(big);
		encoding = ff.opSqrt(encoding);
		BigDecimal result = ff.getHostFloat(encoding);
		Assert.assertEquals("1.414213562373095", result.toString());
	}

	@Test
	public void testOpInt2FloatLongInt() {
		FloatFormat ff = new FloatFormat(4);

		long result = ff.opInt2Float(2, 4);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(2.0d, ff.getHostFloat(result), 0);

		result = ff.opInt2Float(-2, 4);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(-2.0d, ff.getHostFloat(result), 0);

		result = ff.opInt2Float(0, 4);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(0d, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpInt2FloatBigIntegerInt() {
		FloatFormat ff = new FloatFormat(4);

		BigInteger limit = BigInteger.ONE.shiftLeft(32);

		BigInteger result = ff.opInt2Float(BigInteger.valueOf(2), 4, true);
		assertTrue(result.compareTo(limit) < 0);// verify that only 4-bytes are used
		Assert.assertEquals(BigDecimal.valueOf(2.0d).stripTrailingZeros(), ff.getHostFloat(result));

		result = ff.opInt2Float(BigInteger.valueOf(-2), 4, true);
		assertTrue(result.compareTo(limit) < 0);// verify that only 4-bytes are used
		Assert.assertEquals(BigDecimal.valueOf(-2.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		result = ff.opInt2Float(BigInteger.ZERO, 4, true);
		assertTrue(result.compareTo(limit) < 0);// verify that only 4-bytes are used
		Assert.assertEquals(BigDecimal.ZERO, ff.getHostFloat(result));
	}

	@Test
	public void testOpFloat2FloatLongFloatFormat() {
		FloatFormat ff8 = new FloatFormat(8);
		FloatFormat ff4 = new FloatFormat(4);

		long a = ff4.getEncoding(1.75);
		long result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(1.75, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(-1.75);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(-1.75, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(Float.POSITIVE_INFINITY);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(Float.NEGATIVE_INFINITY);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(Float.NaN);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(Double.NaN, ff8.getHostFloat(result), 0);

	}

	@Test
	public void testOpFloat2FloatBigIntegerFloatFormat() {
		FloatFormat ff8 = new FloatFormat(8);
		FloatFormat ff4 = new FloatFormat(4);

		BigInteger a = ff4.getEncoding(BigDecimal.valueOf(1.75d));
		BigInteger result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(BigDecimal.valueOf(1.75d), ff8.getHostFloat(result));

		a = ff4.getEncoding(BigDecimal.valueOf(-1.75d));
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(BigDecimal.valueOf(-1.75d), ff8.getHostFloat(result));

		a = ff4.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff8.getHostFloat(result));

		a = ff4.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff8.getHostFloat(result));

		a = ff4.getEncoding(FloatFormat.BIG_NaN);
		result = ff4.opFloat2Float(a, ff8);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff8.getHostFloat(result));
	}

	@Test
	public void testOpTruncLongInt() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = ff.opTrunc(a, 8);
		Assert.assertEquals(2, result);

		a = ff.getEncoding(-2.5);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(-2, result);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(Long.MAX_VALUE, result);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(Long.MIN_VALUE, result);

		// TODO: What should the correct result be?
		a = ff.getEncoding(Double.NaN);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(0, result);
	}

	@Test
	public void testOpTruncBigIntegerInt() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = ff.opTrunc(a, 8);
		Assert.assertEquals(BigInteger.valueOf(2), result);

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(BigInteger.valueOf(-2), result);

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(BigInteger.valueOf(Long.MAX_VALUE), result);

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(BigInteger.valueOf(Long.MIN_VALUE), result);

		// TODO: What should the correct result be?
		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opTrunc(a, 8);
		Assert.assertEquals(BigInteger.ZERO, result);
	}

	@Test
	public void testOpCeilLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = ff.opCeil(a);
		Assert.assertEquals(3.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = ff.opCeil(a);
		Assert.assertEquals(-2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opCeil(a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opCeil(a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = ff.opCeil(a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpCeilBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = ff.opCeil(a);
		Assert.assertEquals(BigDecimal.valueOf(3.0d).stripTrailingZeros(), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = ff.opCeil(a);
		Assert.assertEquals(BigDecimal.valueOf(-2.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opCeil(a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opCeil(a);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opCeil(a);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpFloorLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = ff.opFloor(a);
		Assert.assertEquals(2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.0);
		result = ff.opFloor(a);
		Assert.assertEquals(-2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = ff.opFloor(a);
		Assert.assertEquals(-3.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opFloor(a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opFloor(a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = ff.opFloor(a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpFloorBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = ff.opFloor(a);
		Assert.assertEquals(BigDecimal.valueOf(2.0d).stripTrailingZeros(), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.0d));
		result = ff.opFloor(a);
		Assert.assertEquals(BigDecimal.valueOf(-2.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = ff.opFloor(a);
		Assert.assertEquals(BigDecimal.valueOf(-3.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opFloor(a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opFloor(a);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opFloor(a);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

	@Test
	public void testOpRoundLong() {
		FloatFormat ff = new FloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = ff.opRound(a);
		Assert.assertEquals(3.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(2.25);
		result = ff.opRound(a);
		Assert.assertEquals(2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(2.75);
		result = ff.opRound(a);
		Assert.assertEquals(3.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = ff.opRound(a);
		Assert.assertEquals(-2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.25);
		result = ff.opRound(a);
		Assert.assertEquals(-2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.75);
		result = ff.opRound(a);
		Assert.assertEquals(-3.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = ff.opRound(a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = ff.opRound(a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = ff.opRound(a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testOpRoundBigInteger() {
		FloatFormat ff = new FloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = ff.opRound(a);
		Assert.assertEquals(BigDecimal.valueOf(3.0d).stripTrailingZeros(), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(2.25d));
		result = ff.opRound(a);
		Assert.assertEquals(BigDecimal.valueOf(2.0d).stripTrailingZeros(), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(2.75d));
		result = ff.opRound(a);
		Assert.assertEquals(BigDecimal.valueOf(3.0d).stripTrailingZeros(), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = ff.opRound(a);
		Assert.assertEquals(BigDecimal.valueOf(-2.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.25d));
		result = ff.opRound(a);
		Assert.assertEquals(BigDecimal.valueOf(-2.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.75d));
		result = ff.opRound(a);
		Assert.assertEquals(BigDecimal.valueOf(-3.0d).stripTrailingZeros(),
			ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = ff.opRound(a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = ff.opRound(a);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = ff.opRound(a);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

}
