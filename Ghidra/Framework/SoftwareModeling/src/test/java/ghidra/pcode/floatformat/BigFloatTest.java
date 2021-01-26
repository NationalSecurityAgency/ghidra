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

import static org.junit.Assert.*;

import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class BigFloatTest extends AbstractGenericTest {
	public BigFloatTest() {
		super();
	}

	@Test
	public void testIEEEFloatRepresentation() {
		Assert.assertEquals("0b0.0", FloatFormat.toBinaryString(0.0f));
		Assert.assertEquals("0b1.0 * 2^0", FloatFormat.toBinaryString(1.0f));
		Assert.assertEquals("0b1.0 * 2^1", FloatFormat.toBinaryString(2.0f));
		Assert.assertEquals("0b1.0 * 2^-1", FloatFormat.toBinaryString(0.5f));
		Assert.assertEquals("-0b1.0 * 2^1", FloatFormat.toBinaryString(-2.0f));
	}

	@Test
	public void testIEEEFloatAsBigFloat() {
		Assert.assertEquals(FloatFormat.toBigFloat(0.0f).toBinaryString(),
			FloatFormat.toBinaryString(0.0f));
		Assert.assertEquals(FloatFormat.toBigFloat(1.0f).toBinaryString(),
			FloatFormat.toBinaryString(1.0f));
		Assert.assertEquals(FloatFormat.toBigFloat(2.0f).toBinaryString(),
			FloatFormat.toBinaryString(2.0f));
		Assert.assertEquals(FloatFormat.toBigFloat(0.5f).toBinaryString(),
			FloatFormat.toBinaryString(0.5f));
		Assert.assertEquals(FloatFormat.toBigFloat(-2.0f).toBinaryString(),
			FloatFormat.toBinaryString(-2.0f));
	}

	@Test
	public void testIEEEFloatAsBigFloatRandom() {
		Random rand = new Random(1);
		for (int i = 0; i < 100; ++i) {
			float f = Float.intBitsToFloat(rand.nextInt());
			Assert.assertEquals(FloatFormat.toBigFloat(f).toBinaryString(),
				FloatFormat.toBinaryString(f));
		}
	}

	@Test
	public void testIEEEDoubleRepresentation() {
		Assert.assertEquals("0b0.0", FloatFormat.toBinaryString(0.0));
		Assert.assertEquals("0b1.0 * 2^0", FloatFormat.toBinaryString(1.0));
		Assert.assertEquals("0b1.0 * 2^1", FloatFormat.toBinaryString(2.0));
		Assert.assertEquals("0b1.0 * 2^-1", FloatFormat.toBinaryString(0.5));
		Assert.assertEquals("-0b1.0 * 2^1", FloatFormat.toBinaryString(-2.0));
	}

	@Test
	public void testIEEEDoubleAsBigFloat() {
		Assert.assertEquals(FloatFormat.toBigFloat(0.0).toBinaryString(),
			FloatFormat.toBinaryString(0.0));
		Assert.assertEquals(FloatFormat.toBigFloat(1.0).toBinaryString(),
			FloatFormat.toBinaryString(1.0));
		Assert.assertEquals(FloatFormat.toBigFloat(2.0).toBinaryString(),
			FloatFormat.toBinaryString(2.0));
		Assert.assertEquals(FloatFormat.toBigFloat(0.5).toBinaryString(),
			FloatFormat.toBinaryString(0.5));
		Assert.assertEquals(FloatFormat.toBigFloat(-2.0).toBinaryString(),
			FloatFormat.toBinaryString(-2.0));
	}

	@Test
	public void testIEEEDoubleAsBigFloatRandom() {
		Random rand = new Random(1);
		for (int i = 0; i < 100; ++i) {
			double d = Double.longBitsToDouble(rand.nextLong());
			Assert.assertEquals(FloatFormat.toBigFloat(d).toBinaryString(),
				FloatFormat.toBinaryString(d));
		}
	}

	interface UnaryProc<T> {
		void apply(T a);
	}

	interface UnaryOp<T> {
		T apply(T a);
	}

	interface BinaryProc<T> {
		void apply(T a, T b);
	}

	interface BinaryOp<T> {
		T apply(T a, T b);
	}

	// used for testing one-argument operations
	final static int NUM_RANDOM_TEST_VALUES_UNARY = 1000;
	// used for each operand of two-argument operations
	final static int NUM_RANDOM_TEST_VALUES_BINARY = 100;

	final static List<Float> testFloatList;
	final static List<Float> testFloatShortList;
	static {
		Random rand = new Random(1);

		// @formatter:off
		List<Float> specialValues =
			List.of(
				-0.0f, 0.0f,
				-1.0f, 1.0f,
				-Float.MIN_VALUE, Float.MIN_VALUE,
				-Float.MAX_VALUE, Float.MAX_VALUE,
				-Float.MIN_NORMAL - Float.MIN_VALUE, -Float.MIN_NORMAL, -Float.MIN_NORMAL + Float.MIN_VALUE,
				 Float.MIN_NORMAL - Float.MIN_VALUE,  Float.MIN_NORMAL,  Float.MIN_NORMAL + Float.MIN_VALUE,
				Float.NaN,
				Float.NEGATIVE_INFINITY, Float.POSITIVE_INFINITY);
		// @formatter:on
		Stream<Float> randStream = Stream.generate(rand::nextInt)
				.limit(NUM_RANDOM_TEST_VALUES_UNARY)
				.map(Float::intBitsToFloat);

		testFloatList = Stream.concat(specialValues.stream(), randStream)
				.collect(Collectors.toUnmodifiableList());
		testFloatShortList =
			testFloatList.subList(0, specialValues.size() + NUM_RANDOM_TEST_VALUES_BINARY);
	}

	final static List<Double> testDoubleList;
	final static List<Double> testDoubleShortList;
	static {
		Random rand = new Random(1);

		// @formatter:off
		List<Double> specialValues =
			List.of(
				-0.0, 0.0,
				-1.0, 1.0,
				-Double.MIN_VALUE, Double.MIN_VALUE,
				-Double.MAX_VALUE, Double.MAX_VALUE,
				-Double.MIN_NORMAL - Double.MIN_VALUE, -Double.MIN_NORMAL, -Double.MIN_NORMAL + Double.MIN_VALUE,
				 Double.MIN_NORMAL - Double.MIN_VALUE,  Double.MIN_NORMAL,  Double.MIN_NORMAL + Double.MIN_VALUE,
				Double.NaN,
				Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY);
		// @formatter:on

		Stream<Double> randStream = Stream.generate(rand::nextLong)
				.limit(NUM_RANDOM_TEST_VALUES_UNARY)
				.map(Double::longBitsToDouble);

		testDoubleList = Stream.concat(specialValues.stream(), randStream)
				.collect(Collectors.toUnmodifiableList());
		testDoubleShortList =
			testDoubleList.subList(0, specialValues.size() + NUM_RANDOM_TEST_VALUES_BINARY);
	}

	public void unaryDoubleOpTest(UnaryOp<Double> op, UnaryProc<BigFloat> bproc) {
		int i = 0;
		for (double fa : testDoubleList) {
			BigFloat bfa = FloatFormat.toBigFloat(fa);

			double fb = op.apply(fa);
			bproc.apply(bfa);

			assertEquals("case #" + Integer.toString(i), Double.isNaN(fb), bfa.isNaN());
			if (!Double.isNaN(fb)) {
				assertEquals("case #" + Integer.toString(i),
					FloatFormat.toBinaryString(op.apply(fa)), bfa.toBinaryString());
			}
			++i;
		}
	}

	public void binaryDoubleOpTest(BinaryOp<Double> op, BinaryProc<BigFloat> bproc) {
		int i = 0;
		for (double fa : testDoubleShortList) {
			int j = 0;
			for (double fb : testDoubleShortList) {
				BigFloat bfa = FloatFormat.toBigFloat(fa);
				BigFloat bfb = FloatFormat.toBigFloat(fb);

				double fc = op.apply(fa, fb);
				bproc.apply(bfa, bfb);

				assertEquals(String.format("case #%d,%d", i, j), Double.isNaN(fc), bfa.isNaN());
				if (!Double.isNaN(fc)) {
					assertEquals(String.format("case #%d,%d", i, j), FloatFormat.toBinaryString(fc),
						bfa.toBinaryString());
				}

				++j;
			}

			++i;
		}
	}

	public void unaryFloatOpTest(UnaryOp<Float> op, UnaryProc<BigFloat> bproc) {
		int i = 0;
		for (float fa : testFloatList) {
			BigFloat bfa = FloatFormat.toBigFloat(fa);

			float fb = op.apply(fa);
			bproc.apply(bfa);
			assertEquals("case #" + Integer.toString(i), Float.isNaN(fb), bfa.isNaN());
			if (!Float.isNaN(fb)) {
				assertEquals("case #" + Integer.toString(i), FloatFormat.toBinaryString(fb),
					bfa.toBinaryString());
			}

			++i;
		}
	}

	public void binaryFloatOpTest(BinaryOp<Float> op, BinaryProc<BigFloat> bproc) {
		int i = 0;
		for (float fa : testFloatShortList) {
			int j = 0;
			for (float fb : testFloatShortList) {
				BigFloat bfa = FloatFormat.toBigFloat(fa);
				BigFloat bfb = FloatFormat.toBigFloat(fb);

				float fc = op.apply(fa, fb);
				bproc.apply(bfa, bfb);

				assertEquals(String.format("case #%d,%d", i, j), Float.isNaN(fc), bfa.isNaN());
				if (!Float.isNaN(fc)) {
					assertEquals(String.format("case #%d,%d", i, j), FloatFormat.toBinaryString(fc),
						bfa.toBinaryString());
				}

				++j;
			}

			++i;
		}
	}

	@Test
	public void testFloatAdd() {
		binaryFloatOpTest((a, b) -> a + b, (a, b) -> a.add(b));
	}

	@Test
	public void testFloatSubstract() {
		binaryFloatOpTest((a, b) -> a - b, (a, b) -> a.sub(b));
	}

	@Test
	public void testFloatMultiply() {
		binaryFloatOpTest((a, b) -> a * b, (a, b) -> a.mul(b));
	}

	@Test
	public void testFloatDivide() {
		binaryFloatOpTest((a, b) -> a / b, (a, b) -> a.div(b));
	}

	@Test
	public void testFloatCompare() {
		int i = 0;
		for (float a : testFloatShortList) {
			int j = 0;
			BigFloat fa = FloatFormat.toBigFloat(a);
			for (float b : testFloatShortList) {
				BigFloat fb = FloatFormat.toBigFloat(b);
				assertEquals(String.format("case #%d,%d", i, j), Float.compare(a, b),
					fa.compareTo(fb));
				++j;
			}
			++i;
		}
	}

	@Test
	public void testFloatSqrt() {
		unaryFloatOpTest(a -> (float) Math.sqrt(a), a -> a.sqrt());
	}

	@Test
	public void testFloatFloor() {
		unaryFloatOpTest(a -> (float) Math.floor(a), a -> a.floor());
	}

	@Test
	public void testFloatCeil() {
		unaryFloatOpTest(a -> (float) Math.ceil(a), a -> a.ceil());
	}

	@Test
	public void testDoubleAdd() {
		binaryDoubleOpTest((a, b) -> a + b, (a, b) -> a.add(b));
	}

	@Test
	public void testDoubleSubstract() {
		binaryDoubleOpTest((a, b) -> a - b, (a, b) -> a.sub(b));
	}

	@Test
	public void testDoubleMultiply() {
		binaryDoubleOpTest((a, b) -> a * b, (a, b) -> a.mul(b));
	}

	@Test
	public void testDoubleDivide() {
		binaryDoubleOpTest((a, b) -> a / b, (a, b) -> a.div(b));
	}

	@Test
	public void testDoubleCompare() {
		int i = 0;
		for (double a : testDoubleShortList) {
			int j = 0;
			BigFloat fa = FloatFormat.toBigFloat(a);
			for (double b : testDoubleShortList) {
				BigFloat fb = FloatFormat.toBigFloat(b);
				assertEquals(String.format("case #%d,%d", i, j), Double.compare(a, b),
					fa.compareTo(fb));
				++j;
			}
			++i;
		}
	}

	@Test
	public void testDoubleSqrt() {
		unaryDoubleOpTest(a -> Math.sqrt(a), a -> a.sqrt());
	}

	@Test
	public void testDoubleFloor() {
		unaryDoubleOpTest(a -> Math.floor(a), a -> a.floor());
	}

	@Test
	public void testDoubleCeil() {
		unaryDoubleOpTest(a -> Math.ceil(a), a -> a.ceil());
	}

}
