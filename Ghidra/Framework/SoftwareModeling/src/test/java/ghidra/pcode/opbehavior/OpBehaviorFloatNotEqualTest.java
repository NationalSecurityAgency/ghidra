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
package ghidra.pcode.opbehavior;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;

public class OpBehaviorFloatNotEqualTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatNotEqualTest() {
		super();
	}

@Test
    public void testEvaluateBinaryLong() {

		OpBehaviorFloatNotEqual op = new OpBehaviorFloatNotEqual();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		Assert.assertEquals(0, op.evaluateBinary(1, 8, ff.getEncoding(1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, ff.getEncoding(-1.234), ff.getEncoding(-1.234)));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, ff.getEncoding(-1.234), ff.getEncoding(1.234)));
		Assert.assertEquals(
			0,
			op.evaluateBinary(1, 8, ff.getEncoding(Double.POSITIVE_INFINITY),
				ff.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(
			1,
			op.evaluateBinary(1, 8, ff.getEncoding(Double.POSITIVE_INFINITY),
				ff.getEncoding(Double.NEGATIVE_INFINITY)));
		Assert.assertEquals(
			0,
			op.evaluateBinary(1, 8, ff.getEncoding(Double.NEGATIVE_INFINITY),
				ff.getEncoding(Double.NEGATIVE_INFINITY)));
		Assert.assertEquals(
			1,
			op.evaluateBinary(1, 8, ff.getEncoding(Double.POSITIVE_INFINITY),
				ff.getEncoding(Double.NaN)));

	}

@Test
    public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatNotEqual op = new OpBehaviorFloatNotEqual();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigDecimal a = BigDecimal.valueOf(1.234d);
		BigDecimal b = BigDecimal.valueOf(-1.234d);
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 8, ff.getEncoding(a), ff.getEncoding(a)));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 8, ff.getEncoding(b), ff.getEncoding(b)));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 8, ff.getEncoding(b), ff.getEncoding(a)));
		Assert.assertEquals(
			BigInteger.ZERO,
			op.evaluateBinary(1, 8, ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY)));
		Assert.assertEquals(
			BigInteger.ONE,
			op.evaluateBinary(1, 8, ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));
		Assert.assertEquals(
			BigInteger.ZERO,
			op.evaluateBinary(1, 8, ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY)));
		Assert.assertEquals(
			BigInteger.ONE,
			op.evaluateBinary(1, 8, ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY),
				ff.getEncoding(FloatFormat.BIG_NaN)));

	}

}
