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

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

public class OpBehaviorFloatTruncTest extends AbstractOpBehaviorTest {
	static final OpBehaviorFloatTrunc OP = OpBehavior.FLOAT_TRUNC;

	@Test
	public void testEvaluateBinaryLong() {
		long a = FF8.getEncoding(2.5);
		long result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(2, result);

		a = FF8.getEncoding(-2.5);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(-2, result);

		a = FF8.getEncoding(Double.POSITIVE_INFINITY);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(Long.MAX_VALUE, result);

		a = FF8.getEncoding(Double.NEGATIVE_INFINITY);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(Long.MIN_VALUE, result);

		// TODO: What should the correct result be?
		a = FF8.getEncoding(Double.NaN);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(0, result);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		BigInteger a = FF8.getEncoding(FF8.getBigFloat(2.5d));
		BigInteger result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigInteger.valueOf(2), result);

		a = FF8.getEncoding(FF8.getBigFloat(-2.5d));
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigInteger.valueOf(-2), result);

		a = FF8.getBigInfinityEncoding(false);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigInteger.valueOf(Long.MAX_VALUE), result);

		a = FF8.getBigInfinityEncoding(true);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigInteger.valueOf(Long.MIN_VALUE), result);

		// TODO: What should the correct result be?
		a = FF8.getBigNaNEncoding(false);
		result = OP.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigInteger.ZERO, result);
	}
}
