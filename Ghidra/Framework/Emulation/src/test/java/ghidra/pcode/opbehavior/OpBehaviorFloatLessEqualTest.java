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

import ghidra.pcode.floatformat.BigFloat;

public class OpBehaviorFloatLessEqualTest extends AbstractOpBehaviorTest {
	static final OpBehaviorFloatLessEqual OP = OpBehavior.FLOAT_LESSEQUAL;

	@Test
	public void testEvaluateBinaryLong() {
		Assert.assertEquals(1,
			OP.evaluateBinary(8, 8, FF8.getEncoding(1.234), FF8.getEncoding(1.234)));
		Assert.assertEquals(1,
			OP.evaluateBinary(8, 8, FF8.getEncoding(-1.234), FF8.getEncoding(-1.234)));

		Assert.assertEquals(0,
			OP.evaluateBinary(8, 8, FF8.getEncoding(1.234), FF8.getEncoding(-1.234)));
		Assert.assertEquals(0,
			OP.evaluateBinary(8, 8, FF8.getEncoding(0), FF8.getEncoding(-1.234)));

		Assert.assertEquals(1, OP.evaluateBinary(8, 8, FF8.getEncoding(0), FF8.getEncoding(1.234)));
		Assert.assertEquals(1,
			OP.evaluateBinary(8, 8, FF8.getEncoding(-1.234), FF8.getEncoding(1.234)));

		Assert.assertEquals(0, OP.evaluateBinary(8, 8, FF8.getEncoding(Double.POSITIVE_INFINITY),
			FF8.getEncoding(1.234)));
		Assert.assertEquals(1, OP.evaluateBinary(8, 8, FF8.getEncoding(Double.NEGATIVE_INFINITY),
			FF8.getEncoding(1.234)));
		Assert.assertEquals(1, OP.evaluateBinary(8, 8, FF8.getEncoding(1.234),
			FF8.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(0, OP.evaluateBinary(8, 8, FF8.getEncoding(1.234),
			FF8.getEncoding(Double.NEGATIVE_INFINITY)));

		Assert.assertEquals(1, OP.evaluateBinary(8, 8, FF8.getEncoding(Double.POSITIVE_INFINITY),
			FF8.getEncoding(Double.POSITIVE_INFINITY)));
		Assert.assertEquals(1, OP.evaluateBinary(8, 8, FF8.getEncoding(Double.NEGATIVE_INFINITY),
			FF8.getEncoding(Double.POSITIVE_INFINITY)));
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		BigFloat a = FF8.getBigFloat(1.234d);
		BigFloat b = FF8.getBigFloat(-1.234d);

		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getEncoding(a), FF8.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getEncoding(b), FF8.getEncoding(b)));

		Assert.assertEquals(BigInteger.ZERO,
			OP.evaluateBinary(8, 8, FF8.getEncoding(a), FF8.getEncoding(b)));
		Assert.assertEquals(BigInteger.ZERO,
			OP.evaluateBinary(8, 8, FF8.getBigZeroEncoding(false), FF8.getEncoding(b)));

		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getBigZeroEncoding(false), FF8.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getEncoding(b), FF8.getEncoding(a)));

		Assert.assertEquals(BigInteger.ZERO,
			OP.evaluateBinary(8, 8, FF8.getBigInfinityEncoding(false), FF8.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getBigInfinityEncoding(true), FF8.getEncoding(a)));
		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getEncoding(a), FF8.getBigInfinityEncoding(false)));
		Assert.assertEquals(BigInteger.ZERO,
			OP.evaluateBinary(8, 8, FF8.getEncoding(a), FF8.getBigInfinityEncoding(true)));

		Assert.assertEquals(BigInteger.ONE, OP.evaluateBinary(8, 8,
			FF8.getBigInfinityEncoding(false), FF8.getBigInfinityEncoding(false)));
		Assert.assertEquals(BigInteger.ONE,
			OP.evaluateBinary(8, 8, FF8.getBigInfinityEncoding(true),
				FF8.getBigInfinityEncoding(false)));
	}
}
