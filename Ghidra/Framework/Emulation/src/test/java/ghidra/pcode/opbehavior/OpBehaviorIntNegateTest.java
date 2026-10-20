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

public class OpBehaviorIntNegateTest extends AbstractOpBehaviorTest {
	static final OpBehaviorIntNegate OP = OpBehavior.INT_NEGATE;

	@Test
	public void testevaluateUnaryLong() {
		Assert.assertEquals(0xffffffffL, OP.evaluateUnary(4, 4, 0));
		Assert.assertEquals(0, OP.evaluateUnary(4, 4, 0xffffffffL));
		Assert.assertEquals(0xfffffffdL, OP.evaluateUnary(4, 4, 2));
		Assert.assertEquals(2, OP.evaluateUnary(4, 4, 0xfffffffdL));
		Assert.assertEquals(0x80000000L, OP.evaluateUnary(4, 4, 0x7fffffffL));
		Assert.assertEquals(0x7fffffffL, OP.evaluateUnary(4, 4, 0x80000000L));
		Assert.assertEquals(1, OP.evaluateUnary(4, 4, 0xfffffffeL));
		Assert.assertEquals(0xfffffffeL, OP.evaluateUnary(4, 4, 1));

		Assert.assertEquals(0, OP.evaluateUnary(8, 8, -1));
		Assert.assertEquals(-1, OP.evaluateUnary(8, 8, 0));
		Assert.assertEquals(-3, OP.evaluateUnary(8, 8, 2));
		Assert.assertEquals(2, OP.evaluateUnary(8, 8, -3));
		Assert.assertEquals(Long.MIN_VALUE, OP.evaluateUnary(8, 8, Long.MAX_VALUE));
		Assert.assertEquals(Long.MAX_VALUE, OP.evaluateUnary(8, 8, Long.MIN_VALUE));
		Assert.assertEquals(1, OP.evaluateUnary(8, 8, -2));
		Assert.assertEquals(-2, OP.evaluateUnary(8, 8, 1));
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		assertEquals(NEG_ONE, OP.evaluateUnary(8, 8, BigInteger.ZERO), 16);
		assertEquals(BigInteger.ZERO, OP.evaluateUnary(8, 8, NEG_ONE), 16);
		assertEquals(getUnsignedBigInt(-3, 16), OP.evaluateUnary(8, 8, getUnsignedBigInt(2)), 16);
		assertEquals(getUnsignedBigInt(2), OP.evaluateUnary(8, 8, getUnsignedBigInt(-3, 16)), 16);
		assertEquals(MIN_NUM, OP.evaluateUnary(8, 8, MAX_NUM), 16);
		assertEquals(MAX_NUM, OP.evaluateUnary(8, 8, MIN_NUM), 16);
		assertEquals(BigInteger.ONE, OP.evaluateUnary(8, 8, getUnsignedBigInt(-2, 16)), 16);
		assertEquals(getUnsignedBigInt(-2, 16), OP.evaluateUnary(8, 8, BigInteger.ONE), 16);
	}
}
