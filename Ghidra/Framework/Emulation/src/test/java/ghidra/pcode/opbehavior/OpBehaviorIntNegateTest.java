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

	public OpBehaviorIntNegateTest() {
		super();
	}

	@Test
    public void testevaluateUnaryLong() {

		OpBehaviorIntNegate op = new OpBehaviorIntNegate();

		Assert.assertEquals(0xffffffffL, op.evaluateUnary(4, 4, 0));
		Assert.assertEquals(0, op.evaluateUnary(4, 4, 0xffffffffL));
		Assert.assertEquals(0xfffffffdL, op.evaluateUnary(4, 4, 2));
		Assert.assertEquals(2, op.evaluateUnary(4, 4, 0xfffffffdL));
		Assert.assertEquals(0x80000000L, op.evaluateUnary(4, 4, 0x7fffffffL));
		Assert.assertEquals(0x7fffffffL, op.evaluateUnary(4, 4, 0x80000000L));
		Assert.assertEquals(1, op.evaluateUnary(4, 4, 0xfffffffeL));
		Assert.assertEquals(0xfffffffeL, op.evaluateUnary(4, 4, 1));

		Assert.assertEquals(0, op.evaluateUnary(8, 8, -1));
		Assert.assertEquals(-1, op.evaluateUnary(8, 8, 0));
		Assert.assertEquals(-3, op.evaluateUnary(8, 8, 2));
		Assert.assertEquals(2, op.evaluateUnary(8, 8, -3));
		Assert.assertEquals(Long.MIN_VALUE, op.evaluateUnary(8, 8, Long.MAX_VALUE));
		Assert.assertEquals(Long.MAX_VALUE, op.evaluateUnary(8, 8, Long.MIN_VALUE));
		Assert.assertEquals(1, op.evaluateUnary(8, 8, -2));
		Assert.assertEquals(-2, op.evaluateUnary(8, 8, 1));

	}

	@Test
    public void testEvaluateBinaryBigInteger() {

		OpBehaviorIntNegate op = new OpBehaviorIntNegate();

		BigInteger negOne = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
		BigInteger minNum = new BigInteger("80000000000000000000000000000000", 16);
		BigInteger maxNum = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

		assertEquals(negOne, op.evaluateUnary(8, 8, BigInteger.ZERO), 16);
		assertEquals(BigInteger.ZERO, op.evaluateUnary(8, 8, negOne), 16);
		assertEquals(getUnsignedBigInt(-3, 16), op.evaluateUnary(8, 8, getUnsignedBigInt(2)), 16);
		assertEquals(getUnsignedBigInt(2), op.evaluateUnary(8, 8, getUnsignedBigInt(-3, 16)), 16);
		assertEquals(minNum, op.evaluateUnary(8, 8, maxNum), 16);
		assertEquals(maxNum, op.evaluateUnary(8, 8, minNum), 16);
		assertEquals(BigInteger.ONE, op.evaluateUnary(8, 8, getUnsignedBigInt(-2, 16)), 16);
		assertEquals(getUnsignedBigInt(-2, 16), op.evaluateUnary(8, 8, BigInteger.ONE), 16);
	}
}
