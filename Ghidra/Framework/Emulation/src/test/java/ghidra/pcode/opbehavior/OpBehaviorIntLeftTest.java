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

public class OpBehaviorIntLeftTest extends AbstractOpBehaviorTest {

	public OpBehaviorIntLeftTest() {
		super();
	}

	@Test
    public void testEvaluateBinaryLong() {

		OpBehaviorIntLeft op = new OpBehaviorIntLeft();

		Assert.assertEquals(0, op.evaluateBinary(4, 4, 0, 8));
		Assert.assertEquals(0, op.evaluateBinary(4, 4, 0, -1));
		Assert.assertEquals(0x100, op.evaluateBinary(4, 4, 1, 8));
		Assert.assertEquals(0x80000000L, op.evaluateBinary(4, 4, 1, 31));
		Assert.assertEquals(0, op.evaluateBinary(4, 4, 1, 32));
		Assert.assertEquals(0, op.evaluateBinary(4, 4, 1, 33));

		Assert.assertEquals(0, op.evaluateBinary(8, 8, 0, 8));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, 0, -1));
		Assert.assertEquals(0x100L, op.evaluateBinary(8, 8, 1, 8));
		Assert.assertEquals(Long.MIN_VALUE, op.evaluateBinary(8, 8, 1, 63));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, 1, 64));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, 1, 65));

	}

	@Test
    public void testEvaluateBinaryBigInteger() {

		OpBehaviorIntLeft op = new OpBehaviorIntLeft();

		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(4, 4, BigInteger.ZERO, getUnsignedBigInt(8)), 4);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(4, 4, BigInteger.ZERO, getUnsignedBigInt(-1)), 4);
		assertEquals(getUnsignedBigInt(0x100L),
			op.evaluateBinary(4, 4, BigInteger.ONE, getUnsignedBigInt(8)), 4);
		assertEquals(getUnsignedBigInt(0x80000000L),
			op.evaluateBinary(4, 4, BigInteger.ONE, getUnsignedBigInt(31)), 4);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(4, 4, BigInteger.ONE, getUnsignedBigInt(32)), 4);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(4, 4, BigInteger.ONE, getUnsignedBigInt(33)), 4);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(4, 4, getUnsignedBigInt(0x80000000L), BigInteger.ONE), 4);

		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(8, 8, BigInteger.ZERO, getUnsignedBigInt(8)), 8);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(8, 8, BigInteger.ZERO, getUnsignedBigInt(-1)), 8);
		assertEquals(getUnsignedBigInt(0x100L),
			op.evaluateBinary(8, 8, BigInteger.ONE, getUnsignedBigInt(8)), 8);
		assertEquals(getUnsignedBigInt(Long.MIN_VALUE),
			op.evaluateBinary(8, 8, BigInteger.ONE, getUnsignedBigInt(63)), 8);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(8, 8, BigInteger.ONE, getUnsignedBigInt(64)), 8);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(8, 8, BigInteger.ONE, getUnsignedBigInt(65)), 8);
		assertEquals(BigInteger.ZERO,
			op.evaluateBinary(8, 8, getUnsignedBigInt(Long.MIN_VALUE), BigInteger.ONE), 4);
	}

}
