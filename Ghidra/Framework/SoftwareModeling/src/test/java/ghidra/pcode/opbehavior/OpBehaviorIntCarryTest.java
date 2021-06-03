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

public class OpBehaviorIntCarryTest extends AbstractOpBehaviorTest {

	public OpBehaviorIntCarryTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorIntCarry op = new OpBehaviorIntCarry();

		Assert.assertEquals(0, op.evaluateBinary(4, 4, 0, 0));
		Assert.assertEquals(1, op.evaluateBinary(4, 4, 1, 0xffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(4, 4, 0xffffffffL, 1));
		Assert.assertEquals(0, op.evaluateBinary(4, 4, 0x7fffffffL, 0x80000000L));
		Assert.assertEquals(1, op.evaluateBinary(4, 4, 0x7fffffffL, 0x80000001L));
		Assert.assertEquals(0, op.evaluateBinary(4, 4, 0x80000000L, 0x7fffffffL));
		Assert.assertEquals(1, op.evaluateBinary(4, 4, 0x80000001L, 0x7fffffffL));

		Assert.assertEquals(0, op.evaluateBinary(8, 8, 0, 0));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, Long.MAX_VALUE, Long.MIN_VALUE));
		Assert.assertEquals(1, op.evaluateBinary(8, 8, Long.MAX_VALUE, Long.MIN_VALUE + 1));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, Long.MIN_VALUE, Long.MAX_VALUE));
		Assert.assertEquals(1, op.evaluateBinary(8, 8, Long.MIN_VALUE + 1, Long.MAX_VALUE));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, 0x7fffffffffffffffL, 1L));
		Assert.assertEquals(0, op.evaluateBinary(8, 8, 1L, 0x7fffffffffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(8, 8, 0xffffffffffffffffL, 1L));
		Assert.assertEquals(1, op.evaluateBinary(8, 8, 1L, 0xffffffffffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(8, 8, 0xffffffffffffffffL, 0xffffffffffffffffL));
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorIntCarry op = new OpBehaviorIntCarry();

		BigInteger NEGATIVE_ONE = new BigInteger("FFFFFFFFFFFFFFFF", 16);
		BigInteger BIG_POSITIVE = new BigInteger("7FFFFFFFFFFFFFFF", 16);
		BigInteger BIG_NEGATIVE = new BigInteger("8000000000000000", 16);

		Assert.assertEquals(BigInteger.ZERO,
			op.evaluateBinary(8, 8, BigInteger.ZERO, BigInteger.ZERO));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(8, 8, BigInteger.ONE, NEGATIVE_ONE));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(8, 8, NEGATIVE_ONE, BigInteger.ONE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(8, 8, BIG_POSITIVE, BIG_NEGATIVE));
		Assert.assertEquals(BigInteger.ONE,
			op.evaluateBinary(8, 8, BIG_POSITIVE, BIG_NEGATIVE.add(BigInteger.ONE)));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(8, 8, BIG_NEGATIVE, BIG_POSITIVE));
		Assert.assertEquals(BigInteger.ONE,
			op.evaluateBinary(8, 8, BIG_NEGATIVE.add(BigInteger.ONE), BIG_POSITIVE));
	}
}
