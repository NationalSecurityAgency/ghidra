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

import ghidra.pcode.utils.Utils;

public class OpBehaviorIntSLessEqualTest extends AbstractOpBehaviorTest {

	public OpBehaviorIntSLessEqualTest() {
		super();
	}

@Test
    public void testEvaluateBinaryLong() {

		OpBehaviorIntSless op = new OpBehaviorIntSless();

		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0, 0));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 1, 0));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0, 1));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0xffffffffL, 0));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0, 0xffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0xffffffffL, 1));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 1, 0xffffffffL));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0xffffffffL, 0xffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0x80000000L, 0));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0, 0x80000000L));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0x80000000L, 1));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 1, 0x80000000L));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0x80000000L, 0x7fffffffL));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0x7fffffffL, 0x80000000L));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0x80000000L, 0x80000000L));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0x7fffffffL, 0x7fffffffL));
		Assert.assertEquals(0, op.evaluateBinary(1, 4, 0xffffffffL, 0x80000000L));
		Assert.assertEquals(1, op.evaluateBinary(1, 4, 0x80000000L, 0xffffffffL));

		Assert.assertEquals(0, op.evaluateBinary(1, 8, 0, 0));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 1, 0));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, 0, 1));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, 0xffffffffffffffffL, 0));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 0, 0xffffffffffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, 0xffffffffffffffffL, 1));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 1, 0xffffffffffffffffL));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 0xffffffffffffffffL, 0xffffffffffffffffL));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, Long.MIN_VALUE, 0));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 0, Long.MIN_VALUE));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, Long.MIN_VALUE, 1));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 1, Long.MIN_VALUE));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, Long.MIN_VALUE, Long.MAX_VALUE));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, Long.MAX_VALUE, Long.MIN_VALUE));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, Long.MIN_VALUE, Long.MIN_VALUE));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, Long.MAX_VALUE, Long.MAX_VALUE));
		Assert.assertEquals(0, op.evaluateBinary(1, 8, 0xffffffffffffffffL, 0x8000000000000000L));
		Assert.assertEquals(1, op.evaluateBinary(1, 8, 0x8000000000000000L, 0xffffffffffffffffL));

	}

@Test
    public void testEvaluateBinaryBigInteger() {

		OpBehaviorIntSless op = new OpBehaviorIntSless();

		BigInteger NEGATIVE_ONE = Utils.convertToUnsignedValue(BigInteger.valueOf(-1), 16);
		BigInteger BIG_POSITIVE = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
		BigInteger BIG_NEGATIVE =
			Utils.convertToUnsignedValue(new BigInteger("80000000000000000000000000000000", 16), 16);

		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BigInteger.ZERO, BigInteger.ZERO));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BigInteger.ONE, BigInteger.ZERO));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 16, BigInteger.ZERO, BigInteger.ONE));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 16, NEGATIVE_ONE, BigInteger.ZERO));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BigInteger.ZERO, NEGATIVE_ONE));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 16, NEGATIVE_ONE, BigInteger.ONE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BigInteger.ONE, NEGATIVE_ONE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, NEGATIVE_ONE, NEGATIVE_ONE));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 16, BIG_NEGATIVE, BigInteger.ZERO));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BigInteger.ZERO, BIG_NEGATIVE));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 16, BIG_NEGATIVE, BigInteger.ONE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BigInteger.ONE, BIG_NEGATIVE));
		Assert.assertEquals(BigInteger.ONE, op.evaluateBinary(1, 16, BIG_NEGATIVE, BIG_POSITIVE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BIG_POSITIVE, BIG_NEGATIVE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BIG_NEGATIVE, BIG_NEGATIVE));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateBinary(1, 16, BIG_POSITIVE, BIG_POSITIVE));

	}
}
