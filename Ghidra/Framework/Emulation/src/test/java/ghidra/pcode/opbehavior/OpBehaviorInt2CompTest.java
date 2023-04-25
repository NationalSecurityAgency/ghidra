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

public class OpBehaviorInt2CompTest extends AbstractOpBehaviorTest {

	public OpBehaviorInt2CompTest() {
		super();
	}

	@Test
    public void testEvaluateBinaryLong() {

		OpBehaviorInt2Comp op = new OpBehaviorInt2Comp();

		Assert.assertEquals(0, op.evaluateUnary(4, 4, 0));
		Assert.assertEquals(1, op.evaluateUnary(4, 4, 0xffffffffL));
		Assert.assertEquals(0xffffffffL, op.evaluateUnary(4, 4, 1));
		Assert.assertEquals(0x80000001L, op.evaluateUnary(4, 4, 0x7fffffffL));
		Assert.assertEquals(0x80000000L, op.evaluateUnary(4, 4, 0x80000000L));// overflow

		Assert.assertEquals(0, op.evaluateUnary(8, 8, 0));
		Assert.assertEquals(1, op.evaluateUnary(8, 8, -1));
		Assert.assertEquals(-1, op.evaluateUnary(8, 8, 1));
		Assert.assertEquals(Long.MIN_VALUE + 1, op.evaluateUnary(8, 8, Long.MAX_VALUE));
		Assert.assertEquals(Long.MIN_VALUE, op.evaluateUnary(8, 8, Long.MIN_VALUE));// overflow
	}

	@Test
    public void testEvaluateBinaryBigInteger() {

		OpBehaviorInt2Comp op = new OpBehaviorInt2Comp();

		BigInteger negOne = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
		BigInteger minNum = new BigInteger("80000000000000000000000000000000", 16);
		BigInteger maxNum = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

		assertEquals(BigInteger.ZERO, op.evaluateUnary(8, 8, BigInteger.ZERO), 16);
		assertEquals(BigInteger.ONE, op.evaluateUnary(8, 8, negOne), 16);
		assertEquals(negOne, op.evaluateUnary(8, 8, BigInteger.ONE), 16);
		assertEquals(minNum.add(BigInteger.ONE), op.evaluateUnary(8, 8, maxNum), 16);
		assertEquals(minNum, op.evaluateUnary(8, 8, minNum), 16);// overflow

	}

}
