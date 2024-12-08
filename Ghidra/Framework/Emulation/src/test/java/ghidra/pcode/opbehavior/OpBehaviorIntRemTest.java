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

import ghidra.pcode.error.LowlevelError;

public class OpBehaviorIntRemTest extends AbstractOpBehaviorTest {

	public OpBehaviorIntRemTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {
		OpBehaviorIntRem op = new OpBehaviorIntRem();
		Assert.assertEquals(0L, op.evaluateBinary(4, 4, 16, 2));
		Assert.assertEquals(1L, op.evaluateBinary(4, 4, 17, 2));
		Assert.assertEquals(1L, op.evaluateBinary(8, 8, 0xffffffffffffffffL, 2L));
	}

	@Test(expected = LowlevelError.class)
	public void testDivideByZeroLong() {
		OpBehaviorIntRem op = new OpBehaviorIntRem();
		op.evaluateBinary(4, 4, 1, 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		OpBehaviorIntRem op = new OpBehaviorIntRem();
		Assert.assertEquals(BigInteger.TWO,
			op.evaluateBinary(16, 16, new BigInteger("fffffffffffffffffffffffffffffff2", 16),
				BigInteger.TWO.add(BigInteger.TWO)));

	}

	@Test(expected = LowlevelError.class)
	public void testDivideByZeroBigInteger() {
		OpBehaviorIntRem op = new OpBehaviorIntRem();
		op.evaluateBinary(16, 16, BigInteger.ONE, BigInteger.ZERO);
	}

}
