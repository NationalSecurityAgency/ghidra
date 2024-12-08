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

public class OpBehaviorBoolNegateTest extends AbstractOpBehaviorTest {

	public OpBehaviorBoolNegateTest() {
		super();
	}

@Test
    public void testEvaluateBinaryLong() {

		OpBehaviorBoolNegate op = new OpBehaviorBoolNegate();

		Assert.assertEquals(1, op.evaluateUnary(1, 1, 0));
		Assert.assertEquals(0, op.evaluateUnary(1, 1, 1));
	}

@Test
    public void testEvaluateBinaryBigInteger() {

		OpBehaviorBoolNegate op = new OpBehaviorBoolNegate();

		Assert.assertEquals(BigInteger.ONE, op.evaluateUnary(1, 1, BigInteger.ZERO));
		Assert.assertEquals(BigInteger.ZERO, op.evaluateUnary(1, 1, BigInteger.ONE));
	}
}
