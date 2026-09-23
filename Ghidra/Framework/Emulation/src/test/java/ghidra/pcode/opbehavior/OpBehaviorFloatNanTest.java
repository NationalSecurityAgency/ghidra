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

public class OpBehaviorFloatNanTest extends AbstractOpBehaviorTest {
	static final OpBehaviorFloatNan OP = OpBehavior.FLOAT_NAN;

	@Test
	public void testEvaluateBinaryLong() {
		Assert.assertEquals(1, OP.evaluateUnary(1, 8, FF8.getEncoding(Double.NaN)));
		Assert.assertEquals(0, OP.evaluateUnary(1, 8, FF8.getEncoding(0)));
		Assert.assertEquals(0, OP.evaluateUnary(1, 8, FF8.getEncoding(1.234)));
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		Assert.assertEquals(BigInteger.ONE, OP.evaluateUnary(1, 8, FF8.getBigNaNEncoding(false)));
		Assert.assertEquals(BigInteger.ZERO, OP.evaluateUnary(1, 8, FF8.getBigZeroEncoding(false)));
		Assert.assertEquals(BigInteger.ZERO,
			OP.evaluateUnary(1, 8, FF8.getEncoding(FF8.getBigFloat(1.234d))));
	}
}
