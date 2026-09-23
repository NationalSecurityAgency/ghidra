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

public class OpBehaviorPopcountTest extends AbstractOpBehaviorTest {
	static final OpBehaviorPopcount OP = OpBehavior.POPCOUNT;

	@Test
	public void testEvaluateUnaryLong() {
		Assert.assertEquals(0, OP.evaluateUnary(1, 1, 0L));
		Assert.assertEquals(0, OP.evaluateUnary(1, 2, 0L));
		Assert.assertEquals(0, OP.evaluateUnary(1, 4, 0L));
		Assert.assertEquals(0, OP.evaluateUnary(1, 8, 0L));

		Assert.assertEquals(8, OP.evaluateUnary(1, 1, 0xffL));
		Assert.assertEquals(16, OP.evaluateUnary(1, 2, 0xffffL));
		Assert.assertEquals(32, OP.evaluateUnary(1, 4, 0xffffffffL));
		Assert.assertEquals(64, OP.evaluateUnary(1, 8, 0xffffffffffffffffL));

		Assert.assertEquals(4, OP.evaluateUnary(1, 1, 0x96L));
		Assert.assertEquals(11, OP.evaluateUnary(1, 2, 0xdbf4L));
		Assert.assertEquals(16, OP.evaluateUnary(1, 4, 0x460f457bL));
		Assert.assertEquals(41, OP.evaluateUnary(1, 8, 0x1fae97efca7d5759L));

		Assert.assertEquals(5, OP.evaluateUnary(1, 1, 0x7aL));
		Assert.assertEquals(10, OP.evaluateUnary(1, 2, 0xfca5L));
		Assert.assertEquals(20, OP.evaluateUnary(1, 4, 0x2660dfffL));
		Assert.assertEquals(38, OP.evaluateUnary(1, 8, 0x79f635017adefe4eL));

		Assert.assertEquals(4, OP.evaluateUnary(1, 1, 0x17L));
		Assert.assertEquals(10, OP.evaluateUnary(1, 2, 0x77d1L));
		Assert.assertEquals(15, OP.evaluateUnary(1, 4, 0x5758039eL));
		Assert.assertEquals(28, OP.evaluateUnary(1, 8, 0xd46223189c178d6aL));

		Assert.assertEquals(7, OP.evaluateUnary(1, 1, 0xbfL));
		Assert.assertEquals(12, OP.evaluateUnary(1, 2, 0xe3efL));
		Assert.assertEquals(17, OP.evaluateUnary(1, 4, 0xb2d7e134L));
		Assert.assertEquals(34, OP.evaluateUnary(1, 8, 0x69f7a0fa6eeda6L));
	}

	@Test
	public void testEvaluateUnaryBigInteger() {
		assertEquals(BigInteger.ZERO, OP.evaluateUnary(1, 16, BigInteger.ZERO), 16);
		assertEquals(BigInteger.valueOf(128), OP.evaluateUnary(1, 16, NEGATIVE_ONE), 16);
		assertEquals(BigInteger.valueOf(127), OP.evaluateUnary(1, 16, BIG_POSITIVE), 16);
		assertEquals(BigInteger.ONE, OP.evaluateUnary(1, 16, BIG_NEGATIVE), 16);

		BigInteger val = BigInteger.valueOf(0x79f635017adefe4eL);
		val = val.shiftLeft(64);
		val = val.or(Utils.convertToUnsignedValue(BigInteger.valueOf(0xd46223189c178d6aL), 8));
		assertEquals(BigInteger.valueOf(66), OP.evaluateUnary(1, 16, val), 16);

		BigInteger FF = BigInteger.valueOf(0xff);
		val = BigInteger.ZERO;
		for (int i = 0; i < 20; ++i) {
			val = val.shiftLeft(16);
			val = val.add(FF);
		}
		assertEquals(BigInteger.valueOf(160), OP.evaluateUnary(1, 40, val), 40);
	}
}
