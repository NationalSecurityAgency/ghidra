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

public class OpBehaviorLzcountTest extends AbstractOpBehaviorTest {
	@Test
	public void testEvaluateUnaryLong() {

		OpBehaviorLzcount op = new OpBehaviorLzcount();

		Assert.assertEquals(8, op.evaluateUnary(1, 1, 0L));
		Assert.assertEquals(16, op.evaluateUnary(1, 2, 0L));
		Assert.assertEquals(32, op.evaluateUnary(1, 4, 0L));
		Assert.assertEquals(64, op.evaluateUnary(1, 8, 0L));

		Assert.assertEquals(0, op.evaluateUnary(1, 1, 0xffL));
		Assert.assertEquals(0, op.evaluateUnary(1, 2, 0xffffL));
		Assert.assertEquals(0, op.evaluateUnary(1, 4, 0xffffffffL));
		Assert.assertEquals(0, op.evaluateUnary(1, 8, 0xffffffffffffffffL));

		Assert.assertEquals(0, op.evaluateUnary(1, 1, 0x96L));
		Assert.assertEquals(0, op.evaluateUnary(1, 2, 0xdbf4L));
		Assert.assertEquals(1, op.evaluateUnary(1, 4, 0x460f457bL));
		Assert.assertEquals(3, op.evaluateUnary(1, 8, 0x1fae97efca7d5759L));

		Assert.assertEquals(4, op.evaluateUnary(1, 1, 0xaL));
		Assert.assertEquals(6, op.evaluateUnary(1, 2, 0x2a5L));
		Assert.assertEquals(9, op.evaluateUnary(1, 4, 0x60dfffL));
		Assert.assertEquals(13, op.evaluateUnary(1, 8, 0x635017adefe4eL));

		Assert.assertEquals(3, op.evaluateUnary(1, 1, 0x17L));
		Assert.assertEquals(8, op.evaluateUnary(1, 2, 0xd1L));
		Assert.assertEquals(22, op.evaluateUnary(1, 4, 0x39eL));
		Assert.assertEquals(27, op.evaluateUnary(1, 8, 0x189c178d6aL));

		Assert.assertEquals(4, op.evaluateUnary(1, 1, 0xfL));
		Assert.assertEquals(4, op.evaluateUnary(1, 2, 0xff0L));
		Assert.assertEquals(0, op.evaluateUnary(1, 4, 0xffff0000L));
		Assert.assertEquals(24, op.evaluateUnary(1, 8, 0xff00ff00ffL));

	}

	@Test
	public void testEvaluateUnaryBigInteger() {
		OpBehaviorLzcount op = new OpBehaviorLzcount();

		BigInteger NEGATIVE_ONE = Utils.convertToUnsignedValue(BigInteger.valueOf(-1), 16);
		BigInteger BIG_POSITIVE = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
		BigInteger BIG_NEGATIVE = Utils
				.convertToUnsignedValue(new BigInteger("80000000000000000000000000000000", 16), 16);

		assertEquals(BigInteger.valueOf(128), op.evaluateUnary(1, 16, BigInteger.ZERO), 16);
		assertEquals(BigInteger.ZERO, op.evaluateUnary(1, 16, NEGATIVE_ONE), 16);
		assertEquals(BigInteger.ONE, op.evaluateUnary(1, 16, BIG_POSITIVE), 16);
		assertEquals(BigInteger.ZERO, op.evaluateUnary(1, 16, BIG_NEGATIVE), 16);

		BigInteger val = BigInteger.valueOf(0x35017adefe4eL);
		val = val.shiftLeft(64);
		val = val.or(Utils.convertToUnsignedValue(BigInteger.valueOf(0xd46223189c178d6aL), 8));
		assertEquals(BigInteger.valueOf(18), op.evaluateUnary(1, 16, val), 16);

		BigInteger FF = BigInteger.valueOf(0xff);
		val = BigInteger.ZERO;
		for (int i = 0; i < 20; ++i) {
			val = val.shiftLeft(16);
			val = val.add(FF);
		}
		assertEquals(BigInteger.valueOf(8), op.evaluateUnary(1, 40, val), 40);
	}

}
