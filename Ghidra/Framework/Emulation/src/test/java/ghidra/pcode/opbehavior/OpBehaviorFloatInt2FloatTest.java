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

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.pcode.utils.Utils;

public class OpBehaviorFloatInt2FloatTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatInt2FloatTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatInt2Float op = new OpBehaviorFloatInt2Float();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(4);

		long result = op.evaluateUnary(4, 4, 2);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(2.0d, ff.getHostFloat(result), 0);

		result = op.evaluateUnary(4, 4, -2);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(-2.0d, ff.getHostFloat(result), 0);

		result = op.evaluateUnary(4, 4, 0);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(0d, ff.getHostFloat(result), 0);

		result = op.evaluateUnary(4, 4, 0x0ffffffffL);
		Assert.assertEquals(0, result & 0xffffffff00000000L);// verify that only 4-bytes are used
		Assert.assertEquals(-1.0d, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatInt2Float op = new OpBehaviorFloatInt2Float();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(4);

		BigInteger limit = BigInteger.ONE.shiftLeft(32);

		BigInteger result = op.evaluateUnary(4, 4, BigInteger.valueOf(2));
		assertTrue(result.compareTo(limit) < 0);// verify that only 4-bytes are used
		Assert.assertEquals(ff.getBigFloat(2.0d), ff.getHostFloat(result));

		result = op.evaluateUnary(4, 4, BigInteger.valueOf(-2));
		assertTrue(result.compareTo(limit) < 0);// verify that only 4-bytes are used
		Assert.assertEquals(ff.getBigFloat(-2.0d), ff.getHostFloat(result));

		result = op.evaluateUnary(4, 4, BigInteger.ZERO);
		assertTrue(result.compareTo(limit) < 0);// verify that only 4-bytes are used
		Assert.assertEquals(ff.getBigZero(false), ff.getHostFloat(result));

		BigInteger NEG_ONE = Utils.bytesToBigInteger(
			new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff }, 4, false, false);
		result = op.evaluateUnary(4, 4, NEG_ONE);
		Assert.assertEquals(ff.getBigFloat(-1.0d), ff.getHostFloat(result));

	}

}
