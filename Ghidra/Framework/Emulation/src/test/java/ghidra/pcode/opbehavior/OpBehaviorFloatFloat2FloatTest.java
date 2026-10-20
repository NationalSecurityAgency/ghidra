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

public class OpBehaviorFloatFloat2FloatTest extends AbstractOpBehaviorTest {
	static final OpBehaviorFloatFloat2Float OP = OpBehavior.FLOAT_FLOAT2FLOAT;

	@Test
	public void testEvaluateBinaryLong() {
		long a = FF4.getEncoding(1.75);
		long result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(1.75, FF8.decodeHostFloat(result), 0);

		a = FF4.getEncoding(-1.75);
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(-1.75, FF8.decodeHostFloat(result), 0);

		a = FF4.getEncoding(Float.POSITIVE_INFINITY);
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, FF8.decodeHostFloat(result), 0);

		a = FF4.getEncoding(Float.NEGATIVE_INFINITY);
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, FF8.decodeHostFloat(result), 0);

		a = FF4.getEncoding(Float.NaN);
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(Double.NaN, FF8.decodeHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		BigInteger a = FF4.getEncoding(FF4.getBigFloat(1.75d));
		BigInteger result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(FF8.getBigFloat(1.75d), FF8.decodeBigFloat(result));

		a = FF4.getEncoding(FF4.getBigFloat(-1.75d));
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(FF8.getBigFloat(-1.75d), FF8.decodeBigFloat(result));

		a = FF4.getEncoding(FF4.getBigInfinity(false));
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(FF8.getBigInfinity(false), FF8.decodeBigFloat(result));

		a = FF4.getEncoding(FF4.getBigInfinity(true));
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(FF8.getBigInfinity(true), FF8.decodeBigFloat(result));

		a = FF4.getEncoding(FF4.getBigNaN(false));
		result = OP.evaluateUnary(8, 4, a);
		Assert.assertEquals(FF8.getBigNaN(false), FF8.decodeBigFloat(result));
	}
}
