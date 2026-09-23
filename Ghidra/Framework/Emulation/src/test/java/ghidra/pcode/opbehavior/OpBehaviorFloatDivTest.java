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

public class OpBehaviorFloatDivTest extends AbstractOpBehaviorTest {
	static final OpBehaviorFloatDiv OP = OpBehavior.FLOAT_DIV;

	@Test
	public void testEvaluateBinaryLong() {
		long a = FF8.getEncoding(3.75);
		long b = FF8.getEncoding(1.5);
		long result = FF8.opDiv(a, b);
		Assert.assertEquals(2.5, FF8.decodeHostFloat(result), 0);

		b = FF8.getEncoding(0);
		result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.POSITIVE_INFINITY, FF8.decodeHostFloat(result), 0);

		a = FF8.getEncoding(-3.75);
		result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, FF8.decodeHostFloat(result), 0);

		b = FF8.getEncoding(Double.NaN);
		result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.NaN, FF8.decodeHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		BigInteger a = FF8.getEncoding(FF8.getBigFloat(3.75d));
		BigInteger b = FF8.getEncoding(FF8.getBigFloat(1.5d));
		BigInteger result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FF8.getBigFloat(2.5d), FF8.decodeBigFloat(result));

		b = FF8.getBigZeroEncoding(false);
		result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FF8.getBigInfinity(false), FF8.decodeBigFloat(result));

		a = FF8.getEncoding(FF8.getBigFloat(-3.75d));
		result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FF8.getBigInfinity(true), FF8.decodeBigFloat(result));

		b = FF8.getBigNaNEncoding(false);
		result = OP.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FF8.getBigNaN(false), FF8.decodeBigFloat(result));
	}
}
