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

import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;

public class OpBehaviorFloatAddTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatAddTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatAdd op = new OpBehaviorFloatAdd();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		long a = ff.getEncoding(1.234);
		long b = ff.getEncoding(1.123);
		long result = op.evaluateBinary(8, 8, a, b);// 1.234 + 1.123
		Assert.assertEquals(2.357, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-1.123);
		result = op.evaluateBinary(8, 8, a, b);// -1.123 + 1.123
		Assert.assertEquals(0d, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// +INFINITY + 1.123
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY + 1.123
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY + -INFINITY
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY + +INFINITY
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		b = ff.getEncoding(1.123);
		result = op.evaluateBinary(8, 8, a, b);// NaN + 1.123
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatAdd op = new OpBehaviorFloatAdd();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigInteger a = ff.getEncoding(ff.getBigFloat(1.234d));
		BigInteger b = ff.getEncoding(ff.getBigFloat(1.123d));
		BigInteger result = op.evaluateBinary(8, 8, a, b);// 1.234 + 1.123
		Assert.assertEquals(ff.getBigFloat(2.357), ff.getHostFloat(result));

		a = ff.getEncoding(ff.getBigFloat(-1.123d));
		result = op.evaluateBinary(8, 8, a, b);// -1.123 + 1.123
		Assert.assertEquals(ff.getBigZero(false), ff.getHostFloat(result));

		a = ff.getEncoding(ff.getBigInfinity(false));
		result = op.evaluateBinary(8, 8, a, b);// +INFINITY + 1.123
		Assert.assertEquals(ff.getBigInfinity(false), ff.getHostFloat(result));

		a = ff.getBigInfinityEncoding(true);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY + 1.123
		Assert.assertEquals(ff.getBigInfinity(true), ff.getHostFloat(result));

		b = ff.getBigInfinityEncoding(true);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY + -INFINITY
		Assert.assertEquals(ff.getBigInfinity(true), ff.getHostFloat(result));

		b = ff.getEncoding(ff.getBigInfinity(false));
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY + +INFINITY
		Assert.assertEquals(ff.getBigNaN(false), ff.getHostFloat(result));

		a = ff.getBigNaNEncoding(false);
		b = ff.getEncoding(ff.getBigFloat(1.123d));
		result = op.evaluateBinary(8, 8, a, b);// NaN + 1.123
		Assert.assertEquals(ff.getBigNaN(false), ff.getHostFloat(result));
	}

}
