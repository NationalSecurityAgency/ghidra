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

public class OpBehaviorFloatSubTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatSubTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatSub op = new OpBehaviorFloatSub();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		long a = ff.getEncoding(1.5);
		long b = ff.getEncoding(1.25);
		long result = op.evaluateBinary(8, 8, a, b);// 1.5 - 1.25
		Assert.assertEquals(0.25, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-1.25);
		result = op.evaluateBinary(8, 8, a, b);// -1.25 - 1.25
		Assert.assertEquals(-2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// +INFINITY - 1.25
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY - 1.25
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY - -INFINITY
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY - +INFINITY
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		b = ff.getEncoding(1.25);
		result = op.evaluateBinary(8, 8, a, b);// NaN - 1.25
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatSub op = new OpBehaviorFloatSub();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigInteger a = ff.getEncoding(ff.getBigFloat(1.5d));
		BigInteger b = ff.getEncoding(ff.getBigFloat(1.25d));
		BigInteger result = op.evaluateBinary(8, 8, a, b);// 1.5 - 1.25
		Assert.assertEquals(ff.getBigFloat(0.25d), ff.getHostFloat(result));

		a = ff.getEncoding(ff.getBigFloat(-1.25d));
		result = op.evaluateBinary(8, 8, a, b);// -1.25 - 1.25
		Assert.assertEquals(ff.getBigFloat(-2.5d), ff.getHostFloat(result));

		a = ff.getBigInfinityEncoding(false);
		result = op.evaluateBinary(8, 8, a, b);// +INFINITY - 1.25
		Assert.assertEquals(ff.getBigInfinity(false), ff.getHostFloat(result));

		a = ff.getBigInfinityEncoding(true);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY - 1.25
		Assert.assertEquals(ff.getBigInfinity(true), ff.getHostFloat(result));

		b = ff.getBigInfinityEncoding(true);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY - -INFINITY
		Assert.assertEquals(ff.getBigNaN(false), ff.getHostFloat(result));

		b = ff.getBigInfinityEncoding(false);
		result = op.evaluateBinary(8, 8, a, b);// -INFINITY - +INFINITY
		Assert.assertEquals(ff.getBigInfinity(true), ff.getHostFloat(result));

		a = ff.getBigNaNEncoding(false);
		b = ff.getEncoding(ff.getBigFloat(1.25d));
		result = op.evaluateBinary(8, 8, a, b);// NaN - 1.25
		Assert.assertEquals(ff.getBigNaN(false), ff.getHostFloat(result));

	}

}
