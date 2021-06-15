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

public class OpBehaviorFloatMultTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatMultTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatMult op = new OpBehaviorFloatMult();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		long a = ff.getEncoding(2.5);
		long b = ff.getEncoding(1.5);
		long result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(3.75, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NaN);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatMult op = new OpBehaviorFloatMult();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigInteger a = ff.getEncoding(ff.getBigFloat(2.5d));
		BigInteger b = ff.getEncoding(ff.getBigFloat(1.5d));
		BigInteger result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(ff.getBigFloat(3.75d), ff.getHostFloat(result));

		b = ff.getBigInfinityEncoding(false);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(ff.getBigInfinity(false), ff.getHostFloat(result));

		a = ff.getBigInfinityEncoding(true);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(ff.getBigInfinity(true), ff.getHostFloat(result));

		b = ff.getBigNaNEncoding(false);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(ff.getBigNaN(false), ff.getHostFloat(result));
	}

}
