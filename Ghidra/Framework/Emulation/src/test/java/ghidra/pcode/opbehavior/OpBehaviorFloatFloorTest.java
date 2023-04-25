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

public class OpBehaviorFloatFloorTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatFloorTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatFloor op = new OpBehaviorFloatFloor();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.0);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(-2.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(-3.0, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatFloor op = new OpBehaviorFloatFloor();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigInteger a = ff.getEncoding(ff.getBigFloat(2.5d));
		BigInteger result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(ff.getBigFloat(2.0d), ff.getHostFloat(result));

		a = ff.getEncoding(ff.getBigFloat(-2.0d));
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(ff.getBigFloat(-2.0d), ff.getHostFloat(result));

		a = ff.getEncoding(ff.getBigFloat(-2.5d));
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(ff.getBigFloat(-3.0d), ff.getHostFloat(result));

		a = ff.getBigInfinityEncoding(false);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(ff.getBigInfinity(false), ff.getHostFloat(result));

		a = ff.getBigInfinityEncoding(true);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(ff.getBigInfinity(true), ff.getHostFloat(result));

		a = ff.getBigNaNEncoding(false);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(ff.getBigNaN(false), ff.getHostFloat(result));
	}

}
