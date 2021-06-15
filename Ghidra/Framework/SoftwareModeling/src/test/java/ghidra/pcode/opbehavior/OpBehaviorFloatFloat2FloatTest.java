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

public class OpBehaviorFloatFloat2FloatTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatFloat2FloatTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatFloat2Float op = new OpBehaviorFloatFloat2Float();

		FloatFormat ff8 = FloatFormatFactory.getFloatFormat(8);
		FloatFormat ff4 = FloatFormatFactory.getFloatFormat(4);

		long a = ff4.getEncoding(1.75);
		long result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(1.75, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(-1.75);
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(-1.75, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(Float.POSITIVE_INFINITY);
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(Float.NEGATIVE_INFINITY);
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff8.getHostFloat(result), 0);

		a = ff4.getEncoding(Float.NaN);
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(Double.NaN, ff8.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatFloat2Float op = new OpBehaviorFloatFloat2Float();

		FloatFormat ff8 = FloatFormatFactory.getFloatFormat(8);
		FloatFormat ff4 = FloatFormatFactory.getFloatFormat(4);

		BigInteger a = ff4.getEncoding(ff4.getBigFloat(1.75d));
		BigInteger result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(ff8.getBigFloat(1.75d), ff8.getHostFloat(result));

		a = ff4.getEncoding(ff4.getBigFloat(-1.75d));
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(ff8.getBigFloat(-1.75d), ff8.getHostFloat(result));

		a = ff4.getEncoding(ff4.getBigInfinity(false));
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(ff8.getBigInfinity(false), ff8.getHostFloat(result));

		a = ff4.getEncoding(ff4.getBigInfinity(true));
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(ff8.getBigInfinity(true), ff8.getHostFloat(result));

		a = ff4.getEncoding(ff4.getBigNaN(false));
		result = op.evaluateUnary(8, 4, a);
		Assert.assertEquals(ff8.getBigNaN(false), ff8.getHostFloat(result));
	}

}
