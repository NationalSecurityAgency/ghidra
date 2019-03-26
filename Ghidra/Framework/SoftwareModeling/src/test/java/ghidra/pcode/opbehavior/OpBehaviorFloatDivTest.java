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

import java.math.BigDecimal;
import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;

public class OpBehaviorFloatDivTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatDivTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatDiv op = new OpBehaviorFloatDiv();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		long a = ff.getEncoding(3.75);
		long b = ff.getEncoding(1.5);
		long result = ff.opDiv(a, b);
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		b = ff.getEncoding(0);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-3.75);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.NEGATIVE_INFINITY, ff.getHostFloat(result), 0);

		b = ff.getEncoding(Double.NaN);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatDiv op = new OpBehaviorFloatDiv();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(3.75d));
		BigInteger b = ff.getEncoding(BigDecimal.valueOf(1.5d));
		BigInteger result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		b = ff.getEncoding(BigDecimal.ZERO);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-3.75d));
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, ff.getHostFloat(result));

		b = ff.getEncoding(FloatFormat.BIG_NaN);
		result = op.evaluateBinary(8, 8, a, b);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

}
