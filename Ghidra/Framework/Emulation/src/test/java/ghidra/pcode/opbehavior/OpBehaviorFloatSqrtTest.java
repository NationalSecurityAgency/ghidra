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

import ghidra.pcode.floatformat.*;

public class OpBehaviorFloatSqrtTest extends AbstractOpBehaviorTest {
	static final OpBehaviorFloatSqrt OP = OpBehavior.FLOAT_SQRT;

	@Test
	public void testEvaluateBinaryLong() {
		long longbits = FF8.getEncoding(2.0);
		longbits = OP.evaluateUnary(8, 8, longbits);
		double d = FF8.decodeHostFloat(longbits);
		Assert.assertEquals("1.414213562373095", Double.toString(d).substring(0, 17));
	}

	@Test
	public void testEvaluateBinaryBigInteger() {
		BigFloat big = FF8.getBigFloat(2.0);
		BigInteger encoding = FF8.getEncoding(big);
		encoding = OP.evaluateUnary(8, 8, encoding);
		BigFloat result = FF8.decodeBigFloat(encoding);
		Assert.assertEquals("1.414213562373095", FF8.round(result).toString());
	}
}
