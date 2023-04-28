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

import generic.test.AbstractGenericTest;
import ghidra.pcode.utils.Utils;
import ghidra.util.StringUtilities;

public abstract class AbstractOpBehaviorTest extends AbstractGenericTest {

	public AbstractOpBehaviorTest() {
		super();
	}

	protected void assertEquals(BigInteger expected, BigInteger result, int byteSize) {
		// discards irrelevant bytes before comparing - ignores overflow bytes
		byte[] resultBytes = Utils.bigIntegerToBytes(result, byteSize, true);
		byte[] expectedBytes = Utils.bigIntegerToBytes(expected, byteSize, true);
		org.junit.Assert.assertEquals(toHexString(expectedBytes), toHexString(resultBytes));
	}

	protected void assertEquals(long expected, long result, int byteSize) {
		// discards irrelevant bytes before comparing - ignores overflow bytes
		byte[] resultBytes = Utils.longToBytes(result, byteSize, true);
		byte[] expectedBytes = Utils.longToBytes(expected, byteSize, true);
		org.junit.Assert.assertEquals(toHexString(expectedBytes), toHexString(resultBytes));
	}

	private String toHexString(byte[] bytes) {
		StringBuilder buf = new StringBuilder("0x");
		for (byte b : bytes) {
			String valStr = StringUtilities.pad(Integer.toHexString(b & 0xff), '0', 2);
			buf.append(valStr);
		}
		return buf.toString();
	}

	protected BigInteger getUnsignedBigInt(long val) {
		if (val > 0) {
			return BigInteger.valueOf(val);
		}
		return new BigInteger(1, Utils.longToBytes(val, 8, true));
	}

	protected BigInteger getUnsignedBigInt(long val, int size) {
		if (val > 0) {
			return BigInteger.valueOf(val);
		}
		return new BigInteger(1, Utils.longToBytes(val, size, true));
	}
}
