/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.dbg.util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @deprecated Will be removed in 11.3. Portions may be refactored into trace object database.
 */
@Deprecated(forRemoval = true, since = "11.2")
public enum ConversionUtils {
	;
	/**
	 * Converts a given big integer into a 2's-complement big-endian byte array
	 * 
	 * If the value requires fewer than {@code length} bytes, the more-significant bytes of the
	 * result are filled according to the sign of the value. If the value requires more than
	 * {@code length} bytes, the more-significant bytes of the value are truncated.
	 * 
	 * @param length the number of bytes in the output byte array
	 * @param value the input value to convert
	 * @return the resulting byte array
	 */
	public static byte[] bigIntegerToBytes(int length, BigInteger value) {
		byte[] bytes = value.toByteArray();
		if (length == bytes.length) {
			return bytes;
		}
		byte[] result = new byte[length];
		if (value.signum() < 0) {
			Arrays.fill(result, (byte) -1);
		}
		if (length < bytes.length) {
			System.arraycopy(bytes, bytes.length - length, result, 0, length);
		}
		else {
			System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
		}
		return result;
	}
}
