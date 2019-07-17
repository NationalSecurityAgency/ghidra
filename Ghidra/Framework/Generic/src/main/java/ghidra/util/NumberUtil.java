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
package ghidra.util;

public class NumberUtil {

	public static final int UNSIGNED_BYTE_MASK = 0xff;
	public static final int UNSIGNED_SHORT_MASK = 0xffff;
	public static final long UNSIGNED_INT_MASK = 0xffffffffL;

	//public static final long UNSIGNED_LONG_MASK = 0xffffffffffffffffL;

	/**
	 * Get the unsigned value of a number.
	 * @param value the value stored in a signed number
	 * @return the unsigned value of the number
	 */
	public static Number getUnsignedValue(Number value) {
		if (value instanceof Byte) {
			return value.byteValue() & UNSIGNED_BYTE_MASK;
		}
		else if (value instanceof Short) {
			return value.shortValue() & UNSIGNED_SHORT_MASK;
		}
		else if (value instanceof Integer) {
			return value.intValue() & UNSIGNED_INT_MASK;
		}
		else if (value instanceof Long) {
			// TODO: Is this valid?
			if (value.longValue() < 0) {
				return value.longValue() & 0xffffffffffffffffL;
			}
			return value;
		}
		throw new UnsupportedOperationException("Number instance not handled!");
	}

	/**
	 * Compare to the maximum unsigned value that the current number is holding.
	 * @param value the value stored in a signed number
	 * @return true if equal to the maximum and false otherwise
	 */
	public static boolean equalsMaxUnsignedValue(Number value) {
		// All number types should be the max when equal to signed value -1 in two's complement
		if (value.longValue() == -1) {
			return true;
		}
		return false;
	}
}
