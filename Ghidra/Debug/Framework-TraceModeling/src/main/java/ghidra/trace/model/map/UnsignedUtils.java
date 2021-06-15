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
package ghidra.trace.model.map;

import com.google.common.primitives.UnsignedLong;

public enum UnsignedUtils {
	;
	/**
	 * Equivalent to {@link UnsignedLong#doubleValue()}, but without the overhead of instantiating
	 * one.
	 * 
	 * @param val the long to treat as unsigned and convert
	 * @return the double
	 */
	public static double unsignedLongToDouble(long val) {
		double dVal = val & 0x7FFF_FFFF_FFFF_FFFFL;
		if (val < 0) {
			dVal += 0x1.0p63;
		}
		return dVal;
	}
}
