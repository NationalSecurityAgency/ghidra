/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcode.utils;

public class AddressUtils {

	public static int unsignedCompare( long v1, long v2 ) {
		if ( v1 == v2 ) {
			return 0;
		}
		if ( v1 >= 0 && v2 >= 0 ) {
			return v1 < v2 ? -1 : 1;
		}
		if ( v1 < 0 && v2 < 0 ) {
			return v1 < v2 ? -1 : 1;
		}
		if ( v1 < 0 ) {
			return 1;
		}
		return -1;
	}
	public static long unsignedSubtract( long a, long b ) {
		return a - b;
	}

	public static long unsignedAdd( long a, long b ) {
		return a + b;
	}
}
