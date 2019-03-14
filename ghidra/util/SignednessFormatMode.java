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

/**
 * Defines how the sign of integer-type numbers is to be interpreted for rendering.
 */
public enum SignednessFormatMode {
	/**
	 * Values to be rendered in binary, octal, or hexadecimal bases are rendered
	 * as unsigned; numbers rendered in decimal are rendered as signed.
	 *
	 */
	DEFAULT,
	/** All values are rendered in their <i>unsigned</i> form  */
	UNSIGNED,
	/** All values are rendered in their <i>signed</i> form */
	SIGNED;

	public static SignednessFormatMode parse(int value) {
		for (SignednessFormatMode mode : SignednessFormatMode.values()) {
			if (mode.ordinal() == value) {
				return mode;
			}
		}
		throw new IllegalArgumentException();
	}
}
