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
package resources;

/**
 * Enum specifying the quadrant of an overlay, either upper left, upper right, lower left, lower right.
 */
public enum QUADRANT {
	UL(0, 0), UR(1, 0), LL(0, 1), LR(1, 1);

	QUADRANT(int x, int y) {
		this.x = x;
		this.y = y;
	}

	int x, y;

	/**
	 * String to enum.
	 * 
	 * @param s string of either "UL", "UR", "LL", "LR"
	 * @param defaultValue value to return if string is invalid
	 * @return QUADRANT enum
	 */
	public static QUADRANT valueOf(String s, QUADRANT defaultValue) {
		if (s != null) {
			try {
				return QUADRANT.valueOf(s.toUpperCase());
			}
			catch (IllegalArgumentException iae) {
				// ignore
			}
		}
		return defaultValue;
	}
}
