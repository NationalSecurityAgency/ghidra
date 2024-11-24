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
package ghidra.app.util.pdb.classtype;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public enum Property {
	UNKNOWN("INVALID_PROPERTY", -1),
	BLANK("", 0), // means non-virtual, non-static, non-friend
	VIRTUAL("virtual", 1),
	STATIC("static", 2),
	FRIEND("friend", 3);
	// Also consider <intro>, <pure>, <intro,pure>.  See MSFT.

	private static final Map<Integer, Property> BY_VALUE = new HashMap<>();
	static {
		for (Property val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}
	private final String label;
	private final int value;

	public String getString() {
		return label;
	}

	@Override
	public String toString() {
		return label;
	}

	public int getValue() {
		return value;
	}

	public static Property fromValue(int val) {
		return BY_VALUE.getOrDefault(val, UNKNOWN);
	}

	private Property(String label, int value) {
		this.label = label;
		this.value = value;
	}
}
