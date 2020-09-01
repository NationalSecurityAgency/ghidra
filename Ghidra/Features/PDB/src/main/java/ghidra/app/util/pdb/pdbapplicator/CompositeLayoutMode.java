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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.HashMap;
import java.util.Map;

public enum CompositeLayoutMode {
	MEMBERS_ONLY("Legacy", 0, OoComponentLayoutMode.MEMBERS_ONLY),
	BASIC_SIMPLE_COMPLEX("Complex with Basic Fallback", 1, OoComponentLayoutMode.BASIC),
	SIMPLE_COMPLEX("Complex with Simple Fallback", 2, OoComponentLayoutMode.SIMPLE),
	COMPLEX("Complex Always", 3, OoComponentLayoutMode.COMPLEX);

	private static final Map<Integer, CompositeLayoutMode> BY_VALUE = new HashMap<>();
	static {
		for (CompositeLayoutMode val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	public final String label;
	private final int value;
	private OoComponentLayoutMode layoutMode;

	@Override
	public String toString() {
		return label;
	}

	private CompositeLayoutMode(String label, int value, OoComponentLayoutMode layoutMode) {
		this.label = label;
		this.value = value;
		this.layoutMode = layoutMode;
	}

	public OoComponentLayoutMode getLayoutMode() {
		return layoutMode;
	}
}
