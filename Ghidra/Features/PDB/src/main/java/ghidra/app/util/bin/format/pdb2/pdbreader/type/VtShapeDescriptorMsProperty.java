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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.util.HashMap;
import java.util.Map;

/**
 * VTShape Descriptor Property used on VtShapeMsType PDB data type.
 */
public enum VtShapeDescriptorMsProperty {

	NEAR("near", 0),
	FAR("far", 1),
	THIN("thin", 2),
	OUTER("outer", 3),
	META("meta", 4),
	NEAR32("near32", 5),
	FAR32("far32", 6),
	UNUSED("unused", 7);

	private static final Map<Integer, VtShapeDescriptorMsProperty> BY_VALUE = new HashMap<>();
	static {
		for (VtShapeDescriptorMsProperty val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	public final String label;
	public final int value;

	@Override
	public String toString() {
		return label;
	}

	public static VtShapeDescriptorMsProperty fromValue(int val) {
		return BY_VALUE.getOrDefault(val, UNUSED);
	}

	private VtShapeDescriptorMsProperty(String label, int value) {
		this.label = label;
		this.value = value;
	}

}
