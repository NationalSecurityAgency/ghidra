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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.AbstractParsableItem;

/**
 * VTShape Descriptor Property used on VtShapeMsType PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class VtShapeDescriptorMsProperty extends AbstractParsableItem {

	private static final int NEAR = 0;
	private static final int FAR = 1;
	private static final int THIN = 2;
	private static final int OUTER = 3;
	private static final int META = 4;
	private static final int NEAR32 = 5;
	private static final int FAR32 = 6;
	private static final int UNUSED = 7;

	private static final String[] VTS_STRING = new String[8];
	static {
		VTS_STRING[0] = "near";
		VTS_STRING[1] = "far";
		VTS_STRING[2] = "thin";
		VTS_STRING[3] = "outer";
		VTS_STRING[4] = "meta";
		VTS_STRING[5] = "near32";
		VTS_STRING[6] = "far32";
		VTS_STRING[7] = "";
	}

	//==============================================================================================
	private int value;

	//==============================================================================================
	/**
	 * Constructor for the VtShapeDescriptorMsProperty
	 * @param value Value of the property.
	 */
	public VtShapeDescriptorMsProperty(int value) {
		this.value = value;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isNear() {
		return (value == NEAR);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isFar() {
		return (value == FAR);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isThin() {
		return (value == THIN);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isOuter() {
		return (value == OUTER);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isMeta() {
		return (value == META);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isNear32() {
		return (value == NEAR32);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isFar32() {
		return (value == FAR32);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isUnused() {
		return (value >= UNUSED);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(VTS_STRING[value]);
	}

}
