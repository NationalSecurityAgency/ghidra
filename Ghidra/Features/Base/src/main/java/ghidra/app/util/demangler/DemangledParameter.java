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
package ghidra.app.util.demangler;

/**
 * A class to represent a demangled function parameter.
 * <p>
 * This extends {@link DemangledDataType} in order to associate an optional parameter label with
 * its data type.
 */
public class DemangledParameter {

	private DemangledDataType type;
	private String label;

	/**
	 * Creates a new {@link DemangledParameter} with the given type and no label
	 * 
	 * @param type The parameter type
	 */
	public DemangledParameter(DemangledDataType type) {
		this.type = type;
	}

	/**
	 * {@return the parameter's type}
	 */
	public DemangledDataType getType() {
		return type;
	}

	/**
	 * {@return the parameter's label (could be null)}
	 */
	public String getLabel() {
		return label;
	}

	/**
	 * Sets the parameter's label
	 * 
	 * @param label The label (null for no label)
	 */
	public void setLabel(String label) {
		this.label = label;
	}

	@Override
	public String toString() {
		String ret = type.toString();
		if (label != null) {
			ret += " " + label;
		}
		return ret;
	}
}
