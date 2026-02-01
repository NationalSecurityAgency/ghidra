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
package ghidra.app.util.demangler.swift.datatypes;

import ghidra.app.util.demangler.DemangledDataType;

/**
 * A Swift array
 */
public class SwiftArray extends DemangledDataType {

	private DemangledDataType boundType;

	/**
	 * Creates a new Swift array bound to the "undefined" type
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 */
	public SwiftArray(String mangled, String originalDemangled) {
		super(mangled, originalDemangled, "Array");
		setNamespace(SwiftDataTypeUtils.getSwiftNamespace());
		setBoundType(
			new DemangledDataType(mangled, originalDemangled, DemangledDataType.UNDEFINED));
		setArray(1);
	}

	/**
	 * {@return the bound type}
	 */
	public DemangledDataType getBoundType() {
		return boundType;
	}

	/**
	 * Sets the bound type
	 * 
	 * @param type The bound type
	 */
	public void setBoundType(DemangledDataType type) {
		boundType = type;
		setName("Array<%s>".formatted(type.getName()));
	}
}
