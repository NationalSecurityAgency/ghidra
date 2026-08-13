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
import ghidra.app.util.demangler.DemangledStructure;

/**
 * A Swift character
 */
public class SwiftCharacter extends DemangledStructure {

	/**
	 * Creates a new Swift character
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 */
	public SwiftCharacter(String mangled, String originalDemangled) {
		super(mangled, originalDemangled, "Character",
			SwiftDataTypeUtils.getCategoryPath(SwiftDataTypeUtils.getSwiftNamespace()).getPath(),
			true);
		setNamespace(SwiftDataTypeUtils.getSwiftNamespace());

		DemangledDataType stringDt = new DemangledDataType(mangled, null, DemangledDataType.CHAR);
		stringDt.incrementPointerLevels();

		DemangledDataType voidDt = new DemangledDataType(mangled, null, DemangledDataType.VOID);
		voidDt.incrementPointerLevels();

		addField("str", stringDt);
		addField("bridgeObject", voidDt);
	}
}
