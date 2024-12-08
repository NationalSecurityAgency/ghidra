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

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangler;

/**
 * A Swift structure
 */
public class SwiftEnum extends DemangledStructure {

	/**
	 * Creates a new Swift enum
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The enum name
	 * @param namespace The enum namespace (could be null)
	 * @param demangler A {@link SwiftDemangler}
	 * @throws DemangledException if a problem occurred
	 */
	public SwiftEnum(String mangled, String originalDemangled, String name, Demangled namespace,
			SwiftDemangler demangler) throws DemangledException {
		super(mangled, originalDemangled, name,
			SwiftDataTypeUtils.getCategoryPath(namespace).getPath(), true);
		setNamespace(namespace);

		// The mangled output doesn't seem to indicate what field of the enum is being used, so
		// it's not currently clear how to query the type metadata for real type information.
		// Raw enums seem to just be bytes, so for now we'll just use a struct with 1 byte entry.
		DemangledDataType dt =
			new DemangledDataType(mangled, originalDemangled, DemangledDataType.INT8);
		addField("value", null, dt);
	}
}
