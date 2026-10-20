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
 * A Swift tuple
 */
public class SwiftTuple extends SwiftStructure {

	/**
	 * Creates a new Swift tuple
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param list The elements of the tuple
	 * @param demangler A {@link SwiftDemangler}
	 * @throws DemangledException if a problem occurred
	 */
	public SwiftTuple(String mangled, String originalDemangled, DemangledList list,
			SwiftDemangler demangler) throws DemangledException {
		super(mangled, originalDemangled, "tuple%d".formatted(list.size()), null, demangler);

		int i = 0;
		for (Demangled element : list) {
			if (element instanceof DemangledDataType ddt) {
				addField(Integer.toString(i), ddt);
			}
			else if (element instanceof DemangledVariable variable) {
				addField(variable.getName(), variable.getDataType());
			}
			i++;
		}
	}
}
