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

import java.util.List;

import ghidra.app.util.demangler.*;

/**
 * A Swift function
 */
public class SwiftFunction extends DemangledFunction {

	/**
	 * Creates a new Swift function
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The natively demangled string
	 * @param name The function name
	 * @param namespace The function namespace (could be null)
	 * @param callingConvention The function calling convention (could be null)
	 */
	public SwiftFunction(String mangled, String originalDemangled, String name, Demangled namespace,
			String callingConvention) {
		super(mangled, originalDemangled, name);
		setNamespace(namespace);
		setCallingConvention(callingConvention);
	}

	public void setType(DemangledFunction type, Demangled labelList) {
		setReturnType(type.getReturnType());
		List<DemangledParameter> params = type.getParameters();
		for (int i = 0; i < params.size(); i++) {
			DemangledParameter param = params.get(i);
			if (labelList instanceof DemangledList list && i < list.size() &&
				list.get(i) instanceof DemangledLabel label) {
				param.setLabel(label.getName());
			}
			addParameter(param);
		}
	}
}
