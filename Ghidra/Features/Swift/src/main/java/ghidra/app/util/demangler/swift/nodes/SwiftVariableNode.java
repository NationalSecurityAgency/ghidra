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
package ghidra.app.util.demangler.swift.nodes;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangledNodeKind;
import ghidra.app.util.demangler.swift.SwiftDemangler;

/**
 * A {@link SwiftDemangledNodeKind#Variable} {@link SwiftNode}
 */
public class SwiftVariableNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		String name = null;
		Demangled namespace = null;
		Demangled privateDeclNamespace = null;
		Demangled type = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case Identifier:
					name = child.getText();
					break;
				case PrivateDeclName:
					Demangled temp = child.demangle(demangler);
					name = temp.getName();
					privateDeclNamespace = temp.getNamespace();
					break;
				case Class:
				case Enum:
				case Extension:
				case Module:
				case Protocol:
				case Structure:
					namespace = child.demangle(demangler);
					break;
				case Type:
					type = child.demangle(demangler);
					break;
				default:
					skip(child);
					break;
			}
		}
		if (name == null) {
			return getUnknown();
		}
		DemangledVariable variable =
			new DemangledVariable(properties.mangled(), properties.originalDemangled(), name);
		if (type instanceof DemangledDataType ddt) {
			variable.setDatatype(ddt);
		}
		variable.setNamespace(SwiftNode.join(namespace, privateDeclNamespace));
		return variable;
	}
}
