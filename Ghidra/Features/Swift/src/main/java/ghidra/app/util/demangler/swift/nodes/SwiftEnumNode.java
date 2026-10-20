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

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.swift.SwiftDemangledNodeKind;
import ghidra.app.util.demangler.swift.SwiftDemangler;
import ghidra.app.util.demangler.swift.datatypes.SwiftEnum;

/**
 * A {@link SwiftDemangledNodeKind#Enum} {@link SwiftNode}
 */
public class SwiftEnumNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		String name = null;
		Demangled namespace = null;
		Demangled privateDeclNamespace = null;
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
				case Structure:
					namespace = child.demangle(demangler);
					break;
				default:
					skip(child);
					break;
			}
		}
		if (name == null) {
			return getUnknown();
		}
		return new SwiftEnum(properties.mangled(), properties.originalDemangled(), name,
			SwiftNode.join(namespace, privateDeclNamespace), demangler);
	}
}
