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
 * A {@link SwiftDemangledNodeKind#ProtocolConformance} {@link SwiftNode}
 */
public class SwiftProtocolConformanceNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		Demangled type = null;
		Demangled protocol = null;
		Demangled namespace = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case Module:
					namespace = child.demangle(demangler);
					break;
				case Type:
					if (child.hasChild(SwiftDemangledNodeKind.Protocol)) {
						protocol = child.demangle(demangler);
					}
					else {
						type = child.demangle(demangler);
					}
					break;
				default:
					skip(child);
					break;
			}
		}
		if (type == null || protocol == null) {
			return getUnknown();
		}
		DemangledUnknown demangled =
			new DemangledUnknown(properties.mangled(), properties.originalDemangled(),
				type.getNamespaceString() + "->" + protocol.getNamespaceString());
		demangled.setNamespace(namespace);
		return demangled;
	}
}
