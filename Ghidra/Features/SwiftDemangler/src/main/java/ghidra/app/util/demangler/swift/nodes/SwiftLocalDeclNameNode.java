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
 * A {@link SwiftDemangledNodeKind#LocalDeclName} {@link SwiftNode}
 */
public class SwiftLocalDeclNameNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		String name = null;
		Long number = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case Identifier:
					name = child.getText();
					break;
				case Number:
					try {
						number = Long.decode(child.getIndex());
					}
					catch (NumberFormatException e) {
						throw new DemangledException(e);
					}
					break;
				default:
					skip(child);
					break;
			}
		}
		if (name == null) {
			return getUnknown();
		}
		if (number != null) {
			name += "#" + (number + 1);
		}
		return new DemangledLabel(properties.mangled(), properties.originalDemangled(), name);
	}
}
