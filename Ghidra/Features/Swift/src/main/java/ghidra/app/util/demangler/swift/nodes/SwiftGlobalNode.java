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
import ghidra.app.util.demangler.swift.datatypes.SwiftPrimitive;
import ghidra.program.model.data.DataUtilities;

/**
 * A {@link SwiftDemangledNodeKind#Global} {@link SwiftNode}
 */
public class SwiftGlobalNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		Demangled demangled = null;
		Demangled suffix = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case GenericSpecialization:
				case MergedFunction:
				case ObjCAttribute:
					continue;
				case Suffix:
					suffix = child.demangle(demangler);
					break;
				default:
					demangled = child.demangle(demangler);
					break;
			}
		}
		if (demangled == null) {
			return getUnknown();
		}
		if (suffix != null && !(demangled instanceof SwiftPrimitive) &&
			DataUtilities.isValidDataTypeName(suffix.getName())) {
			// Some suffix names aren't renderable, so validate them
			demangled.setName(demangled.getName() + suffix.getName());
		}
		return demangled;
	}
}
