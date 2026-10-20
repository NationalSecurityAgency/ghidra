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
 * A {@link SwiftDemangledNodeKind#BuiltinTypeName} {@link SwiftNode}
 */
public class SwiftBuiltinTypeNameNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		String orig = getText();
		String name = switch (orig) {
			case "Builtin.Int1":
				yield DemangledDataType.INT8;
			case "Builtin.Word":
				yield DemangledDataType.INT16;
			case "Builtin.RawPointer":
				yield DemangledDataType.VOID;
			default:
				yield orig;
		};
		DemangledDataType type =
			new DemangledDataType(properties.mangled(), properties.originalDemangled(), name);
		if (orig.equals("Builtin.RawPointer")) {
			type.incrementPointerLevels();
		}
		return type;
	}
}
