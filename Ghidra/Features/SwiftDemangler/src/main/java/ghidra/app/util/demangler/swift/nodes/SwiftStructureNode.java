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
import ghidra.app.util.demangler.swift.datatypes.*;

/**
 * A {@link SwiftDemangledNodeKind#Structure} {@link SwiftNode}
 */
public class SwiftStructureNode extends SwiftNode {

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

		String mangled = properties.mangled();
		String orig = properties.originalDemangled();
		if (SwiftDataTypeUtils.isSwiftNamespace(namespace)) {
			DemangledDataType type = switch (name) {
				case "Bool" -> new SwiftPrimitive(mangled, orig, DemangledDataType.BOOL);
				case "Int" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT);
				case "Int8" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT8);
				case "Int16" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT16);
				case "Int32" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT32);
				case "Int64" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT64);
				case "UInt" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT, true);
				case "UInt8" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT8, true);
				case "UInt16" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT16, true);
				case "UInt32" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT32, true);
				case "UInt64" -> new SwiftPrimitive(mangled, orig, DemangledDataType.INT64, true);
				case "Float" -> new SwiftPrimitive(mangled, orig, DemangledDataType.FLOAT);
				case "Float16" -> new SwiftPrimitive(mangled, orig, DemangledDataType.FLOAT2);
				case "Double" -> new SwiftPrimitive(mangled, orig, DemangledDataType.DOUBLE);
				case "Array" -> new SwiftArray(mangled, orig);
				case "Character" -> new SwiftCharacter(mangled, orig);
				case "String" -> new SwiftString(mangled, orig);
				default -> null;
			};
			if (type != null) {
				return type;
			}
		}

		SwiftStructure struct = new SwiftStructure(mangled, orig, name,
			SwiftNode.join(namespace, privateDeclNamespace), demangler);

		// The structure has no fields, which behaves poorly in the decompiler. Give it one
		// undefined* field instead.
		if (struct.getFields().isEmpty()) {
			DemangledDataType undefined =
				new DemangledDataType(mangled, orig, DemangledDataType.UNDEFINED);
			undefined.incrementPointerLevels();
			struct.addField("unknown", null, undefined);
		}

		return struct;
	}
}
