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
import ghidra.program.model.lang.CompilerSpec;

/**
 * A {@link SwiftDemangledNodeKind#FunctionType} {@link SwiftNode}
 */
public class SwiftFunctionTypeNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		Demangled argumentTuple = null;
		Demangled returnType = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case ArgumentTuple:
					argumentTuple = child.demangle(demangler);
					break;
				case ReturnType:
					returnType = child.demangle(demangler);
					break;
				default:
					skip(child);
					break;
			}
		}
		SwiftFunction function =
			new SwiftFunction(properties.mangled(), properties.originalDemangled(), "<unknown>",
				null, CompilerSpec.CALLING_CONVENTION_default);

		// Parameters
		function.addParameters(SwiftDataTypeUtils.extractParameters(argumentTuple));

		// Seems like when calling a struct (or enum) method, the "this" struct is passed after the 
		// explicit parameters
		SwiftNode functionAncestor =
			getFirstAncestor(SwiftDemangledNodeKind.Function, SwiftDemangledNodeKind.Getter);
		if (functionAncestor != null) {
			if (functionAncestor.getKind().equals(SwiftDemangledNodeKind.Getter)) {
				functionAncestor = functionAncestor.getChildren().get(0);
			}
			SwiftNode struct = functionAncestor.getChild(SwiftDemangledNodeKind.Structure);
			SwiftNode enumm = functionAncestor.getChild(SwiftDemangledNodeKind.Enum);
			if (struct != null) {
				if (struct.demangle(demangler) instanceof DemangledDataType type) {
					function.addParameter(new DemangledParameter(type));
				}
			}
			else if (enumm != null) {
				if (enumm.demangle(demangler) instanceof DemangledDataType type) {
					function.addParameter(new DemangledParameter(type));
					// Enums are currently represented as single field structures, but in reality,
					// there could be more fields.  Add a varargs parameter so these other fields
					// can show up in the decompiler.
					DemangledDataType varargs = new DemangledDataType(properties.mangled(),
						properties.originalDemangled(), DemangledDataType.UNDEFINED);
					varargs.setVarArgs();
					function.addParameter(new DemangledParameter(varargs));
				}
			}
		}

		// Return type
		if (returnType instanceof DemangledDataType type) {
			function.setReturnType(type);
		}
		else if (returnType instanceof DemangledList list && list.size() > 0) {
			if (list.containsNull()) {
				DemangledDataType dt = new DemangledDataType(properties.mangled(),
					properties.originalDemangled(), DemangledDataType.UNDEFINED);
				dt.incrementPointerLevels();
				function.setReturnType(dt);
			}
			else {
				SwiftTuple tuple = new SwiftTuple(properties.mangled(),
					properties.originalDemangled(), list, demangler);
				function.setReturnType(tuple);
			}
		}

		return function;
	}
}
