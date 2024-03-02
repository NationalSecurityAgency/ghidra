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

import java.util.stream.Collectors;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangledNodeKind;
import ghidra.app.util.demangler.swift.SwiftDemangler;
import ghidra.app.util.demangler.swift.datatypes.SwiftArray;

/**
 * A {@link SwiftDemangledNodeKind#BoundGenericStructure} {@link SwiftNode}
 */
public class SwiftBoundGenericStructureNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		Demangled type = null;
		Demangled typeList = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case Type:
					type = child.demangle(demangler);
					break;
				case TypeList:
					typeList = child.demangle(demangler);
					break;
				default:
					skip(child);
					break;
			}
		}

		if (type instanceof SwiftArray arr) {
			if (typeList instanceof DemangledList list && !list.isEmpty()) {
				Demangled first = list.get(0);
				if (first instanceof DemangledDataType ddt) {
					arr.setBoundType(ddt);
				}
			}
			return arr;
		}

		if (typeList instanceof DemangledList list) {
			String typeNames = list
					.stream()
					.map(e -> e.getName())
					.collect(Collectors.joining(","));
			type.setName("%s<%s>".formatted(type.getName(), typeNames));
			return type;
		}

		return getUnknown();
	}
}
