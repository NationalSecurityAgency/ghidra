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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangledNodeKind;
import ghidra.app.util.demangler.swift.SwiftDemangler;
import ghidra.app.util.demangler.swift.datatypes.SwiftTuple;

/**
 * A {@link SwiftDemangledNodeKind#Tuple} {@link SwiftNode}
 */
public class SwiftTupleNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		List<Demangled> elements = new ArrayList<>();
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case TupleElement:
					elements.add(child.demangle(demangler));
					break;
				default:
					skip(child);
					break;
			}
		}

		// Argument tuples should be treated as a list of items instead of a tuple data type
		SwiftNode parent = getParent();
		if (parent != null) {
			parent = parent.getParent();
			if (parent != null && parent.getKind().equals(SwiftDemangledNodeKind.ArgumentTuple)) {
				return new DemangledList(elements);
			}
		}

		return new SwiftTuple(properties.mangled(), properties.originalDemangled(),
			new DemangledList(elements), demangler);
	}
}
