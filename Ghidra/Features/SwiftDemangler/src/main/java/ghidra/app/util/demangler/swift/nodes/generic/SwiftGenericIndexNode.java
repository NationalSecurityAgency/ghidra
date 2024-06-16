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
package ghidra.app.util.demangler.swift.nodes.generic;

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledLabel;
import ghidra.app.util.demangler.swift.SwiftDemangler;
import ghidra.app.util.demangler.swift.nodes.SwiftNode;

/**
 * A {@link SwiftNode} that just contains an index
 */
public class SwiftGenericIndexNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) {
		return new DemangledLabel(properties.mangled(), properties.originalDemangled(), getIndex());
	}
}
