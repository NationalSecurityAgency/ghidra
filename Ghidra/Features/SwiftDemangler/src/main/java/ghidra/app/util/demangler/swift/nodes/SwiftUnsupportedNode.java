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

/**
 * A {@link SwiftDemangledNodeKind#Unsupported} {@link SwiftNode}
 */
public class SwiftUnsupportedNode extends SwiftNode {

	private String originalKind;

	/**
	 * Create a new {@link SwiftUnsupportedNode} {@link SwiftNode}
	 * 
	 * @param originalKind The original {@link SwiftDemangledNodeKind kind} of {@link SwiftNode} that is
	 *   not supported
	 * @param props The {@link ghidra.app.util.demangler.swift.nodes.SwiftNode.NodeProperties}
	 */
	public SwiftUnsupportedNode(String originalKind, NodeProperties props) {
		this.originalKind = originalKind;
		this.properties = props;
	}

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		skip(this);
		return getUnknown();
	}
	
	@Override
	public String toString() {
		return super.toString() + " (" + originalKind + ")";
	}
}
