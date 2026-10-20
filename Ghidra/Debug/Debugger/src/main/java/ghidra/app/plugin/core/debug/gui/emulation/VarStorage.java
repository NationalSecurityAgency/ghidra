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
package ghidra.app.plugin.core.debug.gui.emulation;

import java.util.List;
import java.util.stream.Stream;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;

record VarStorage(List<VarStorageNode> nodes, int size) {
	static VarStorage fromPieces(Varnode[] pieces, CompilerSpec cSpec) {
		return new VarStorage(Stream.of(pieces)
				.map(vn -> VarStorageNode.fromVarnode(vn, cSpec))
				.toList());
	}

	static VarStorage fromVariableStorage(VariableStorage vs, CompilerSpec cSpec) {
		return fromPieces(vs.getVarnodes(), cSpec);
	}

	static VarStorage fromExpression(SleighLanguage language, String expression) {
		// TODO: Could break ValueLocation down into its Varnodes, but what's that buy?
		return new VarStorage(List.of(VarStorageNode.fromExpression(language, expression)));
	}

	VarStorage(List<VarStorageNode> nodes) {
		this(nodes, nodes.stream().mapToInt(VarStorageNode::size).sum());
	}

	Address address() {
		return nodes.getFirst().address();
	}

	@Override
	public final String toString() {
		if (nodes.size() == 1) {
			return nodes.getFirst().toString();
		}
		return nodes.toString();
	}

	public VarStorage deref(SleighLanguage language, AddressSpace space, int length) {
		if (nodes.size() != 1) {
			throw new UnsupportedOperationException("Deref of multi-node storage not supported");
		}
		return new VarStorage(List.of(nodes.getFirst().deref(language, space, length)), length);
	}

	public VarStorage deref(SleighLanguage language, AddressSpace space, int offset, int length) {
		if (offset == 0) {
			return deref(language, space, length);
		}
		if (nodes.size() != 1) {
			throw new UnsupportedOperationException("Deref of multi-node storage not supported");
		}
		return new VarStorage(List.of(nodes.getFirst().deref(language, space, offset, length)),
			length);
	}
}
