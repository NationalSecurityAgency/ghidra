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
package ghidra.dbg.sctl.client;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.dbg.sctl.protocol.types.SctlFunctionParameter;
import ghidra.dbg.sctl.protocol.types.SctlFunctionTypeName;

public class SctlTargetFunctionDataType
		extends SctlTargetNamedDataType<SctlTargetFunctionDataType, SctlTargetFunctionParameter> {

	// TODO: Dispose of this once converted?
	protected final SctlFunctionTypeName nFunction;

	public SctlTargetFunctionDataType(SctlTargetDataTypeNamespace types,
			SctlFunctionTypeName nFunction) {
		super(types, nFunction, NamedDataTypeKind.FUNCTION, "FunctionType");
		this.nFunction = nFunction;
	}

	public CompletableFuture<Void> collectMembers() {
		AsyncFence fence = new AsyncFence();
		List<SctlTargetFunctionParameter> elems = new ArrayList<>(nFunction.params.size());
		fence.include(parent.getType(nFunction.tname.sel).thenAccept(t -> {
			SctlTargetFunctionParameter r =
				new SctlTargetFunctionParameter(this, -1, "<return>", t);
			synchronized (elems) {
				elems.add(r);
			}
		}));
		for (int i = 0; i < nFunction.params.size(); i++) {
			int pos = i;
			SctlFunctionParameter param = nFunction.params.get(i);
			fence.include(parent.getType(param.tname.sel).thenAccept(t -> {
				SctlTargetFunctionParameter p =
					new SctlTargetFunctionParameter(this, pos, param.pname.str, t);
				synchronized (elems) {
					elems.add(p);
				}
			}));
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), elems, "Initialized");
		});
	}
}
