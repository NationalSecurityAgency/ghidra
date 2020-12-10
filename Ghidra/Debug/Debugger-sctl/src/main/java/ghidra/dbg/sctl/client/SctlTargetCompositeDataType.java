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
import ghidra.dbg.sctl.protocol.types.*;

public class SctlTargetCompositeDataType<T extends SctlTargetCompositeDataType<T>>
		extends SctlTargetNamedDataType<T, SctlTargetCompositeField> {

	// TODO: Dispose of this once converted?
	protected final AbstractSctlAggregateTypeDefinition tdef;

	protected SctlTargetCompositeDataType(SctlTargetDataTypeNamespace types,
			AbstractSctlTaggedTypeName tname, AbstractSctlAggregateTypeDefinition tdef,
			NamedDataTypeKind kind, String typeHint) {
		super(types, tname, kind, typeHint);
		this.tdef = tdef;
	}

	protected CompletableFuture<Void> collectFields() {
		AsyncFence fence = new AsyncFence();
		List<SctlTargetCompositeField> elems = new ArrayList<>(tdef.fields.size());
		for (int i = 0; i < tdef.fields.size(); i++) {
			int pos = i;
			SctlAggregateField field = tdef.fields.get(i);
			fence.include(parent.getType(field.tname.sel).thenAccept(t -> {
				SctlTargetCompositeField f =
					new SctlTargetCompositeField(this, pos, field.off, field.id.str, t);
				synchronized (elems) {
					elems.add(f);
				}
			}));
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), elems, "Initialized");
		});
	}
}
