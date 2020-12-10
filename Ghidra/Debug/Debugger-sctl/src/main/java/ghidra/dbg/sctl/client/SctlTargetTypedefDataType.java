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

import java.util.List;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.sctl.protocol.types.*;

public class SctlTargetTypedefDataType
		extends SctlTargetNamedDataType<SctlTargetTypedefDataType, SctlTargetTypedefDef> {

	public static class Ref extends AbstractRef<SctlTargetTypedefDataType> {
		protected final SctlTypedefTypeName nTypedef;

		public Ref(SctlTargetDataTypeNamespace types, SctlTypedefTypeName nTypedef) {
			super(types, nTypedef);
			this.nTypedef = nTypedef;
		}

		@Override
		protected CompletableFuture<? extends SctlTargetTypedefDataType> doGet() {
			return AsyncUtils.sequence(TypeSpec.cls(SctlTargetTypedefDataType.class)).then(seq -> {
				types.getTypeDef(nTypedef).handle(seq::next);
			}, TypeSpec.cls(SelSctlTypeDefinition.class)).then((def, seq) -> {
				SctlTypedefTypeDefinition dTypedef = (SctlTypedefTypeDefinition) def.sel;
				SctlTargetTypedefDataType tTypedef =
					new SctlTargetTypedefDataType(types, nTypedef, dTypedef);
				tTypedef.collectDef().thenApply(__ -> tTypedef).handle(seq::next);
			}, TypeSpec.cls(SctlTargetTypedefDataType.class)).then((tTypedef, seq) -> {
				types.changeElements(List.of(), List.of(tTypedef), "Fetched");
				seq.exit(tTypedef);
			}).finish();
		}
	}

	// TODO: Dispose of this once converted?
	protected final AbstractSctlTypeName nDef;

	public SctlTargetTypedefDataType(SctlTargetDataTypeNamespace types, SctlTypedefTypeName tname,
			SctlTypedefTypeDefinition dTypedef) {
		super(types, tname, NamedDataTypeKind.TYPEDEF, "TypedefType");
		this.nDef = dTypedef.tname.sel;
	}

	protected CompletableFuture<Void> collectDef() {
		return parent.getType(nDef).thenAccept(tDef -> {
			SctlTargetTypedefDef def = new SctlTargetTypedefDef(this, tDef);
			changeElements(List.of(), List.of(def), "Initialized");
		});
	}
}
