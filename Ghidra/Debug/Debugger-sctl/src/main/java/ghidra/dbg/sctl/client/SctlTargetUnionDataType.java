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

public class SctlTargetUnionDataType extends SctlTargetCompositeDataType<SctlTargetUnionDataType> {

	public static class Ref extends AbstractRef<SctlTargetUnionDataType> {
		protected final SctlUnionTypeName nUnion;

		public Ref(SctlTargetDataTypeNamespace types, SctlUnionTypeName nUnion) {
			super(types, nUnion);
			this.nUnion = nUnion;
		}

		@Override
		protected CompletableFuture<? extends SctlTargetUnionDataType> doGet() {
			return AsyncUtils.sequence(TypeSpec.cls(SctlTargetUnionDataType.class)).then(seq -> {
				types.getTypeDef(nUnion).handle(seq::next);
			}, TypeSpec.cls(SelSctlTypeDefinition.class)).then((def, seq) -> {
				SctlUnionTypeDefinition dUnion = (SctlUnionTypeDefinition) def.sel;
				SctlTargetUnionDataType tStruct =
					new SctlTargetUnionDataType(types, nUnion, dUnion);
				tStruct.collectFields().thenApply(__ -> tStruct).handle(seq::next);
			}, TypeSpec.cls(SctlTargetUnionDataType.class)).then((tUnion, seq) -> {
				types.changeElements(List.of(), List.of(tUnion), "Fetched");
				seq.exit(tUnion);
			}).finish();
		}
	}

	protected SctlTargetUnionDataType(SctlTargetDataTypeNamespace types, SctlUnionTypeName nUnion,
			SctlUnionTypeDefinition dUnion) {
		super(types, nUnion, dUnion, NamedDataTypeKind.UNION, "UnionType");
	}
}
