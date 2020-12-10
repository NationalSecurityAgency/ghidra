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

public class SctlTargetStructDataType
		extends SctlTargetCompositeDataType<SctlTargetStructDataType> {

	public static class Ref extends AbstractRef<SctlTargetStructDataType> {
		protected final SctlStructTypeName nStruct;

		public Ref(SctlTargetDataTypeNamespace types, SctlStructTypeName nStruct) {
			super(types, nStruct);
			this.nStruct = nStruct;
		}

		@Override
		protected CompletableFuture<? extends SctlTargetStructDataType> doGet() {
			return AsyncUtils.sequence(TypeSpec.cls(SctlTargetStructDataType.class)).then(seq -> {
				types.getTypeDef(nStruct).handle(seq::next);
			}, TypeSpec.cls(SelSctlTypeDefinition.class)).then((def, seq) -> {
				SctlStructTypeDefinition dStruct = (SctlStructTypeDefinition) def.sel;
				SctlTargetStructDataType tStruct =
					new SctlTargetStructDataType(types, nStruct, dStruct);
				tStruct.collectFields().thenApply(__ -> tStruct).handle(seq::next);
			}, TypeSpec.cls(SctlTargetStructDataType.class)).then((tStruct, seq) -> {
				types.changeElements(List.of(), List.of(tStruct), "Fetched");
				seq.exit(tStruct);
			}).finish();
		}
	}

	protected SctlTargetStructDataType(SctlTargetDataTypeNamespace types,
			SctlStructTypeName nStruct, SctlStructTypeDefinition dStruct) {
		super(types, nStruct, dStruct, NamedDataTypeKind.STRUCT, "StructType");
	}
}
