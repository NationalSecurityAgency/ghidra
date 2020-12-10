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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.sctl.protocol.types.*;

public class SctlTargetEnumDataType
		extends SctlTargetNamedDataType<SctlTargetEnumDataType, SctlTargetEnumConstant> {

	public static class Ref extends AbstractRef<SctlTargetEnumDataType> {
		protected final SctlEnumTypeName nEnum;

		protected Ref(SctlTargetDataTypeNamespace types, SctlEnumTypeName nEnum) {
			super(types, nEnum);
			this.nEnum = nEnum;
		}

		@Override
		protected CompletableFuture<? extends SctlTargetEnumDataType> doGet() {
			return AsyncUtils.sequence(TypeSpec.cls(SctlTargetEnumDataType.class)).then(seq -> {
				types.getTypeDef(nEnum).handle(seq::next);
			}, TypeSpec.cls(SelSctlTypeDefinition.class)).then((def, seq) -> {
				SctlEnumTypeDefinition dEnum = (SctlEnumTypeDefinition) def.sel;
				SctlTargetEnumDataType tEnum = new SctlTargetEnumDataType(types, nEnum, dEnum);
				types.changeElements(List.of(), List.of(tEnum), "Fetched");
				seq.exit(tEnum);
			}).finish();
		}
	}

	// TODO: Dispose of this once converted?
	protected final SctlEnumTypeDefinition dEnum;

	protected final int byteLength;

	public SctlTargetEnumDataType(SctlTargetDataTypeNamespace types, SctlEnumTypeName tname,
			SctlEnumTypeDefinition dEnum) {
		super(types, tname, NamedDataTypeKind.ENUM, "EnumType");
		this.dEnum = dEnum;

		this.byteLength = dEnum.rep.getByteLength();

		changeAttributes(List.of(), Map.of( //
			ENUM_BYTE_LENGTH_ATTRIBUTE_NAME, byteLength //
		), "Initialized");

		List<SctlTargetEnumConstant> elems = new ArrayList<>(dEnum.consts.size());
		for (int i = 0; i < dEnum.consts.size(); i++) {
			SctlEnumConstant c = dEnum.consts.get(i);
			elems.add(new SctlTargetEnumConstant(this, i, c.value, c.id.str));
		}
		changeElements(List.of(), elems, "Initialized");
	}
}
