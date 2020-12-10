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
package ghidra.dbg.sctl.protocol.types;

import java.util.Map;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.TypedByField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.consts.Tkind;

/**
 * The format for {@code tname} in SCTL
 * 
 * This parses {@code Tkind} and selects the appropriate kind of type name
 */
public class SelSctlTypeName extends Packet {
	public SelSctlTypeName() {
	}

	public SelSctlTypeName(AbstractSctlTypeName sel) {
		this.sel = sel;
	}

	public static final Map<Tkind, Class<? extends AbstractSctlTypeName>> KIND_MAP =
		typeMap(Tkind.class, AbstractSctlTypeName.class) //
				.put(Tkind.Tbase, SctlBaseTypeName.class) // 1. base type
				.put(Tkind.Tstruct, SctlStructTypeName.class) // 2. tagged type
				.put(Tkind.Tunion, SctlUnionTypeName.class) // 2. ...
				.put(Tkind.Tenum, SctlEnumTypeName.class) // 2. ...
				.put(Tkind.Ttypedef, SctlTypedefTypeName.class) // 3. typedef type
				.put(Tkind.Tptr, SctlPointerTypeName.class) // 4. pointer type
				.put(Tkind.Tarr, SctlArrayTypeName.class) // 5. array type
				.put(Tkind.Tfun, SctlFunctionTypeName.class) // 6. function type
				.put(Tkind.Tbitfield, SctlBitfieldTypeName.class) // 7. bitfield type
				.put(Tkind.Tconst, SctlEnumConstTypeName.class) // 8. enumeration constant type
				.put(Tkind.Tundef, SctlUndefinedTypeName.class) // 9. undefined
				.build();

	@PacketField
	public Tkind kind;

	@PacketField
	@TypedByField(by = "kind", map = "KIND_MAP")
	public AbstractSctlTypeName sel;
}
