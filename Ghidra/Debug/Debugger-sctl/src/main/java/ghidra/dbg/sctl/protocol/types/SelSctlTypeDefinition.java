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
 * The format for {@code tdef[]} in SCTL
 * 
 * This parses {@code Tkind} and selects the appropriate kind of type definition
 */
public class SelSctlTypeDefinition extends Packet {
	public static final Map<Tkind, Class<? extends AbstractSctlTypeDefinition>> KIND_MAP =
		typeMap(Tkind.class, AbstractSctlTypeDefinition.class) //
				.put(Tkind.Tbase, SctlBaseTypeDefinition.class) // 1. base type
				.put(Tkind.Tstruct, SctlStructTypeDefinition.class) // 2. aggregate types
				.put(Tkind.Tunion, SctlUnionTypeDefinition.class) // 2. ...
				.put(Tkind.Tenum, SctlEnumTypeDefinition.class) // 3. enum type
				.put(Tkind.Ttypedef, SctlTypedefTypeDefinition.class) // 4. typedef type
				.build();

	@PacketField
	public Tkind kind;

	@PacketField
	@TypedByField(by = "kind", map = "KIND_MAP")
	public AbstractSctlTypeDefinition sel;

	public AbstractSctlTypeName getTypeName() {
		return sel.getTypeName();
	}
}
