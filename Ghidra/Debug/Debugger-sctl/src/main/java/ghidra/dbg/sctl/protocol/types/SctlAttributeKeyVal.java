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
import ghidra.dbg.sctl.protocol.consts.Attrval;

/**
 * The format for SCTL key-value pairs in attributes
 */
public class SctlAttributeKeyVal extends Packet {
	public static final Map<Attrval, Class<? extends SctlAtom>> ATOM_MAP =
		typeMap(Attrval.class, SctlAtom.class) //
				.put(Attrval.Astr, SctlStringAtom.class) //
				.put(Attrval.Acid, SctlSymbolAtom.class) //
				.put(Attrval.Auint, SctlUIntAtom.class) // 
				.build();

	@PacketField
	public Attrval keyKind;

	@PacketField
	@TypedByField(by = "keyKind", map = "ATOM_MAP")
	public SctlAtom key;

	@PacketField
	public Attrval valKind;

	@PacketField
	@TypedByField(by = "valKind", map = "ATOM_MAP")
	public SctlAtom val;
}
