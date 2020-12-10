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
package ghidra.dbg.sctl.protocol.common;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.BitmaskEncoded;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.sctl.protocol.consts.Stype;
import ghidra.dbg.sctl.protocol.types.SctlAttributes;
import ghidra.dbg.sctl.protocol.types.SelSctlTypeName;

/**
 * The format of {@code sym}
 */
public class SctlSymbol extends Packet {
	/**
	 * For unmarshalling
	 */
	public SctlSymbol() {
	}

	/**
	 * Construct the symbol portion of a message
	 * 
	 * @param name the name
	 * @param flags the Stype flags
	 * @param val the value (address or constant)
	 * @param size the size, in bytes
	 * @param tname the type name
	 */
	public SctlSymbol(String name, BitmaskSet<Stype> flags, long val, long size,
			SelSctlTypeName tname) {
		this.name = new SctlString(name);
		this.flags = flags;
		this.val = val;
		this.attrs = SctlAttributes.empty();
		this.size = size;
		this.tname = tname;
	}

	@PacketField
	public SctlString name;

	@PacketField
	@BitmaskEncoded(type = Byte.class)
	public BitmaskSet<Stype> flags;

	@PacketField
	public long val;

	@PacketField
	public SctlAttributes attrs;

	@PacketField
	public long size;

	@PacketField
	public SelSctlTypeName tname;
}
