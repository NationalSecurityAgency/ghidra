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
package ghidra.dbg.sctl.protocol;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.TypedByField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.consts.Mkind;

public abstract class AbstractSelSctlPacket extends Packet {
	/**
	 * For unmarshalling
	 */
	public AbstractSelSctlPacket() {
	}

	/**
	 * Construct a SCTL message with the given tag and message
	 * 
	 * @param tag the tag
	 * @param sel the message
	 */
	public AbstractSelSctlPacket(int tag, SctlPacket sel) {
		this.tag = tag;
		this.sel = sel;
	}

	@PacketField
	public Mkind op;

	@PacketField
	public int tag;

	@PacketField
	@TypedByField(by = "op", map = "METHOD_MAP")
	public SctlPacket sel;
}
