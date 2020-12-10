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
import ghidra.comm.packet.annot.SizedByField;
import ghidra.comm.packet.fields.PacketField;

/**
 * A string in {@code size[8]str[size]} format
 */
public class SctlString extends Packet {
	/**
	 * For unmarshalling
	 */
	public SctlString() {
	}

	/**
	 * Wrap a string for SCTL packets
	 * 
	 * @param str the string
	 */
	public SctlString(String str) {
		this.str = str;
	}

	@PacketField
	public long len;

	@PacketField
	@SizedByField("len")
	public String str;

	@Override
	public String toString() {
		return "\"" + str + "\"";
	}
}
