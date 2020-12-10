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
package ghidra.comm.packet.err;

import ghidra.comm.packet.Packet;

/**
 * Occurs when a packet class is declared incorrectly, i.e., missing a public default constructor
 */
public class PacketDeclarationException extends RuntimeException {
	private Class<? extends Packet> packet;

	public PacketDeclarationException(Class<? extends Packet> packet, String msg, Throwable cause) {
		super("Problem in " + packet + ": " + msg, cause);
		this.packet = packet;
	}

	public PacketDeclarationException(Class<? extends Packet> packet, String msg) {
		this(packet, msg, null);
	}

	public Class<? extends Packet> getPacket() {
		return packet;
	}
}
