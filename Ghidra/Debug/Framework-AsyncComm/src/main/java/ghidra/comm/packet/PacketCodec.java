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
package ghidra.comm.packet;

import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;

/**
 * A means of encoding and decoding packets
 * 
 * @param <T> the type of encoded packets
 */
public interface PacketCodec<T> {
	/**
	 * Register a packet type with this codec
	 * 
	 * This performs some validation of the packet definition and prepares encoders and decoders for
	 * the individual fields -- called field codecs -- for the packet. A packet must be registered
	 * before and can be encoded or decoded. Note that registering a packet type implicitly
	 * registers the packet types of any of its fields, recursively. Thus, if the protocol is
	 * defined by a single root packet type, it is only necessary to register it. If a packet
	 * factory will be used, its particular implementations must be registered explicitly, often via
	 * {@link PacketFactory#registerTypes(PacketCodec)}.
	 * 
	 * @param pkt the packet type to register
	 */
	public void registerPacketType(Class<? extends Packet> pkt);

	/**
	 * Decode a packet of the given type from encoded data
	 * 
	 * @param pktType the type of packet expected
	 * @param data the encoded packet data
	 * @return the decoded packet
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public default <P extends Packet> P decodePacket(Class<P> pktType, T data)
			throws PacketDecodeException {
		return decodePacket(pktType, data, DefaultPacketFactory.getInstance());
	}

	/**
	 * Decode a packet of the given type from encoded data using a packet factory
	 * 
	 * Packet factories provide a means of dynamically modifying the expected format of a packet, or
	 * for providing pluggable field formats. This is most commonly used for implementing multiple
	 * versions or dialects of a protocol. Pluggable points are indicated by fields having abstract
	 * types, usually extending {@link Packet}. A {@link PacketFactory} can then provide an
	 * implementation of that type particular to a version of the protocol. A different factory can
	 * be given for each decode, if desired, allowing for versions to be negotiated dynamically.
	 * 
	 * @param pktType the type of packet expected
	 * @param data the encoded packet data
	 * @param factory a packet factory, usually implementing a particular version of the protocol
	 * @return the decoded packet
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public <P extends Packet> P decodePacket(Class<P> pktType, T data, PacketFactory factory)
			throws PacketDecodeException;

	/**
	 * Encode a packet into a buffer (optional operation)
	 * 
	 * If this codec encodes to and from a mutable buffer with a cursor, then it is possible to
	 * re-use a buffer or append an encoded packet to an exiting buffer.
	 * 
	 * @see #encodePacket(Packet)
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param pkt the packet to encode
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	public void encodePacket(T buf, Packet pkt) throws PacketEncodeException;

	/**
	 * Encode a packet
	 * 
	 * During encoding, some field values may be modified, e.g., a field that measures the size of
	 * another field will be set to the appropriate value.
	 * 
	 * @param p the packet to encode
	 * @return the encoded data
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	public T encodePacket(Packet p) throws PacketEncodeException;
}
