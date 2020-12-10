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

import java.nio.ByteBuffer;

import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;

/**
 * A marshaller for encoding, decoding, and framing packets on a channel
 * 
 * It is certainly possible to implement a marshaller by simply invoking the codec; however, the
 * marshaller may be responsible for some portion of packet encoding not implemented in the packet
 * itself, i.e., "framing." For instance, a protocol may include a frame which gives the length of
 * the packet to follow. It is usually easier to implement this in the marshaller than in a
 * {@link Packet}.
 * 
 * @param <W> the type of packets to write, possibly abstract
 * @param <R> the type of packets to read, possibly abstract
 * @param <E> the type of buffer for framing and encoding packets, usually {@link ByteBuffer}
 */
public interface PacketMarshaller<W, R, E> {
	/**
	 * Marshall a packet into the given buffer
	 * 
	 * @param outbuf the output buffer
	 * @param pkt the packet to encode and marshall
	 * @throws PacketEncodeException if there's a problem encoding the packet
	 */
	public abstract void marshall(E outbuf, W pkt) throws PacketEncodeException;

	/**
	 * Unmarshall a packet from the given buffer using a given packet sub-type
	 * 
	 * @param expected the sub-type expected
	 * @param inbuf the input buffer
	 * @return the unmarshalled and decoded packet
	 * @throws PacketDecodeException if there's a problem decoding the packet
	 * 
	 * @NOTE If an error occurs preventing the successful unmarshalling of a complete packet, then
	 *       this method must restore the buffer's state so that no data is consumed.
	 */
	public abstract <R2 extends R> R2 unmarshall(Class<R2> expected, E inbuf)
			throws PacketDecodeException;

	/**
	 * Unmarshall a packet from the given buffer using the default packet type
	 * 
	 * @param inbuf the input buffer
	 * @return the unmarshalled and decoded packet
	 * @throws PacketDecodeException if there's a problem decoding the packet
	 * 
	 * @NOTE If an error occurs preventing the successful unmarshalling of a complete packet, then
	 *       this method must restore the buffer's state so that no data is consumed.
	 */
	public default R unmarshall(E inbuf) throws PacketDecodeException {
		return unmarshall(getDefaultType(), inbuf);
	}

	/**
	 * Get the default packet type for reading
	 * 
	 * @return the default packet type
	 */
	public Class<? extends R> getDefaultType();
}
