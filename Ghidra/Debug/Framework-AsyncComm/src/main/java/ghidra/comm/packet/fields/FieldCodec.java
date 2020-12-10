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
package ghidra.comm.packet.fields;

import java.io.IOException;

import ghidra.comm.packet.*;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;

/**
 * A codec to encode fields of a particular type
 * 
 * This may be provided by the packet codec, in which case it's most likely a primitive field codec,
 * i.e., at the top of the chain. Primitive field codecs actually encode the given data into the
 * final output buffer, or decode data from the input buffer. Non-primitive field codecs -- those
 * found further down the chain -- transform or process the data as it passes on to the next field
 * codec.
 * 
 * @see AbstractPacketCodec
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type linking this codec to the next codec down the chain, or to the annotated
 *            field
 */
public interface FieldCodec<ENCBUF, DECBUF, T> {
	/**
	 * Decode a value from a buffer
	 * 
	 * @param pkt the packet currently being decoded
	 * @param buf the buffer from which the value is decoded
	 * @param count for arrays and collections, the number of elements to decode, or {@code null}
	 *            for unlimited
	 * @param factory a packet factory, usually implementing a particular version of the protocol
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException;

	/**
	 * Encode a value into a buffer
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param pkt the packet currently being encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException;
}
