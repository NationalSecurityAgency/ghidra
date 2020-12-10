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
package ghidra.comm.packet.codecs;

import java.io.IOException;
import java.lang.reflect.Field;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.packet.string.RegexSeparated;

/**
 * A codec for encoding elements of an array or collection
 * 
 * @see RepeatedField
 * @see RegexSeparated
 * @see ArrayFieldCodec
 * @see CollectionFieldCodec
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <E> the type of element encoded, as passed through the chain
 */
public interface ElementCodec<ENCBUF, DECBUF, E> {
	/**
	 * Decode an element
	 * 
	 * The simplest implementation delegates directly to {@code chainNext}. Other implementations
	 * typically parse information to delineate each element.
	 * 
	 * @param pkt the packet currently being decoded
	 * @param field the field currently being decoded
	 * @param buf the buffer from which the element is decoded
	 * @param elemType the type expected for each element
	 * @param last true if this is known to be the last element of the array or collection
	 * @param chainNext the next field codec in the chain
	 * @param factory a packet factory, usually implementing a particular version of the protocol
	 * @return the decoded element
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	E decodeElement(Packet pkt, Field field, DECBUF buf, Class<E> elemType, boolean last,
			FieldCodec<ENCBUF, DECBUF, E> chainNext, PacketFactory factory)
			throws IOException, PacketDecodeException;

	/**
	 * Encode an element
	 * 
	 * The simplest implementation delegate directly to {@code chainNext}. Other implementations
	 * typically insert information to delineate each element.
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param pkt the packet currently being encoded
	 * @param field the field currently being encoded
	 * @param elem the element to encode
	 * @param last true if this is the last element of the array or collection
	 * @param chainNext the next field codec in the chain
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	void encodeElement(ENCBUF buf, Packet pkt, Field field, E elem, boolean last,
			FieldCodec<ENCBUF, DECBUF, E> chainNext) throws IOException, PacketEncodeException;
}
