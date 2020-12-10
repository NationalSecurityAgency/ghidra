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

import ghidra.comm.packet.*;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * A codec for all the basic types including primitives, strings, enumerations, and sub-packets
 * 
 * This interface is used primarily by {@link AbstractPacketCodec} as a convenience for providing an
 * implementation of {@link FieldCodec} for each of the basic types. It is easier to implement these
 * methods than it is to implement an individual class for each primitive.
 * 
 * @param <ENCBUF> the type of the temporary encode buffer
 * @param <DECBUF> the type of the temporary decode buffer
 */
public interface PrimitiveCodec<ENCBUF, DECBUF> {
	/**
	 * Decode a boolean value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	boolean decodeBoolean(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode a byte value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	byte decodeByte(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode a character value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	char decodeChar(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode a short integer value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	short decodeShort(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode an integer value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	int decodeInt(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode a long integer value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	long decodeLong(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode a single-precision float value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	float decodeFloat(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode a double-precision float value
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	double decodeDouble(Field field, DECBUF buf) throws IOException, PacketDecodeException;

	/**
	 * Decode an enumeration constant
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param type the enumeration of values expected
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	<E extends Enum<E>> E decodeEnumConstant(Field field, DECBUF buf, Class<E> type)
			throws IOException, PacketDecodeException;

	/**
	 * Decode a character sequence, e.g., {@link String}
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param count the number of characters to decode, or null for unlimited
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	CharSequence decodeCharSequence(Field field, DECBUF buf, Integer count)
			throws IOException, PacketDecodeException;

	/**
	 * Decode a packet
	 * 
	 * This is used internally both to decode root packets, as well as to decode packets used as
	 * fields in parent packets.
	 * 
	 * @param parent if applicable, the packet containing this packet as a field
	 * @param field if applicable, the field of the parent packet
	 * @param buf the decode buffer positioned at the packet data
	 * @param pktType the type of packet to decode
	 * @param factory a factory for instantiating abstract types
	 * @return the decoded packet
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	<P extends Packet> P decodePacket(Packet parent, Field field, DECBUF buf, Class<P> pktType,
			PacketFactory factory) throws IOException, PacketDecodeException;

	/**
	 * Encode a boolean value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeBoolean(ENCBUF buf, Field field, boolean val)
			throws IOException, PacketEncodeException;

	/**
	 * Encode a byte value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeByte(ENCBUF buf, Field field, byte val) throws IOException, PacketEncodeException;

	/**
	 * Encode a character value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeChar(ENCBUF buf, Field field, char val) throws IOException, PacketEncodeException;

	/**
	 * Encode a short integer value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeShort(ENCBUF buf, Field field, short val) throws IOException, PacketEncodeException;

	/**
	 * Encode an integer value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeInt(ENCBUF buf, Field field, int val) throws IOException, PacketEncodeException;

	/**
	 * Encode a long integer value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeLong(ENCBUF buf, Field field, long val) throws IOException, PacketEncodeException;

	/**
	 * Encode a single-precision float value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeFloat(ENCBUF buf, Field field, float val) throws IOException, PacketEncodeException;

	/**
	 * Encode a double-precision float value
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeDouble(ENCBUF buf, Field field, double val)
			throws IOException, PacketEncodeException;

	/**
	 * Encode an enumeration constant
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	public void encodeEnumConstant(ENCBUF buf, Field field, Enum<?> val)
			throws IOException, PacketEncodeException;

	/**
	 * Encode a character sequence, e.g., {@link String}
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodeCharSequence(ENCBUF buf, Field field, CharSequence val)
			throws IOException, PacketEncodeException;

	/**
	 * Encode a packet
	 * 
	 * This is used internally both to encode root packets, as well as to encode packets used as
	 * fields in parent packets.
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field if applicable, the field of the parent packet
	 * @param val the packet to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	void encodePacket(ENCBUF buf, Field field, Packet val)
			throws IOException, PacketEncodeException;
}
