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
package ghidra.comm.packet.binary;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.codecs.PrimitiveCodec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for encoding enumeration values for {@link AbstractByteBufferPacketCodec}
 *
 * This simply encodes the value's ordinal in the smallest primitive type possible. For example, if
 * the {@code enum} has 256 or fewer constants, the ordinal is encoding using a single byte.
 *
 * @param <U> the type of the {@code enum}
 */
public class ByteBufferEnumFieldCodec<U extends Enum<U>>
		extends AbstractFieldCodec<ByteBuffer, ByteBuffer, U> {
	private final Class<U> type;
	private final PrimitiveCodec<ByteBuffer, ByteBuffer> codec;

	public ByteBufferEnumFieldCodec(Class<? extends Packet> pktType, Field field, Class<U> type,
			PrimitiveCodec<ByteBuffer, ByteBuffer> codec) {
		super(pktType, field);
		this.type = type;
		this.codec = codec;
	}

	@Override
	public U decodeField(Packet pkt, ByteBuffer buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return codec.decodeEnumConstant(field, buf, type);
	}

	@Override
	public void encodeField(ByteBuffer buf, Packet pkt, U val)
			throws IOException, PacketEncodeException {
		codec.encodeEnumConstant(buf, field, val);
	}
}
