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
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for encoding byte arrays for {@link AbstractByteBufferPacketCodec}
 * 
 * This simply appends the array contents to the buffer for encoding, or consumes the remaining
 * contents of the buffer for decoding.
 */
class ByteArrayFieldCodec extends AbstractFieldCodec<ByteBuffer, ByteBuffer, byte[]> {
	private final AbstractByteBufferPacketCodec<?> codec;

	ByteArrayFieldCodec(AbstractByteBufferPacketCodec<?> codec, Class<? extends Packet> pktType,
			Field field) {
		super(pktType, field);
		this.codec = codec;
	}

	@Override
	public byte[] decodeField(Packet pkt, ByteBuffer buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return codec.decodeByteArray(field, buf, count);
	}

	@Override
	public void encodeField(ByteBuffer buf, Packet pkt, byte[] val)
			throws IOException, PacketEncodeException {
		codec.encodeByteArray(buf, field, val);
	}
}
