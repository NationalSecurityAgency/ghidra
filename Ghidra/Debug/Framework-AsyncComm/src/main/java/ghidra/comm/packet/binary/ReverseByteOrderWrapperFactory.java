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
import java.nio.ByteOrder;
import java.util.Deque;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link ReverseByteOrder} for {@link ByteBufferPacketCodec}
 */
public class ReverseByteOrderWrapperFactory extends AbstractWrapperFactory<ByteBuffer, ByteBuffer> {
	@Override
	public <T> FieldCodec<ByteBuffer, ByteBuffer, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ByteBuffer, ByteBuffer> codec,
			Deque<FieldCodecFactory<ByteBuffer, ByteBuffer>> chain) {

		FieldCodec<ByteBuffer, ByteBuffer, T> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		return new AbstractFieldCodec<ByteBuffer, ByteBuffer, T>(pktType, field) {
			@Override
			public T decodeField(Packet pkt, ByteBuffer buf, Integer count, PacketFactory factory)
					throws IOException, PacketDecodeException {
				ByteOrder orig = buf.order();
				buf.order(
					orig == ByteOrder.BIG_ENDIAN ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
				T result = chainNext.decodeField(pkt, buf, count, factory);
				buf.order(orig);
				return result;
			}

			@Override
			public void encodeField(ByteBuffer buf, Packet pkt, T val)
					throws IOException, PacketEncodeException {
				ByteOrder orig = buf.order();
				buf.order(
					orig == ByteOrder.BIG_ENDIAN ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
				chainNext.encodeField(buf, pkt, val);
				buf.order(orig);
			}
		};
	}
}
