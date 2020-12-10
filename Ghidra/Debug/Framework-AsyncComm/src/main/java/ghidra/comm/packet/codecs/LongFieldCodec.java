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
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for encoding long values
 * 
 * This delegates to the given {@link PrimitiveCodec}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class LongFieldCodec<ENCBUF, DECBUF> extends AbstractFieldCodec<ENCBUF, DECBUF, Long> {
	private final PrimitiveCodec<ENCBUF, DECBUF> codec;

	public LongFieldCodec(PrimitiveCodec<ENCBUF, DECBUF> codec, Class<? extends Packet> pktType,
			Field field) {
		super(pktType, field);
		this.codec = codec;
	}

	@Override
	public Long decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return codec.decodeLong(field, buf);
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, Long val)
			throws IOException, PacketEncodeException {
		codec.encodeLong(buf, field, val);
	}
}
